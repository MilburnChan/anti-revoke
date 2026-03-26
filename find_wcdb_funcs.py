#!/usr/bin/env python3
"""
find_wcdb_funcs.py — Locate WCDB-related revoke functions in wechat.dylib.

Searches __cstring for DB column names (is_revoke, revoke_time, etc.),
finds ADRP+ADD references in __text, then identifies enclosing functions
and their guard variable addresses.

Note: Strings like "AddRevokeMessage" are in __const (indirect/table reference),
not searchable via ADRP+ADD. Use __cstring column names instead.

Usage: python3 find_wcdb_funcs.py
"""

import struct
import sys

BINARY = "/Applications/WeChat.app/Contents/Frameworks/wechat.dylib"

# __cstring DB column names and log markers — these are directly referenced via ADRP+ADD
CSTRING_TARGETS = [
    b"is_revoke",
    b"revoke_time",
    b"is_revoke\x00",
    b"revoke_time\x00",
]

# Also search __cstring for log-format strings containing these names
LOG_TARGETS = [
    b"AddRevokeMessage",
    b"HandleRevokeFail",
    b"GetRevokeMessage",
    b"UpdateMessageOnT",
    b"DeleteMessageFts",
    b"AddMessageToDB",
    b"revoke",
]

# ARM64 __text region (VA range, from readme)
TEXT_START_VA = 0x16000
TEXT_SIZE     = 0x5F25DD0

# __cstring region (VA range, from readme)
CSTRING_START_VA = 0x842FB8D
CSTRING_SIZE     = 0xF7080


def find_arm64_slice(data):
    magic = struct.unpack(">I", data[:4])[0]
    if magic != 0xCAFEBABE:
        return (0, len(data))
    nfat = struct.unpack(">I", data[4:8])[0]
    for i in range(nfat):
        off = 8 + i * 20
        cputype, cpusubtype, offset, size, align = struct.unpack(">IIIII", data[off:off+20])
        if cputype == 0x0100000C:  # ARM64
            return (offset, size)
    raise ValueError("No arm64 slice found")


def find_strings_in_region(data, region_file_start, region_size, targets):
    """Search for target bytes within a specific file region."""
    region = data[region_file_start:region_file_start + region_size]
    results = {}
    for target in targets:
        offset = 0
        while True:
            pos = region.find(target, offset)
            if pos == -1:
                break
            end = region.find(b'\x00', pos)
            if end == -1:
                end = pos + len(target)
            full_str = region[pos:end].decode('utf-8', errors='replace')
            file_off = region_file_start + pos
            results.setdefault(full_str, []).append(file_off)
            offset = pos + 1
    return results


def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm |= ~0xFFFFF
    return (pc & ~0xFFF) + (imm << 12)


def decode_add_imm(insn):
    """Decode ADD Xd, Xn, #imm12. Return (rd, rn, imm) or None."""
    if (insn & 0xFF800000) not in (0x91000000, 0x11000000):
        return None
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return (rd, rn, imm12)


def decode_ldr_imm64(insn):
    """Decode LDR Xt, [Xn, #imm*8]. Return (rt, rn, imm) or None."""
    if (insn & 0xFFC00000) != 0xF9400000:
        return None
    imm12 = ((insn >> 10) & 0xFFF) << 3
    rn = (insn >> 5) & 0x1F
    rt = insn & 0x1F
    return (rt, rn, imm12)


def find_adrp_add_refs(data, slice_offset, target_va):
    """Find ADRP+ADD instruction pairs that compute target_va."""
    target_page = target_va & ~0xFFF
    target_off  = target_va & 0xFFF

    results = []
    for i in range(0, TEXT_SIZE, 4):
        pc = TEXT_START_VA + i
        file_off = slice_offset + pc

        if file_off + 8 > len(data):
            break

        insn0 = struct.unpack_from("<I", data, file_off)[0]
        page = decode_adrp(insn0, pc)
        if page != target_page:
            continue

        adrp_rd = insn0 & 0x1F

        # Check +4: ADD Xd, Xsame, #off
        insn1 = struct.unpack_from("<I", data, file_off + 4)[0]
        add = decode_add_imm(insn1)
        if add and add[1] == adrp_rd and add[2] == target_off:
            results.append(pc)
            continue

        # Also check +8 (sometimes there's an instruction between ADRP and ADD)
        if file_off + 12 <= len(data):
            insn2 = struct.unpack_from("<I", data, file_off + 8)[0]
            add2 = decode_add_imm(insn2)
            if add2 and add2[1] == adrp_rd and add2[2] == target_off:
                results.append(pc)

    return results


def load_function_starts(data, slice_offset):
    """Parse LC_FUNCTION_STARTS from arm64 slice. Returns sorted list of function VAs."""
    base = slice_offset
    magic = struct.unpack_from("<I", data, base)[0]
    if magic not in (0xFEEDFACF, 0xCEFAEDFE):
        print(f"  ERROR: unexpected magic 0x{magic:x} at slice start")
        return []

    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    print(f"  Mach-O magic=0x{magic:x}, ncmds={ncmds}")

    cmd_off = base + 32
    for ci in range(ncmds):
        if cmd_off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cmd_off)
        if cmd == 0x26:  # LC_FUNCTION_STARTS
            dataoff, datasize = struct.unpack_from("<II", data, cmd_off + 8)
            print(f"  LC_FUNCTION_STARTS: dataoff=0x{dataoff:x} datasize=0x{datasize:x}")
            # Try both: slice-relative and file-absolute
            for label, start in [("slice-relative", slice_offset + dataoff),
                                  ("file-absolute",  dataoff)]:
                if start + datasize > len(data):
                    continue
                fsd = data[start:start + datasize]
                funcs = _decode_func_starts(fsd)
                print(f"    {label}: {len(funcs):,} functions (first=0x{funcs[0]:x} last=0x{funcs[-1]:x})" if funcs else f"    {label}: 0 functions")
                if len(funcs) > 10000:
                    return funcs
        cmd_off += cmdsize

    return []


def _decode_func_starts(fsd):
    funcs = []
    addr = 0
    i = 0
    while i < len(fsd):
        delta = 0
        shift = 0
        while i < len(fsd):
            b = fsd[i]; i += 1
            delta |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
        if delta == 0:
            break
        addr += delta
        funcs.append(addr)
    return sorted(funcs)


def find_enclosing_function(funcs, va):
    lo, hi = 0, len(funcs) - 1
    result = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid] <= va:
            result = funcs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return result


def check_guard_variable(data, slice_offset, func_va):
    """Check for guard variable pattern at function start. Return guard VA or None."""
    file_off = slice_offset + func_va
    if file_off + 16 > len(data):
        return None
    insns = [struct.unpack_from("<I", data, file_off + i*4)[0] for i in range(4)]

    page = decode_adrp(insns[0], func_va)
    if page is None:
        return None

    ldr = decode_ldr_imm64(insns[1])
    if ldr is None:
        return None
    if ldr[1] != (insns[0] & 0x1F):
        return None

    # CBZ or CBNZ at insns[2]
    if (insns[2] & 0x7E000000) not in (0x34000000, 0x36000000):
        return None

    return page + ldr[2]


def estimate_func_size(data, slice_offset, func_va):
    """Count instructions up to first RET (max 512 insns)."""
    file_off = slice_offset + func_va
    count = 0
    for i in range(512):
        if file_off + i*4 + 4 > len(data):
            break
        insn = struct.unpack_from("<I", data, file_off + i*4)[0]
        count += 1
        if insn == 0xD65F03C0:  # RET
            break
    return count * 4


def main():
    print(f"Loading {BINARY} ...")
    with open(BINARY, "rb") as f:
        data = f.read()
    print(f"Binary size: {len(data):,} bytes\n")

    slice_offset, slice_size = find_arm64_slice(data)
    print(f"ARM64 slice: offset=0x{slice_offset:x}, size=0x{slice_size:x}\n")

    # ── Step 1: Find strings in __cstring ────────────────────────────────────
    cstring_file_start = slice_offset + CSTRING_START_VA
    print(f"=== Step 1: Search __cstring (file 0x{cstring_file_start:x} .. "
          f"0x{cstring_file_start + CSTRING_SIZE:x}) ===")

    all_targets = CSTRING_TARGETS + LOG_TARGETS
    hits = find_strings_in_region(data, cstring_file_start, CSTRING_SIZE, all_targets)

    if not hits:
        print("  No target strings found in __cstring.\n")
    else:
        for s, offsets in sorted(hits.items(), key=lambda x: x[1][0]):
            for foff in offsets:
                va = foff - slice_offset
                print(f"  \"{s}\" @ file=0x{foff:x}  VA=0x{va:x}")
        print()

    # ── Step 2: Load function starts ─────────────────────────────────────────
    print("=== Step 2: Load LC_FUNCTION_STARTS ===")
    funcs = load_function_starts(data, slice_offset)
    print(f"  Using {len(funcs):,} function VAs\n")

    if not funcs:
        print("  ERROR: Could not load function starts. Aborting.\n")
        return

    # ── Step 3: ADRP+ADD reference search ────────────────────────────────────
    print("=== Step 3: ADRP+ADD reference search ===")
    found_funcs = {}  # func_va -> list of (string, ref_va)

    for s, offsets in hits.items():
        for foff in offsets:
            target_va = foff - slice_offset
            print(f"  Searching refs to \"{s}\" (VA=0x{target_va:x}) ...", flush=True)
            refs = find_adrp_add_refs(data, slice_offset, target_va)
            print(f"    → {len(refs)} reference(s)")
            for ref_va in refs:
                func_va = find_enclosing_function(funcs, ref_va)
                if func_va:
                    found_funcs.setdefault(func_va, []).append((s, ref_va))
    print()

    # ── Step 4: Report results ────────────────────────────────────────────────
    print("=== Step 4: Functions containing references ===")
    if not found_funcs:
        print("  No functions found. Possible reasons:")
        print("  - Strings may not be in __cstring (check __const section)")
        print("  - References may use a different instruction pattern")
        print()
    else:
        for func_va in sorted(found_funcs):
            guard_va = check_guard_variable(data, slice_offset, func_va)
            size = estimate_func_size(data, slice_offset, func_va)
            refs = found_funcs[func_va]
            ref_strs = ", ".join(f"\"{r[0]}\"@0x{r[1]:x}" for r in refs)
            guard_str = f"guard=0x{guard_va:x}" if guard_va else "no-guard"
            print(f"  func=0x{func_va:x}  size~{size}B  {guard_str}")
            print(f"    refs: {ref_strs}")
        print()

    print("=== Step 5: Hookable summary (guard variable found) ===")
    hookable = []
    for func_va in sorted(found_funcs):
        guard_va = check_guard_variable(data, slice_offset, func_va)
        if guard_va:
            names = list(set(r[0] for r in found_funcs[func_va]))
            hookable.append((guard_va, func_va, names))

    if hookable:
        for guard_va, func_va, names in hookable:
            print(f"  Guard VA: 0x{guard_va:x}  Function VA: 0x{func_va:x}  ({', '.join(names)})")
    else:
        print("  None found with guard variables.")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
