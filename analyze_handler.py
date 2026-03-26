#!/usr/bin/env python3
"""Analyze the revoke action handler at VA 0x40f8378 to find BL targets."""

import struct
import sys

BINARY = "/Applications/WeChat.app/Contents/Frameworks/wechat.dylib"
HANDLER_VA = 0x40f8378
HANDLER_SIZE = 3540

def find_arm64_slice(data):
    magic = struct.unpack(">I", data[:4])[0]
    if magic != 0xCAFEBABE:
        return (0, len(data))
    nfat = struct.unpack(">I", data[4:8])[0]
    for i in range(nfat):
        off = 8 + i * 20
        cputype, cpusubtype, offset, size, align = struct.unpack(">IIIII", data[off:off+20])
        if cputype == 0x0100000C:
            return (offset, size)
    raise ValueError("No arm64 slice")

def decode_bl(insn, pc):
    """Decode BL instruction, return target address or None."""
    if (insn >> 26) != 0b100101:
        return None
    imm26 = insn & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 |= ~0x3FFFFFF  # sign extend
    return pc + (imm26 << 2)

def decode_adrp(insn, pc):
    """Decode ADRP instruction."""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm |= ~0xFFFFF
    return (pc & ~0xFFF) + (imm << 12)

def classify_function(data, slice_offset, target_va, depth=0):
    """Read first instructions of a function and try to classify it."""
    file_off = slice_offset + target_va
    if file_off < 0 or file_off + 64 > len(data):
        return "out of range"

    insns = []
    for i in range(16):
        raw = struct.unpack_from("<I", data, file_off + i * 4)[0]
        insns.append(raw)

    # Check for guard variable pattern: adrp+ldr+cbz+br
    has_guard = False
    guard_va = None
    if decode_adrp(insns[0], target_va) is not None:
        # Check if second insn is LDR
        if (insns[1] & 0xFFC00000) == 0xF9400000:  # LDR Xt, [Xn, #imm]
            page = decode_adrp(insns[0], target_va)
            imm12 = ((insns[1] >> 10) & 0xFFF) << 3  # scale by 8 for 64-bit
            guard_va = page + imm12
            has_guard = True

    # Check if function is very small (ret within first few insns)
    for i in range(8):
        if insns[i] == 0xD65F03C0:  # ret
            if i <= 2:
                return f"tiny ({i+1} insns)" + (f" guard=0x{guard_va:x}" if has_guard else "")

    # Count instructions before first ret or end
    func_size = 0
    for i in range(min(256, (len(data) - file_off) // 4)):
        raw = struct.unpack_from("<I", data, file_off + i * 4)[0]
        func_size += 1
        if raw == 0xD65F03C0:  # ret
            break

    # Count BLs in target function
    bl_count = 0
    for i in range(func_size):
        raw = struct.unpack_from("<I", data, file_off + i * 4)[0]
        if decode_bl(raw, target_va + i * 4) is not None:
            bl_count += 1

    result = f"~{func_size*4}B, {bl_count}BLs"
    if has_guard:
        result += f", guard=0x{guard_va:x}"
    return result

def main():
    with open(BINARY, "rb") as f:
        data = f.read()

    slice_offset, slice_size = find_arm64_slice(data)
    print(f"ARM64 slice: offset=0x{slice_offset:x}, size=0x{slice_size:x}")

    handler_file_off = slice_offset + HANDLER_VA
    print(f"Handler at VA 0x{HANDLER_VA:x}, file offset 0x{handler_file_off:x}")
    print(f"Handler size: {HANDLER_SIZE} bytes ({HANDLER_SIZE//4} instructions)")
    print()

    # Extract all BL targets
    bl_targets = []
    for i in range(HANDLER_SIZE // 4):
        pc = HANDLER_VA + i * 4
        raw = struct.unpack_from("<I", data, handler_file_off + i * 4)[0]
        target = decode_bl(raw, pc)
        if target is not None:
            bl_targets.append((i, pc, target))

    print(f"Found {len(bl_targets)} BL instructions:")
    print()

    # Classify each target
    seen_targets = {}
    for idx, (i, pc, target) in enumerate(bl_targets):
        if target not in seen_targets:
            info = classify_function(data, slice_offset, target)
            seen_targets[target] = info
        else:
            info = seen_targets[target]
        print(f"  BL[{idx:2d}] @ 0x{pc:x} (+{i*4:#06x}) → 0x{target:x}  {info}")

    print()
    print("=== Unique targets with guard variables ===")
    for target, info in sorted(seen_targets.items()):
        if "guard=" in info:
            print(f"  0x{target:x}: {info}")

    print()
    print("=== Unique targets by size (largest first) ===")
    sized = []
    for target, info in seen_targets.items():
        try:
            size_str = info.split("~")[1].split("B")[0]
            size = int(size_str)
            sized.append((size, target, info))
        except:
            pass
    for size, target, info in sorted(sized, reverse=True)[:20]:
        print(f"  0x{target:x}: {info}")

if __name__ == "__main__":
    main()
