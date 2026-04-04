#!/usr/bin/env python3
"""
Anti-revoke patch for WeChat macOS (Apple Silicon).

Two-layer defense:
  1. Binary patch: isRevokeMessage() returns false before the hook dylib loads
  2. Hook dylib: installs a guard hook so revoke packets keep being blocked at runtime

The script does not rely on a single hardcoded build any more. It resolves the
current build's isRevokeMessage stub and guard variable directly from
wechat.dylib, then compiles antirevoke.dylib with the resolved guard address.

Usage:
  python3 patch_wechat.py [--backup] [--restore] [--dry-run]
"""

import struct
import shutil
import subprocess
import sys
import os
import plistlib

WECHAT_APP = "/Applications/WeChat.app"
BINARY = os.path.join(WECHAT_APP, "Contents/Frameworks/wechat.dylib")
FRAMEWORKS_DIR = os.path.join(WECHAT_APP, "Contents/Frameworks")
VALIDATED_SHORT_VERSION = "4.1.8"
DYLIB_NAME = "antirevoke.dylib"
DYLIB_LOAD_PATH = "@loader_path/antirevoke.dylib"

ORIGINAL_REVOKE_BODY = bytes([
    0x08, 0x0C, 0x40, 0xB9,  # ldr w8, [x0, #0xc]
    0x49, 0xE2, 0x84, 0x52,  # mov w9, #0x2712
    0x1F, 0x01, 0x09, 0x6B,  # cmp w8, w9
    0xE0, 0x17, 0x9F, 0x1A,  # cset w0, eq
    0xC0, 0x03, 0x5F, 0xD6,  # ret
])
PATCHED_REVOKE_PREFIX = bytes([
    0x00, 0x00, 0x80, 0x52,  # mov w0, #0
    0xC0, 0x03, 0x5F, 0xD6,  # ret
])
PATCHED_REVOKE_BODY = PATCHED_REVOKE_PREFIX + ORIGINAL_REVOKE_BODY[8:]

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

class Patch:
    def __init__(self, name, va, original_bytes, patched_bytes, description):
        self.name = name
        self.va = va
        self.original_bytes = original_bytes
        self.patched_bytes = patched_bytes
        self.description = description

class ResolvedTarget:
    def __init__(self, patch, guard_va, stub_va, state):
        self.patch = patch
        self.guard_va = guard_va
        self.stub_va = stub_va
        self.state = state


def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def decode_adrp(word, pc):
    if (word & 0x9F000000) != 0x90000000:
        return None
    rd = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = sign_extend((immhi << 2) | immlo, 21) << 12
    target = (pc & ~0xFFF) + imm
    return rd, target


def decode_ldr_x_uimm(word):
    if (word & 0xFFC00000) != 0xF9400000:
        return None
    rt = word & 0x1F
    rn = (word >> 5) & 0x1F
    imm12 = (word >> 10) & 0xFFF
    return rt, rn, imm12 * 8


def decode_cbz_x(word, pc):
    if (word & 0x7F000000) != 0x34000000:
        return None
    if (word & 0x80000000) == 0:
        return None
    rt = word & 0x1F
    imm19 = (word >> 5) & 0x7FFFF
    target = pc + (sign_extend(imm19, 19) << 2)
    return rt, target


def decode_br(word):
    if (word & 0xFFFFFC1F) != 0xD61F0000:
        return None
    return (word >> 5) & 0x1F


def resolve_revoke_target(data, slice_offset, slice_size):
    """Locate isRevokeMessage and its guard variable in the current arm64 slice."""
    blob = data[slice_offset:slice_offset + slice_size]
    body_len = len(ORIGINAL_REVOKE_BODY)
    candidates = []

    max_off = len(blob) - (16 + body_len)
    for stub_va in range(0, max_off + 1, 4):
        w0, w1, w2, w3 = struct.unpack_from("<IIII", blob, stub_va)
        adrp = decode_adrp(w0, stub_va)
        ldr = decode_ldr_x_uimm(w1)
        cbz = decode_cbz_x(w2, stub_va + 8)
        br_reg = decode_br(w3)
        if not adrp or not ldr or not cbz or br_reg is None:
            continue

        adrp_reg, page_va = adrp
        ldr_rt, ldr_rn, ldr_disp = ldr
        cbz_reg, cbz_target = cbz
        if not (adrp_reg == ldr_rt == ldr_rn == cbz_reg == br_reg):
            continue

        body_va = stub_va + 16
        if cbz_target != body_va:
            continue

        body = blob[body_va:body_va + body_len]
        if body == ORIGINAL_REVOKE_BODY:
            state = "original"
        elif body == PATCHED_REVOKE_BODY:
            state = "patched"
        else:
            continue

        candidates.append(
            ResolvedTarget(
                patch=Patch(
                    name="isRevokeMessage_return_false",
                    va=body_va,
                    original_bytes=ORIGINAL_REVOKE_BODY[:8],
                    patched_bytes=PATCHED_REVOKE_PREFIX,
                    description="isRevokeMessage() always returns false — keeps original message visible",
                ),
                guard_va=page_va + ldr_disp,
                stub_va=stub_va,
                state=state,
            )
        )

    if not candidates:
        raise ValueError("Could not locate isRevokeMessage stub in the current arm64 slice")
    if len(candidates) != 1:
        detail = ", ".join(hex(c.patch.va) for c in candidates[:8])
        raise ValueError(f"Expected 1 isRevokeMessage candidate, found {len(candidates)}: {detail}")
    return candidates[0]

def verify_patches(data, slice_offset, patches):
    """Check that original bytes match at expected locations."""
    results = []
    for p in patches:
        file_offset = slice_offset + p.va
        actual = data[file_offset:file_offset + len(p.original_bytes)]
        match = actual == p.original_bytes
        already_patched = actual == p.patched_bytes
        results.append((p, match, already_patched, actual))
    return results

def apply_patches(data, slice_offset, patches):
    """Apply all patches to the binary data."""
    data = bytearray(data)
    for p in patches:
        file_offset = slice_offset + p.va
        data[file_offset:file_offset + len(p.patched_bytes)] = p.patched_bytes
    return bytes(data)

def restore_patches(data, slice_offset, patches):
    """Restore original bytes."""
    data = bytearray(data)
    for p in patches:
        file_offset = slice_offset + p.va
        data[file_offset:file_offset + len(p.patched_bytes)] = p.original_bytes
    return bytes(data)

def get_wechat_version(app_path):
    """Read WeChat version and build number from Info.plist."""
    plist_path = os.path.join(app_path, "Contents/Info.plist")
    if not os.path.exists(plist_path):
        return None, None
    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)
    version = plist.get("CFBundleShortVersionString", "unknown")
    build = plist.get("CFBundleVersion", "unknown")
    return version, build

def check_wechat_running():
    """Check if WeChat is currently running."""
    result = subprocess.run(["pgrep", "-x", "WeChat"], capture_output=True)
    return result.returncode == 0

def codesign(path):
    """Re-sign with ad-hoc signature."""
    subprocess.run(
        ["codesign", "--remove-signature", path],
        capture_output=True, text=True
    )
    result = subprocess.run(
        ["codesign", "--force", "--deep", "--sign", "-", path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  Warning: codesign failed: {result.stderr}")
        return False
    subprocess.run(["xattr", "-cr", path], capture_output=True)
    return True


# --- LC_LOAD_DYLIB injection ---

def check_dylib_loaded(data, slice_offset, dylib_path):
    """Check if a dylib is already in the load commands."""
    ncmds = struct.unpack_from("<I", data, slice_offset + 16)[0]
    pos = slice_offset + 32  # after mach_header_64
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == 0x0C:  # LC_LOAD_DYLIB
            name_offset = struct.unpack_from("<I", data, pos + 8)[0]
            name_end = data.index(b'\x00', pos + name_offset)
            name = data[pos + name_offset:name_end].decode('utf-8', errors='replace')
            if name == dylib_path:
                return True
        pos += cmdsize
    return False


def inject_load_dylib(data, slice_offset, dylib_path):
    """Add LC_LOAD_DYLIB command to the arm64 slice's Mach-O header."""
    if check_dylib_loaded(data, slice_offset, dylib_path):
        print(f"  LC_LOAD_DYLIB for {dylib_path} already present")
        return data

    data = bytearray(data)

    # Build LC_LOAD_DYLIB command
    # struct dylib_command { uint32 cmd, cmdsize; uint32 name_offset; uint32 timestamp, current_version, compat_version; }
    name_bytes = dylib_path.encode('utf-8') + b'\x00'
    name_offset = 24  # sizeof(dylib_command) header
    cmdsize = name_offset + len(name_bytes)
    # Align to 8 bytes
    cmdsize = (cmdsize + 7) & ~7
    cmd_data = struct.pack("<II", 0x0C, cmdsize)  # cmd, cmdsize
    cmd_data += struct.pack("<I", name_offset)     # name offset
    cmd_data += struct.pack("<III", 0, 0, 0)       # timestamp, current_version, compat_version
    cmd_data += name_bytes
    cmd_data += b'\x00' * (cmdsize - len(cmd_data))  # padding

    # Read current header
    ncmds = struct.unpack_from("<I", data, slice_offset + 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, slice_offset + 20)[0]
    end_of_cmds = slice_offset + 32 + sizeofcmds

    # Write new load command at end of existing commands
    data[end_of_cmds:end_of_cmds + cmdsize] = cmd_data

    # Update ncmds and sizeofcmds
    struct.pack_into("<I", data, slice_offset + 16, ncmds + 1)
    struct.pack_into("<I", data, slice_offset + 20, sizeofcmds + cmdsize)

    print(f"  Injected LC_LOAD_DYLIB: {dylib_path} ({cmdsize} bytes)")
    return bytes(data)


def compile_dylib(source_dir, guard_va):
    """Compile antirevoke.dylib from source."""
    src = os.path.join(source_dir, "antirevoke.c")
    out = os.path.join(source_dir, DYLIB_NAME)
    if not os.path.exists(src):
        print(f"Error: {src} not found")
        return None
    result = subprocess.run(
        ["clang", "-dynamiclib", "-arch", "arm64",
         f"-DIS_REVOKE_MSG_GUARD_VA=0x{guard_va:x}",
         "-o", out, src],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error compiling {src}: {result.stderr}")
        return None
    print(f"  Compiled: {out}")
    print(f"  Guard VA: 0x{guard_va:x}")
    return out


def install_dylib(source_dir, guard_va):
    """Compile and copy antirevoke.dylib to Frameworks dir."""
    dylib_src = compile_dylib(source_dir, guard_va)
    if not dylib_src:
        return False
    dst = os.path.join(FRAMEWORKS_DIR, DYLIB_NAME)
    shutil.copy2(dylib_src, dst)
    print(f"  Installed: {dst}")
    return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Anti-Revoke Patch for WeChat macOS")
    parser.add_argument("--backup", action="store_true", help="Create backup before patching")
    parser.add_argument("--restore", action="store_true", help="Restore from backup")
    parser.add_argument("--dry-run", action="store_true", help="Only verify, don't patch")
    parser.add_argument("--binary", default=BINARY, help="Path to wechat.dylib")
    args = parser.parse_args()

    binary_path = args.binary
    backup_path = binary_path + ".bak"
    app_path = os.path.dirname(os.path.dirname(os.path.dirname(binary_path)))

    if not os.path.exists(binary_path):
        print(f"Error: {binary_path} not found")
        print("Make sure WeChat is installed in /Applications/WeChat.app")
        sys.exit(1)

    # Check version
    version, build = get_wechat_version(app_path)
    if version:
        print(f"WeChat version: {version} (build {build})")
        if version != VALIDATED_SHORT_VERSION:
            print(f"WARNING: This workflow is validated against WeChat {VALIDATED_SHORT_VERSION}.")
            print("         Auto-resolution will still be attempted on your installed build.")

    # Check if running
    if not args.dry_run and check_wechat_running():
        print("Error: WeChat is running. Please quit WeChat first.")
        sys.exit(1)

    if args.restore:
        if not os.path.exists(backup_path):
            print(f"Error: backup {backup_path} not found")
            sys.exit(1)
        shutil.copy2(backup_path, binary_path)
        print(f"Restored from {backup_path}")
        # Remove injected dylib
        dylib_dst = os.path.join(FRAMEWORKS_DIR, DYLIB_NAME)
        if os.path.exists(dylib_dst):
            os.remove(dylib_dst)
            print(f"Removed: {dylib_dst}")
        codesign(app_path)
        print("Done! Restored to original.")
        return

    # Read binary
    with open(binary_path, "rb") as f:
        data = f.read()

    slice_offset, slice_size = find_arm64_slice(data)
    print(f"ARM64 slice: offset={hex(slice_offset)}, size={hex(slice_size)}")
    try:
        target = resolve_revoke_target(data, slice_offset, slice_size)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    print(f"Resolved revoke stub @ VA {hex(target.stub_va)}")
    print(f"Resolved patch site @ VA {hex(target.patch.va)} ({target.state})")
    print(f"Resolved guard VA @ {hex(target.guard_va)}")
    patches = [target.patch]

    # Verify
    print("\nVerifying patches:")
    results = verify_patches(data, slice_offset, patches)

    all_match = True
    all_patched = True
    for p, match, already_patched, actual in results:
        status = "OK" if match else ("ALREADY PATCHED" if already_patched else "MISMATCH")
        if not match and not already_patched:
            all_match = False
        if not already_patched:
            all_patched = False
        print(f"  [{status}] {p.name} @ VA {hex(p.va)}")
        print(f"    {p.description}")
        if not match and not already_patched:
            print(f"    Expected: {p.original_bytes.hex()}")
            print(f"    Actual:   {actual.hex()}")

    # Check if dylib injection is needed
    dylib_already_loaded = check_dylib_loaded(data, slice_offset, DYLIB_LOAD_PATH)
    dylib_installed = os.path.exists(os.path.join(FRAMEWORKS_DIR, DYLIB_NAME))

    if all_patched and dylib_already_loaded and dylib_installed:
        # Dylib file may have been updated — always reinstall to pick up changes
        print("\nBinary patches already applied. Reinstalling hook dylib...")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if install_dylib(script_dir, target.guard_va):
            print("\nRe-signing...")
            if codesign(app_path):
                print("Codesign OK")
            print("\nDone! Restart WeChat for changes to take effect.")
        return

    if all_patched and not args.dry_run:
        print("\nBinary patches already applied, checking hook dylib...")

    if not all_match and not all_patched:
        print("\nError: Some patches don't match expected bytes.")
        print("Auto-resolution succeeded, but the bytes at the patch site are unexpected.")
        print("Please restore your backup or inspect whether the binary was modified by another tool.")
        sys.exit(1)

    if args.dry_run:
        if not all_patched:
            print("\nDry run: binary patches would be applied.")
        if not dylib_already_loaded:
            print("Dry run: LC_LOAD_DYLIB would be injected.")
        if not dylib_installed:
            print("Dry run: antirevoke.dylib would be compiled and installed.")
        return

    # Backup
    if args.backup:
        if not os.path.exists(backup_path):
            shutil.copy2(binary_path, backup_path)
            print(f"\nBackup created: {backup_path}")
        else:
            print(f"\nBackup already exists: {backup_path}")

    patched_data = data

    # Apply binary patches if needed
    if not all_patched:
        print("\nApplying binary patches...")
        patched_data = apply_patches(patched_data, slice_offset, patches)
        results2 = verify_patches(patched_data, slice_offset, patches)
        for p, match, already_patched, actual in results2:
            if not already_patched:
                print(f"  ERROR: Patch verification failed for {p.name}")
                sys.exit(1)

    # Inject LC_LOAD_DYLIB if needed
    if not dylib_already_loaded:
        print("\nInjecting hook dylib loader...")
        patched_data = inject_load_dylib(patched_data, slice_offset, DYLIB_LOAD_PATH)

    # Write if anything changed
    if patched_data is not data:
        with open(binary_path, "wb") as f:
            f.write(patched_data)
        print(f"Written: {binary_path}")

    # Compile and install antirevoke.dylib
    print("\nBuilding hook dylib...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if not install_dylib(script_dir, target.guard_va):
        print("WARNING: Hook dylib installation failed.")
        print("Anti-revoke still works via the binary patch, but the runtime hook will be missing.")

    # Re-sign
    print("\nRe-signing...")
    if codesign(app_path):
        print("Codesign OK")
    else:
        print("Codesign failed - you may need to run manually:")
        print(f"  sudo codesign --force --deep --sign - {app_path}")

    print("\nDone! Restart WeChat for changes to take effect.")

if __name__ == "__main__":
    main()
