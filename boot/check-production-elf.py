#!/usr/bin/env python3
"""Fail-closed *partial* production binary hygiene gate for FortressOS G1.

Reject obvious debug-exit/guest-fixture artifacts in an unstripped ELF64 kernel.
Source feature isolation + executable opcode scan are required, but do NOT prove
that no computed/indirect privileged test port access is possible. BUILD owns
final canonical CI enforcement and must separately check the exact artifact.
"""
import argparse
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import struct
import sys

_loader = SourceFileLoader("fortress_check_kernel_elf",
                           str(Path(__file__).with_name("check-kernel-elf.py")))
_spec = spec_from_loader(_loader.name, _loader)
_elf = module_from_spec(_spec)
_loader.exec_module(_elf)

TEST_SYMBOLS = (
    b"FORTRESS_G1_QEMU_TEST_ONLY",
    b"FORTRESS_G1_PROFILE ",  # must NEVER appear in no-feature hardware ELF
    b"fortress_g1_debug_exit",
    b"FORTRESS_G1_FIXTURE_HANG",
    b"G1_FIXTURE_LATE_PANIC",
    b"FORTRESS_CONSOLE_",
    b"FORTRESS_K2_",
    b"FORTRESS_K1_",
    b"FORTRESS_K3_",
    b"FORTRESS_K4_",
)
PORT_F4_LOADS = (b"\x66\xba\xf4\x00", b"\xba\xf4\x00\x00\x00")


def verify_production_elf(data: bytes) -> dict:
    report = _elf.check_elf(data)  # validates ELF, PT_LOAD/BSS & symbol evidence
    for marker in TEST_SYMBOLS:
        if marker in data:
            raise ValueError("test-only symbol/string retained: " + marker.decode("ascii"))
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    for i in range(phnum):
        kind, flags, offset, _, _, filesize, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phentsize)
        if kind != 1 or not (flags & 1):
            continue
        code = data[offset:offset + filesize]
        for load in PORT_F4_LOADS:
            p = 0
            while (pos := code.find(load, p)) >= 0:
                # x86: mov DX,0x00f4 followed nearby by out DX,AL (EE).
                # This is a conservative fail-closed signature for our known
                # test-only hook. It is NOT general symbolic opcode analysis.
                if b"\xee" in code[pos + len(load):pos + len(load) + 24]:
                    raise ValueError("executable has probable ISA debug-exit 0xf4 sequence")
                p = pos + 1
    return {"status": "PASS", "type": "G1_PRODUCTION_NO_TEST_MARKERS",
            "image_bytes": len(data), "kernel_virtual_base": report["kernel_virtual_base"],
            "limitations": "does not prove absence of computed privileged port I/O"}


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("kernel_elf", type=Path)
    args = a.parse_args()
    try:
        result = verify_production_elf(args.kernel_elf.read_bytes())
    except (ValueError, OSError, struct.error) as exc:
        print("PRODUCTION_ELF_FAIL:", exc, file=sys.stderr)
        return 2
    print(f"PRODUCTION_ELF_PASS: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
