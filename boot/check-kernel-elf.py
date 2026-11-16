#!/usr/bin/env python3
"""Inspect actual ELF64 PT_LOAD geometry; fail closed before packaging a G1 image.

No host disk writes. PT_LOAD physical placement is Limine-owned, so p_paddr
does NOT prove a physical address. Executable Address request supplies that
address at handoff. Here we verify only image geometry and linker symbol span.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

VBASE = 0xFFFFFFFF80000000
U64_LIMIT = 1 << 64
PAGE = 4096


class ElfInvalid(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise ElfInvalid(reason)


def bounded_range(offset, size, total):
    return 0 <= offset <= total and 0 <= size <= total - offset


def check_elf(blob: bytes) -> dict:
    require(len(blob) >= 64, "truncated ELF header")
    require(blob[:4] == b"\x7fELF" and blob[4] == 2 and blob[5] == 1 and blob[6] == 1,
            "not little-endian ELF64")
    (_, typ, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, _) = struct.unpack_from("<16sHHIQQQIHHHHHH", blob)
    require(typ == 2 and machine == 62 and version == 1 and ehsize == 64,
            "expected x86_64 static ET_EXEC")
    require(phnum > 0 and phnum <= 128 and phentsize >= 56,
            "invalid PT header count/size")
    require(bounded_range(phoff, phnum * phentsize, len(blob)), "truncated PT headers")
    loads = []
    for i in range(phnum):
        t, f, off, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", blob, phoff + i * phentsize)
        if t != 1:
            continue
        # The G1 linker splits RX text, R rodata and RW data. This checks
        # ELF declarations only; runtime page-table W^X is a separate gate.
        require((f & 3) != 3, "writable executable PT_LOAD")
        require(memsz > 0 and filesz <= memsz, "invalid load memsz/filesz")
        require(bounded_range(off, filesz, len(blob)), "load image truncated")
        require(align >= PAGE and align & (align - 1) == 0,
                "bad PT_LOAD alignment")
        require(vaddr % PAGE == 0, "unaligned load virtual base")
        require((vaddr - off) % align == 0, "PT_LOAD file/virtual alignment")
        require(vaddr >= VBASE and vaddr + memsz < U64_LIMIT,
                "PT_LOAD noncanonical/overflow")
        loads.append({"vaddr": vaddr, "end": vaddr + memsz,
                      "file_size": filesz, "memory_size": memsz, "flags": f})
    require(loads, "no PT_LOAD")
    loads.sort(key=lambda x: x["vaddr"])
    require(loads[0]["vaddr"] == VBASE, "unexpected kernel virtual base")
    for a, b in zip(loads, loads[1:]):
        require(a["end"] <= b["vaddr"], "PT_LOAD virtual overlap")
    require(any(s["flags"] & 1 and
                s["vaddr"] <= entry < s["vaddr"] + s["file_size"] for s in loads),
            "kernel entry outside file-backed executable PT_LOAD")
    require(any(s["memory_size"] > s["file_size"] for s in loads),
            "expected BSS in PT_LOAD, not present")

    end = (max(s["end"] for s in loads) + PAGE - 1) & ~(PAGE - 1)
    require(end < U64_LIMIT, "rounded kernel image end overflow")
    require(end - VBASE <= 128 * 1024 * 1024, "image exceeds G1 128MiB quota")
    # Linker symbols used at runtime must describe exactly this PT_LOAD envelope.
    require(shnum > 0 and shnum <= 65534 and shentsize >= 64,
            "missing section headers / symbol evidence")
    require(bounded_range(shoff, shnum * shentsize, len(blob)),
            "truncated section headers")
    headers = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + i * shentsize)
               for i in range(shnum)]
    symbols = {}
    for sh in headers:
        _, kind, _, _, off, size, link, _, _, entsz = sh
        if kind != 2:  # SHT_SYMTAB
            continue
        require(link < shnum and entsz >= 24 and size % entsz == 0,
                "bad symbol table header")
        require(bounded_range(off, size, len(blob)), "truncated symbol table")
        strsh = headers[link]
        require(strsh[1] == 3, "bad symbol string table")
        stroff, strlen = strsh[4], strsh[5]
        require(bounded_range(stroff, strlen, len(blob)), "bad symbol names")
        strings = blob[stroff:stroff + strlen]
        for pos in range(off, off + size, entsz):
            name, info, other, section, value, sz = struct.unpack_from("<IBBHQQ", blob, pos)
            if name >= len(strings):
                continue
            end_name = strings.find(b"\x00", name)
            if end_name < 0:
                continue
            key = strings[name:end_name]
            if key in (b"__kernel_start", b"__kernel_end"):
                # Undefined/common/invalid section symbols do not establish a
                # linked runtime address. Linker absolute symbols are valid.
                require(section == 0xfff1 or 0 < section < min(shnum, 0xff00),
                        "runtime linker symbol is not defined")
                require(key.decode() not in symbols, "duplicate runtime linker symbol")
                symbols[key.decode()] = value
    require(symbols.get("__kernel_start") == VBASE and
            symbols.get("__kernel_end") == end,
            "runtime linker symbols disagree with PT_LOAD covered pages")
    return {
        "schema": "fortress.boot.elf.v1",
        "status": "PASS", "type": "ELF64_ET_EXEC_X86_64",
        "entry": hex(entry), "kernel_virtual_base": hex(VBASE),
        "pt_load_count": len(loads), "reserved_physical_span_bytes": end - VBASE,
        "bss_in_image": True,
        "load_segments": [{**r, "vaddr": hex(r["vaddr"]), "end": hex(r["end"])}
                          for r in loads]
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("elf", type=Path)
    args = p.parse_args()
    try:
        report = check_elf(args.elf.read_bytes())
    except (ElfInvalid, OSError, struct.error) as ex:
        print(f"ELF_INVALID: {ex}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
