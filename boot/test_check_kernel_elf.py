import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path
import struct

loader = SourceFileLoader("elfcheck", str(Path(__file__).with_name("check-kernel-elf.py")))
spec = spec_from_loader(loader.name, loader)
elf = module_from_spec(spec)
loader.exec_module(elf)

def fixture():
    # Synthetic ELF64: one executable PT_LOAD at VBASE, 4KiB file + 4KiB BSS,
    # ELF symtab names __kernel_start and __kernel_end, no real executable code.
    buf = bytearray(8192)
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01"+b"\0"*9,
                       2, 62, 1, elf.VBASE + 128, 64, 512, 0, 64, 56, 1, 64, 3, 0)
    buf[:64] = ehdr
    struct.pack_into("<IIQQQQQQ", buf, 64, 1, 5, 4096, elf.VBASE,
                     elf.VBASE, 4096, 8192, 4096)
    # STRTAB at 1024, SYMTAB at 1536
    strings = b"\x00__kernel_start\x00__kernel_end\x00"
    buf[1024:1024+len(strings)] = strings
    struct.pack_into("<IIQQQQIIQQ", buf, 512+64, 0, 3, 0, 0,
                     1024, len(strings), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", buf, 512+128, 0, 2, 0, 0,
                     1536, 72, 1, 0, 8, 24)
    struct.pack_into("<IBBHQQ", buf, 1536+24, 1, 0, 0, 1, elf.VBASE, 0)
    struct.pack_into("<IBBHQQ", buf, 1536+48, 16, 0, 0, 1, elf.VBASE+8192, 0)
    return buf

class ElfGeometryTest(unittest.TestCase):
    def test_valid_geometry(self):
        self.assertEqual(elf.check_elf(fixture())["reserved_physical_span_bytes"],8192)
    def test_wrong_entry(self):
        b=fixture()
        struct.pack_into("<Q",b,24,0)
        with self.assertRaises(elf.ElfInvalid): elf.check_elf(b)
    def test_bss_missing(self):
        b=fixture()
        struct.pack_into("<Q",b,64+40,4096)
        with self.assertRaises(elf.ElfInvalid): elf.check_elf(b)
    def test_bad_symbol_end(self):
        b=fixture()
        struct.pack_into("<Q",b,1536+48+8,elf.VBASE+4096)
        with self.assertRaises(elf.ElfInvalid): elf.check_elf(b)
    def test_truncated_program_header(self):
        b=fixture()[:80]
        with self.assertRaises(elf.ElfInvalid): elf.check_elf(b)
    def test_rejects_non_elf(self):
        with self.assertRaises(elf.ElfInvalid): elf.check_elf(b"not an ELF")
    def test_rejects_wrong_machine(self):
        b=fixture()
        struct.pack_into("<H",b,18,183)
        with self.assertRaises(elf.ElfInvalid): elf.check_elf(b)

    def test_entry_in_zero_fill_bss_rejected(self):
        b = fixture()
        struct.pack_into("<Q", b, 24, elf.VBASE + 4096)
        with self.assertRaisesRegex(elf.ElfInvalid, "file-backed executable"):
            elf.check_elf(b)

    def test_writable_executable_load_rejected(self):
        b = fixture()
        struct.pack_into("<I", b, 64 + 4, 7)  # PF_R | PF_W | PF_X
        with self.assertRaisesRegex(elf.ElfInvalid, "writable executable"):
            elf.check_elf(b)

    def test_invalid_ident_version_rejected(self):
        b = fixture()
        b[6] = 0
        with self.assertRaises(elf.ElfInvalid):
            elf.check_elf(b)

    def test_undefined_runtime_symbols_rejected(self):
        for symbol in (1536 + 24, 1536 + 48):
            with self.subTest(symbol=symbol):
                b = fixture()
                struct.pack_into("<H", b, symbol + 6, 0)  # SHN_UNDEF
                with self.assertRaisesRegex(elf.ElfInvalid, "not defined"):
                    elf.check_elf(b)

    def test_absolute_runtime_symbols_accepted(self):
        b = fixture()
        for symbol in (1536 + 24, 1536 + 48):
            struct.pack_into("<H", b, symbol + 6, 0xfff1)  # SHN_ABS
        self.assertEqual(elf.check_elf(b)["status"], "PASS")

    def test_invalid_runtime_symbol_section_rejected(self):
        b = fixture()
        struct.pack_into("<H", b, 1536 + 24 + 6, 3)  # shnum, outside table
        with self.assertRaisesRegex(elf.ElfInvalid, "not defined"):
            elf.check_elf(b)

    def test_duplicate_runtime_symbol_rejected(self):
        b = fixture()
        struct.pack_into("<Q", b, 512 + 128 + 32, 96)  # four symtab entries
        struct.pack_into("<IBBHQQ", b, 1536 + 72, 1, 0, 0, 1, elf.VBASE, 0)
        with self.assertRaisesRegex(elf.ElfInvalid, "duplicate"):
            elf.check_elf(b)

    def test_load_filesz_greater_than_memsz_rejected(self):
        # K03: the file bytes fit in the blob, but exceed the mapped span.
        b = fixture()
        struct.pack_into("<Q", b, 64 + 40, 4095)
        with self.assertRaisesRegex(elf.ElfInvalid, "memsz/filesz"):
            elf.check_elf(b)

    def test_load_virtual_end_overflow_rejected(self):
        # K03: keep file geometry valid; overflow the 64-bit virtual extent.
        b = fixture()
        struct.pack_into("<Q", b, 64 + 16, (1 << 64) - 4096)
        struct.pack_into("<Q", b, 64 + 40, 8192)
        with self.assertRaisesRegex(elf.ElfInvalid, "noncanonical/overflow"):
            elf.check_elf(b)

if __name__ == "__main__":
    unittest.main()
