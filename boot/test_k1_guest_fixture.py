"""One-CPU K1 oracle tests, with genuine guest grammar and divergent state."""
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path
import unittest

LOADER = SourceFileLoader("k1_runner", str(Path(__file__).with_name("run-qemu.py")))
SPEC = spec_from_loader(LOADER.name, LOADER)
RUNNER = module_from_spec(SPEC)
LOADER.exec_module(RUNNER)

TRACE = b"""FORTRESS_ENTRY
FORTRESS_G1_PROFILE k1-real
FORTRESS_MEMMAP_OK entries=34 modules=0
FORTRESS_FRAMEBUFFER_OK
FORTRESS_RSDP_PRESENT
FORTRESS_K1_ARCH cs=8 tr=56 idt=0xffffffff80009aa0 cr3=0x1ddc8000
FORTRESS_K1_PTE_CHECK rw=0x800000000000a007 rx=0xb005 guard=0x0 borrowed=2
FORTRESS_K1_CR3 old=0x1ddc8000 new=0x1000 cs=8 tr=56
FORTRESS_K1_HW_READ_ZERO
FORTRESS_K1_INVLPG_DONE cr3=0x1000 va=0x40001000 leaf=0x0
FORTRESS_K1_EXPECT_PAGE_FAULT
FORTRESS_K1_PF vector=14 error=0 cr2=0x40001000 cpl=0 cr3=0x1000
FORTRESS_K1_TERMINAL_REJECT_OK
"""


class K1OracleTest(unittest.TestCase):
    def test_expected_supervisor_page_fault_is_a_pass(self):
        serial = b"UEFI firmware\x1b[02;01H" + TRACE.replace(b"\n", b"\r\n")
        self.assertEqual(RUNNER.classify_fixture(serial, False, 35, "k1-real"),
                         ("EXPECTED_REJECT", 0))
        absent = TRACE.replace(b"FORTRESS_FRAMEBUFFER_OK\nFORTRESS_RSDP_PRESENT\n",
                               b"FORTRESS_FRAMEBUFFER_ABSENT\n")
        self.assertEqual(RUNNER.classify_fixture(absent, False, 35, "k1-real"),
                         ("EXPECTED_REJECT", 0))

    def test_missing_genuine_terminal_exit_or_trace_is_rejected(self):
        for trace, timeout, exit_code in (
                (b"", False, 35), (TRACE[:-1], False, 35), (TRACE, True, -1),
                (TRACE, True, 35), (TRACE, False, 0), (TRACE, False, 33),
                (TRACE, False, 37), (TRACE + b"FORTRESS_BOOT_OK\n", False, 35),
                (TRACE.replace(b"k1-real", b"k2-ud"), False, 35),
                (TRACE.replace(b"FORTRESS_K1_HW_READ_ZERO\n", b""), False, 35),
                (TRACE.replace(b"FORTRESS_K1_TERMINAL_REJECT_OK", b"FORTRESS_K1_FAIL"), False, 35)):
            with self.subTest(trace=trace[-40:], timeout=timeout, exit_code=exit_code):
                self.assertNotEqual(RUNNER.classify_fixture(trace, timeout, exit_code, "k1-real")[1], 0)

    def test_wrong_cpu_state_and_mapping_rights_are_rejected(self):
        for old, new in (
                (b"entries=34", b"entries=99"),
                (b"cs=8 tr=56 idt=", b"cs=8 tr=40 idt="),
                (b"idt=0xffffffff80009aa0", b"idt=0x40000000"),
                (b"old=0x1ddc8000", b"old=0x1dda0000"),
                (b"new=0x1000", b"new=0x1ddc8000"),
                (b"new=0x1000", b"new=0x1001"),
                (b"rw=0x800000000000a007", b"rw=0xa007"),
                (b"rw=0x800000000000a007", b"rw=0x800000000000a003"),
                (b"rx=0xb005", b"rx=0xb007"),
                (b"rx=0xb005", b"rx=0xa005"),
                (b"guard=0x0", b"guard=0xc003"),
                (b"borrowed=2", b"borrowed=0"),
                (b"cr3=0x1000 va=", b"cr3=0x2000 va="),
                (b"va=0x40001000", b"va=0x40002000"),
                (b"leaf=0x0", b"leaf=0xc005"),
                (b"vector=14 error=0", b"vector=14 error=1"),
                (b"cr2=0x40001000", b"cr2=0x40002000"),
                (b"cpl=0 cr3=0x1000", b"cpl=3 cr3=0x1000"),
                (b"cpl=0 cr3=0x1000", b"cpl=0 cr3=0x2000")):
            with self.subTest(field=old):
                changed = TRACE.replace(old, new, 1)
                self.assertNotEqual(changed, TRACE)
                self.assertEqual(RUNNER.classify_fixture(changed, False, 35, "k1-real"),
                                 ("UNEXPECTED_FIXTURE_OUTCOME", 4))


if __name__ == "__main__":
    unittest.main()
