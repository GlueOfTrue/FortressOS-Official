import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path

loader = SourceFileLoader("g1_runner", str(Path(__file__).with_name("run-qemu.py")))
spec = spec_from_loader(loader.name, loader)
runner = module_from_spec(spec)
loader.exec_module(runner)

GOOD = (b"FORTRESS_ENTRY\n"
        b"FORTRESS_MEMMAP_OK entries=4 modules=0\n"
        b"FORTRESS_FRAMEBUFFER_ABSENT\n"
        b"FORTRESS_BOOT_OK\n")

class G1ClassifierTest(unittest.TestCase):
    def test_pass_requires_terminal_exit(self):
        self.assertEqual(runner.classify(GOOD, False, 33), ("PASS", 0))
    def test_timeout_after_boot_ok_must_fail(self):
        self.assertEqual(runner.classify(GOOD, True, -1), ("TIMEOUT", 3))
    def test_missing_terminal_ack_must_fail(self):
        self.assertEqual(runner.classify(GOOD, False, 0)[1], 4)
    def test_late_panic_precedes_exit(self):
        self.assertEqual(runner.classify(GOOD + b"FORTRESS_BOOT_PANIC\n", False, 33), ("PANIC", 2))
    def test_late_panic_precedes_timeout(self):
        self.assertEqual(runner.classify(GOOD + b"FORTRESS_PANIC fatal\n", True, -1), ("PANIC", 2))
    def test_missing_entry_fails(self):
        self.assertEqual(runner.classify(GOOD.split(b"\n", 1)[1], False, 33), ("SERIAL_INVALID", 4))
    def test_out_of_order_fails(self):
        self.assertEqual(runner.classify(b"FORTRESS_MEMMAP_OK entries=4 modules=0\nFORTRESS_ENTRY\nFORTRESS_BOOT_OK\n", False, 33), ("SERIAL_INVALID", 4))
    def test_duplicate_boot_ok_fails(self):
        self.assertEqual(runner.classify(GOOD + b"FORTRESS_BOOT_OK\n", False, 33), ("SERIAL_INVALID", 4))
    def test_duplicate_entry_fails(self):
        self.assertEqual(runner.classify(GOOD + b"FORTRESS_ENTRY\n", False, 33), ("SERIAL_INVALID", 4))
    def test_truncated_marker_fails(self):
        self.assertEqual(runner.classify(GOOD[:-1], False, 33), ("SERIAL_INVALID", 4))
    def test_partial_marker_fails(self):
        self.assertEqual(runner.classify(GOOD.replace(b"FORTRESS_BOOT_OK", b"FORTRESS_BOOT_OKAY"), False, 33), ("SERIAL_INVALID", 4))
    def test_bad_decimals_fails(self):
        self.assertEqual(runner.classify(GOOD.replace(b"entries=4", b"entries=999"), False, 33), ("SERIAL_INVALID", 4))
    def test_too_long_fails(self):
        self.assertEqual(runner.classify(GOOD + b"x" * 600 + b"\n", False, 33), ("SERIAL_INVALID", 4))
    def test_binary_data_fails(self):
        self.assertEqual(runner.classify(GOOD + b"\xff\n", False, 33), ("SERIAL_INVALID", 4))
    def test_conflicting_framebuffer_fails(self):
        self.assertEqual(runner.classify(GOOD.replace(b"FORTRESS_BOOT_OK", b"FORTRESS_FRAMEBUFFER_OK\nFORTRESS_BOOT_OK"), False, 33), ("SERIAL_INVALID", 4))
    def test_unrecognized_event_fails(self):
        self.assertEqual(runner.classify(GOOD.replace(b"FORTRESS_BOOT_OK", b"FORTRESS_EARLY_EXIT\nFORTRESS_BOOT_OK"), False, 33), ("SERIAL_INVALID", 4))

    def test_guest_ovmf_prefix_isolated(self):
        prefix = b"\x1b[0mUEFI firmware output\x00"
        self.assertEqual(runner.classify(prefix + GOOD, False, 33), ("PASS", 0))
    def test_forged_earlier_kernel_panic_not_dropped(self):
        self.assertEqual(runner.classify(
            b"FORTRESS_BOOT_PANIC\n" + GOOD, False, 33), ("SERIAL_INVALID", 4))
    def test_guest_noise_after_entry_rejected(self):
        self.assertEqual(runner.classify(GOOD.replace(b"FORTRESS_BOOT_OK", b"arbitrary firmware\nFORTRESS_BOOT_OK"), False, 33), ("SERIAL_INVALID", 4))

class K2GuestClassifierTest(unittest.TestCase):
    entry = b"FORTRESS_ENTRY\n"
    profile = b"FORTRESS_G1_PROFILE k2-ud\n"
    cpu = b"FORTRESS_K2_CPU_OK cs=8 ss=16 tr=56 gdtr_limit=71 idtr_limit=4095\n"
    fault = b"FORTRESS_K2_FAULT vector=6 error=0 cpl=0\n"
    good = entry + profile + cpu + fault

    def test_exact_descriptor_readback_and_fault(self):
        self.assertEqual(
            runner.classify_fixture(self.good, False, 35, "k2-ud"),
            ("EXPECTED_REJECT", 0),
        )

    def test_exit_status_and_timeout(self):
        for timed_out, code in ((False, 33), (False, 0), (True, -1), (True, 35)):
            with self.subTest(timed_out=timed_out, code=code):
                self.assertEqual(
                    runner.classify_fixture(self.good, timed_out, code, "k2-ud"),
                    ("UNEXPECTED_FIXTURE_OUTCOME", 4),
                )

    def test_legacy_fixture_cannot_satisfy_k2(self):
        old_profile = self.good.replace(b"k2-ud", b"cpu-ud")
        self.assertEqual(
            runner.classify_fixture(old_profile, False, 35, "k2-ud"),
            ("FIXTURE_ID_MISMATCH", 4),
        )
        old_fault = self.entry + self.profile + b"FORTRESS_CPU_FAULT vector=6 error=0\n"
        self.assertEqual(
            runner.classify_fixture(old_fault, False, 35, "k2-ud"),
            ("UNEXPECTED_FIXTURE_OUTCOME", 4),
        )

    def test_descriptor_or_trap_value_mismatch(self):
        for key, value in (
            (b"cs=8", b"cs=16"),
            (b"ss=16", b"ss=0"),
            (b"tr=56", b"tr=0"),
            (b"gdtr_limit=71", b"gdtr_limit=70"),
            (b"idtr_limit=4095", b"idtr_limit=4096"),
            (b"vector=6", b"vector=13"),
            (b"error=0", b"error=1"),
            (b"cpl=0", b"cpl=3"),
        ):
            with self.subTest(field=key):
                raw = self.good.replace(key, value)
                self.assertEqual(
                    runner.classify_fixture(raw, False, 35, "k2-ud"),
                    ("UNEXPECTED_FIXTURE_OUTCOME", 4),
                )

    def test_sequence_must_be_complete_and_unique(self):
        for raw in (
            self.entry + self.profile + self.fault,
            self.entry + self.profile + self.cpu,
            self.entry + self.profile + self.fault + self.cpu,
            self.good + self.fault,
            self.good + b"FORTRESS_BOOT_OK\n",
        ):
            with self.subTest(raw=raw):
                self.assertEqual(
                    runner.classify_fixture(raw, False, 35, "k2-ud"),
                    ("UNEXPECTED_FIXTURE_OUTCOME", 4),
                )


if __name__ == "__main__":
    unittest.main()
