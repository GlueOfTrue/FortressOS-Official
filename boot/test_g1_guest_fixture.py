import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path

loader = SourceFileLoader("g1_runner_negative", str(Path(__file__).with_name("run-qemu.py")))
spec = spec_from_loader(loader.name, loader)
r = module_from_spec(spec)
loader.exec_module(r)
OK = (b"FORTRESS_ENTRY\nFORTRESS_MEMMAP_OK entries=35 modules=0\n"
      b"FORTRESS_FRAMEBUFFER_OK\nFORTRESS_RSDP_PRESENT\nFORTRESS_BOOT_OK\n")

def with_profile(raw: bytes, fixture: str) -> bytes:
    # Synthetic test marker is inserted into a pre-existing host fixture.
    # Real QEMU guest must emit this from its compile-time Rust feature.
    return raw.replace(b"FORTRESS_ENTRY\n",
                       f"FORTRESS_ENTRY\nFORTRESS_G1_PROFILE {fixture}\n".encode(), 1)


def classified(raw: bytes, timed_out: bool, code: int, fixture: str):
    return r.classify_fixture(with_profile(raw, fixture), timed_out, code, fixture)


class GuestNegativeContract(unittest.TestCase):
    def test_map_zero_expected_reject(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n",
            False, 35, "map-zero"), ("EXPECTED_REJECT", 0))

    def test_map_overlap_expected_reject(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n",
            False, 35, "map-overlap"), ("EXPECTED_REJECT", 0))

    def test_map_overflow_expected_reject(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n",
            False, 35, "map-overflow"), ("EXPECTED_REJECT", 0))

    def test_invalid_fb_expected_reject(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nBOOTINFO_INVALID\n",
            False, 35, "fb-invalid"), ("EXPECTED_REJECT", 0))

    def test_framebuffer_kernel_alias_expected_reject(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nBOOTINFO_INVALID\n",
            False, 35, "fb-alias"), ("EXPECTED_REJECT", 0))

    def test_invalid_kernel_size_expected_reject(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nBOOTINFO_INVALID\n",
            False, 35, "kernel-overflow"), ("EXPECTED_REJECT", 0))

    def test_raw_observed_class_is_panic_with_reason(self):
        self.assertEqual(r.classify(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n", False, 35),
            ("PANIC", 2))

    def test_negative_wrong_exit_must_fail(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n",
            False, 33, "map-zero")[1], 4)

    def test_negative_wrong_reason_must_fail(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nBOOTINFO_INVALID\n",
            False, 35, "map-zero")[1], 4)

    def test_negative_unexpected_success_must_fail(self):
        self.assertEqual(classified(OK, False, 33, "map-overflow")[1], 4)

    def test_negative_timeout_must_fail(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n",
            True, -1, "map-overlap")[1], 4)

    def test_hang_expected_timeout(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_MEMMAP_OK entries=35 modules=0\n"
            b"FORTRESS_G1_FIXTURE_HANG\n",
            True, -1, "hang"), ("EXPECTED_TIMEOUT", 0))

    def test_hang_malformed_memory_counts_fail(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_MEMMAP_OK entries=9999 modules=0\n"
            b"FORTRESS_G1_FIXTURE_HANG\n", True, -1, "hang")[1], 4)

    def test_hang_with_success_exit_must_fail(self):
        self.assertEqual(classified(
            b"FORTRESS_ENTRY\nFORTRESS_MEMMAP_OK entries=35 modules=0\n"
            b"FORTRESS_G1_FIXTURE_HANG\n",
            False, 33, "hang")[1], 4)

    def test_late_panic_expected_reject(self):
        self.assertEqual(classified(
            OK + b"FORTRESS_BOOT_PANIC\nG1_FIXTURE_LATE_PANIC\n",
            False, 35, "late-panic"), ("EXPECTED_REJECT", 0))

    def test_late_panic_wrong_exit_fails(self):
        self.assertEqual(classified(
            OK + b"FORTRESS_BOOT_PANIC\nG1_FIXTURE_LATE_PANIC\n",
            False, 33, "late-panic")[1], 4)

    def test_absent_fb_positive(self):
        self.assertEqual(classified(
            OK.replace(b"FORTRESS_FRAMEBUFFER_OK", b"FORTRESS_FRAMEBUFFER_ABSENT"),
            False, 33, "no-fb"), ("PASS", 0))

    def test_absent_fb_not_observed_fails(self):
        self.assertEqual(classified(OK, False, 33, "no-fb")[1], 4)

    def test_ovmf_preamble_does_not_hide_guest_panic(self):
        self.assertEqual(classified(
            b"\x1b[0mOVMF firmware\xff" + b"FORTRESS_ENTRY\nFORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n",
            False, 35, "map-zero"), ("EXPECTED_REJECT", 0))

    def test_missing_guest_is_not_expected_reject(self):
        self.assertEqual(classified(
            b"FORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n",
            False, 35, "map-zero")[1], 4)

    def test_g0_is_not_g1(self):
        self.assertEqual(classified(
            b"FORTRESSOS_G0_DIAG_V1 BOOT_OK\n",
            False, 35, "map-zero")[1], 4)

if __name__ == "__main__":
    unittest.main()
