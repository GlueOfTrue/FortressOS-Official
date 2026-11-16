"""Candidate profile ID is mandatory even when error reason/exit are identical.

Host-only tests: not proof that the test kernel emitted the correct marker.
"""
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path

loader = SourceFileLoader("candidate_g1_runner", str(Path(__file__).with_name("run-qemu.py")))
spec = spec_from_loader(loader.name, loader)
r = module_from_spec(spec)
loader.exec_module(r)

def serial(case, rest):
    return ("FORTRESS_ENTRY\nFORTRESS_G1_PROFILE " + case + "\n" + rest).encode("ascii")

MAP_FAILED = "FORTRESS_BOOT_PANIC\nMEMMAP_INVALID\n"
FB_FAILED = "FORTRESS_BOOT_PANIC\nBOOTINFO_INVALID\n"
OK = "FORTRESS_MEMMAP_OK entries=35 modules=0\nFORTRESS_FRAMEBUFFER_OK\nFORTRESS_BOOT_OK\n"

class CandidateProfileAttestation(unittest.TestCase):
    def test_expected_map_zero(self):
        self.assertEqual(r.classify_fixture(serial("map-zero", MAP_FAILED),False,35,"map-zero"),
                         ("EXPECTED_REJECT",0))
    def test_expected_map_overflow(self):
        self.assertEqual(r.classify_fixture(serial("map-overflow", MAP_FAILED),False,35,"map-overflow"),
                         ("EXPECTED_REJECT",0))
    def test_expected_map_overlap(self):
        self.assertEqual(r.classify_fixture(serial("map-overlap", MAP_FAILED),False,35,"map-overlap"),
                         ("EXPECTED_REJECT",0))
    def test_map_zero_binary_relabelled_map_overflow_fails(self):
        self.assertEqual(r.classify_fixture(serial("map-zero", MAP_FAILED),False,35,"map-overflow"),
                         ("FIXTURE_ID_MISMATCH",4))
    def test_map_zero_binary_relabelled_map_overlap_fails(self):
        self.assertEqual(r.classify_fixture(serial("map-zero", MAP_FAILED),False,35,"map-overlap"),
                         ("FIXTURE_ID_MISMATCH",4))
    def test_fb_alias_relabelled_fb_invalid_fails(self):
        self.assertEqual(r.classify_fixture(serial("fb-alias", FB_FAILED),False,35,"fb-invalid"),
                         ("FIXTURE_ID_MISMATCH",4))
    def test_fb_alias_valid(self):
        self.assertEqual(r.classify_fixture(serial("fb-alias", FB_FAILED),False,35,"fb-alias"),
                         ("EXPECTED_REJECT",0))
    def test_cpu_fault_requires_exact_vector_and_hardware_error_code(self):
        ud = serial("cpu-ud", "FORTRESS_CPU_FAULT vector=6 error=0\n")
        gp = serial("cpu-gp", "FORTRESS_CPU_FAULT vector=13 error=258\n")
        for name, raw in (("cpu-ud", ud), ("cpu-gp", gp)):
            with self.subTest(name=name):
                self.assertEqual(r.classify_fixture(raw, False, 35, name), ("EXPECTED_REJECT", 0))
                self.assertEqual(r.classify_fixture(raw, False, 33, name)[1], 4)
                self.assertEqual(r.classify_fixture(raw, True, -1, name)[1], 4)
                self.assertEqual(r.classify_fixture(raw + OK.encode(), False, 35, name)[1], 4)
        self.assertEqual(r.classify_fixture(gp.replace(b"error=258", b"error=0"),
                                            False, 35, "cpu-gp")[1], 4)
        self.assertEqual(r.classify_fixture(ud, False, 35, "cpu-gp")[1], 4)

    def test_normal_profile_valid(self):
        self.assertEqual(r.classify_fixture(serial("normal", OK),False,33,"normal"),
                         ("PASS",0))
    def test_normal_profile_missing_fails(self):
        self.assertEqual(r.classify_fixture(b"FORTRESS_ENTRY\n"+OK.encode(),False,33,"normal"),
                         ("FIXTURE_ID_MISMATCH",4))
    def test_forged_duplicate_profile_fails(self):
        self.assertEqual(r.classify_fixture(serial("normal","FORTRESS_G1_PROFILE normal\n"+OK),
                         False,33,"normal"),("FIXTURE_ID_MISMATCH",4))
    def test_wrong_profile_position_fails(self):
        self.assertEqual(r.classify_fixture(b"FORTRESS_ENTRY\nFORTRESS_BOOT_OK\n"
                         b"FORTRESS_G1_PROFILE normal\n",False,33,"normal"),
                         ("FIXTURE_ID_MISMATCH",4))
    def test_wrong_exit_even_with_right_id_fails(self):
        self.assertEqual(r.classify_fixture(serial("map-zero", MAP_FAILED),False,33,"map-zero")[1],4)
    def test_timeout_not_normal_success(self):
        self.assertNotEqual(r.classify_fixture(serial("normal", OK),True,-1,"normal")[1],0)
    def test_late_panic_with_profile_correct(self):
        self.assertEqual(r.classify_fixture(serial("late-panic", OK+
                         "FORTRESS_BOOT_PANIC\nG1_FIXTURE_LATE_PANIC\n"),
                         False,35,"late-panic"),("EXPECTED_REJECT",0))
    def test_no_fb_distinguishes_source(self):
        v=OK.replace("FORTRESS_FRAMEBUFFER_OK","FORTRESS_FRAMEBUFFER_ABSENT")
        self.assertEqual(r.classify_fixture(serial("no-fb",v),False,33,"no-fb"),("PASS",0))
        self.assertEqual(r.classify_fixture(serial("normal",v),False,33,"no-fb")[1],4)
    def test_hang_requires_profile_and_watchdog(self):
        line="FORTRESS_MEMMAP_OK entries=35 modules=0\nFORTRESS_G1_FIXTURE_HANG\n"
        self.assertEqual(r.classify_fixture(serial("hang",line),True,-1,"hang"),("EXPECTED_TIMEOUT",0))
        self.assertNotEqual(r.classify_fixture(serial("normal",line),True,-1,"hang")[1],0)
    def test_kernel_overflow_expected_reject(self):
        self.assertEqual(r.classify_fixture(serial("kernel-overflow", FB_FAILED),False,35,
                         "kernel-overflow"),("EXPECTED_REJECT",0))
    def test_failing_fb_invalid_expected_reject(self):
        self.assertEqual(r.classify_fixture(serial("fb-invalid", FB_FAILED),False,35,
                         "fb-invalid"),("EXPECTED_REJECT",0))

if __name__ == "__main__":
    unittest.main()
