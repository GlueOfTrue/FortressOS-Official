import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path

FOLDER = Path(__file__).parent
def load(name, filename):
    loader = SourceFileLoader(name, str(FOLDER / filename))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module

checker = load("fortress_prod", "check-production-elf.py")
synthetic = load("fortress_elf_test", "test_check_kernel_elf.py")


class ProductionArtifactGateTest(unittest.TestCase):
    def test_clean_unstripped_elf_passes(self):
        self.assertEqual(checker.verify_production_elf(synthetic.fixture())["status"], "PASS")

    def test_guest_fixture_markers_rejected_on_release(self):
        for marker in (b"FORTRESS_G1_PROFILE ", b"FORTRESS_CONSOLE_READY", b"FORTRESS_K2_CPU_OK"):
            with self.subTest(marker=marker):
                blob = synthetic.fixture()
                blob[1248:1248 + len(marker)] = marker
                with self.assertRaisesRegex(ValueError, "test-only"):
                    checker.verify_production_elf(blob)

    def test_feature_symbol_detected(self):
        blob = synthetic.fixture()
        probe = b"FORTRESS_G1_QEMU_TEST_ONLY"
        blob[1200:1200 + len(probe)] = probe
        with self.assertRaisesRegex(ValueError, "test-only"):
            checker.verify_production_elf(blob)

    def test_debug_exit_port_code_detected(self):
        blob = synthetic.fixture()
        blob[4180:4187] = b"\x66\xba\xf4\x00\xb0\x10\xee"
        with self.assertRaisesRegex(ValueError, "0xf4"):
            checker.verify_production_elf(blob)

    def test_truncated_or_stripped_elf_rejected(self):
        with self.assertRaises(Exception):
            checker.verify_production_elf(b"\x7fELF")

    def test_marker_after_code_rejected(self):
        blob = synthetic.fixture()
        probe = b"G1_FIXTURE_LATE_PANIC"
        blob[1900:1900 + len(probe)] = probe
        with self.assertRaisesRegex(ValueError, "test-only"):
            checker.verify_production_elf(blob)

if __name__ == "__main__":
    unittest.main()
