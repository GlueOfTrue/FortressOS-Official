"""Negative cases for the K3 serial and provenance checks."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

PATH = Path(__file__).with_name("run-k3.py")
SPEC = importlib.util.spec_from_file_location("fortress_k3_runner", PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)

A = bytes(19) + b"\x0f\x0b"
B = bytes(11) + b"\xcd\x80" + bytes(26) + b"\xcd\x80" + b"\x0f\x0b"
CODE = {"a": (0x400000, A), "b": (0x400000, B)}

VALID = b"""OVMF: loading boot option
FORTRESS_ENTRY
FORTRESS_G1_PROFILE k3
FORTRESS_MEMMAP_OK entries=15 modules=0
FORTRESS_FRAMEBUFFER_OK
FORTRESS_RSDP_PRESENT
FORTRESS_K3_ROOTS boot=0x9000 a=0x1000 b=0x2000
FORTRESS_K3_REJECT elf=INVALID wx=DENIED
FORTRESS_K3_A case=supervisor-read vector=14 error=5 cs=0x23 ss=0x1b rip=0x40000b rsp=0x800000 flags=0x46 cr2=0xffffffff80000000 cr3=0x1000 target=0xffffffff80000000
FORTRESS_K3_A case=supervisor-write vector=14 error=7 cs=0x23 ss=0x1b rip=0x400010 rsp=0x800000 flags=0x46 cr2=0xffffffff80000000 cr3=0x1000 target=0xffffffff80000000
FORTRESS_K3_A case=peer-read vector=14 error=4 cs=0x23 ss=0x1b rip=0x40000b rsp=0x800000 flags=0x46 cr2=0x900000 cr3=0x1000 target=0x900000
FORTRESS_K3_A case=ud vector=6 error=0 cs=0x23 ss=0x1b rip=0x400013 rsp=0x800000 flags=0x46 cr2=0x0 cr3=0x1000 target=0x0
FORTRESS_K3_REAP pid=STALE cap=STALE
FORTRESS_K3_B step=1 vector=128 error=0 cs=0x23 ss=0x1b rip=0x40000d rsp=0x800000 flags=0x402 live_flags=0x2 cr3=0x2000 rax=0x4b335f425f4f4b31
FORTRESS_K3_B step=2 vector=128 error=0 cs=0x23 ss=0x1b rip=0x400029 rsp=0x800000 flags=0x2 live_flags=0x2 cr3=0x2000 rax=0x4b335f425f4f4b32
FORTRESS_K3_DONE
"""


class SerialOracleTests(unittest.TestCase):
    def test_checked_cpu_state_returns_structured_evidence(self):
        serial = VALID.replace(b"\nFORTRESS_ENTRY", b"\x1b[02;01HFORTRESS_ENTRY", 1)
        result = RUNNER.classify(serial.replace(b"\n", b"\r\n"), 33, "k3", CODE)
        self.assertEqual(result["roots"], {"boot": 0x9000, "a": 0x1000, "b": 0x2000})
        self.assertEqual([f["error"] for f in result["process_a_faults"]], [5, 7, 4, 0])
        self.assertEqual([f["rip"] for f in result["process_b_syscalls"]], [0x40000D, 0x400029])

    def test_refuses_missing_truncated_or_ambiguous_serial(self):
        for evidence in (b"", VALID[:-1], VALID.replace(b"FORTRESS_ENTRY", b"xFORTRESS_ENTRY"),
                         b"FORTRESS_CPU_FAULT vector=8\n" + VALID,
                         VALID + b"FORTRESS_PANIC\n", b"x" * (RUNNER.MAX_SERIAL + 1)):
            with self.subTest(prefix=evidence[:25]):
                with self.assertRaises(RUNNER.EvidenceError):
                    RUNNER.classify(evidence, 33, "k3", CODE)

    def test_rejects_process_outcomes_other_than_debug_exit(self):
        for exit_code in (-9, -1, 0, 1, 35):
            with self.subTest(exit_code=exit_code):
                with self.assertRaises(RUNNER.EvidenceError):
                    RUNNER.classify(VALID, exit_code, "k3", CODE)

    def test_mutations_that_break_hardware_or_isolation_checks_fail(self):
        mutations = (
            (b"G1_PROFILE k3", b"G1_PROFILE k1-real"),
            (b"a=0x1000 b=0x2000", b"a=0x1000 b=0x1000"),
            (b"a=0x1000 b=0x2000", b"a=0x1000 b=0x2001"),
            (b"elf=INVALID wx=DENIED", b"elf=INVALID wx=ALLOWED"),
            (b"case=supervisor-read vector=14 error=5", b"case=supervisor-read vector=14 error=1"),
            (b"cs=0x23", b"cs=0x8"),
            (b"ss=0x1b", b"ss=0x10"),
            (b"rsp=0x800000", b"rsp=0x810000"),
            (b"cr2=0x900000", b"cr2=0x910000"),
            (b"cr3=0x1000 target=", b"cr3=0x2000 target="),
            (b"rip=0x400013", b"rip=0x400012"),
            (b"pid=STALE cap=STALE", b"pid=STALE cap=VALID"),
            (b"flags=0x402", b"flags=0x2"),
            (b"live_flags=0x2", b"live_flags=0x40402"),
            (b"rip=0x40000d", b"rip=0x40000e"),
            (b"rip=0x400029", b"rip=0x40000d"),
            (b"rax=0x4b335f425f4f4b32", b"rax=0x4b335f425f4f4b31"),
            (b"FORTRESS_K3_DONE\n", b"FORTRESS_PANIC\n"),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                changed = VALID.replace(old, new, 1)
                self.assertNotEqual(changed, VALID)
                with self.assertRaises(RUNNER.EvidenceError):
                    RUNNER.classify(changed, 33, "k3", CODE)


class IpcOracleTests(unittest.TestCase):
    def test_requires_genuine_per_domain_traps_and_ordered_ipc_witnesses(self):
        a = b"\x90\xcd\x80\x90\xcd\x80\x90\xcd\x80\x90"
        b = b"\x90\xcd\x80\x90"
        code = {"a": (0x400000, a), "b": (0x400000, b)}

        def trap(phase, root, rip, opcode, value):
            return (f"FORTRESS_K4_TRAP phase={phase} vector=128 error=0 cs=0x23 ss=0x1b "
                    f"rip={rip:#x} rsp=0x800000 flags=0x2 cr3={root:#x} rax={opcode:#x} rdi={value:#x}")

        payload = 0x4b345f5041594c44
        send = trap("send", 0x1000, 0x400003, 0x40, payload)
        echo = trap("echo", 0x2000, 0x400003, 0x41, payload)
        amplify = trap("amplify", 0x1000, 0x400006, 0x42, 2)
        deny = "FORTRESS_K4_DENY rights=0x2"
        done = trap("done", 0x1000, 0x400009, 0x43, 1)
        trace = [
            "FORTRESS_K4_ROOTS boot=0x9000 a=0x1000 b=0x2000", send,
            "FORTRESS_K4_BLOCK request=1", echo, "FORTRESS_K4_WAKE request=1",
            amplify, deny, done,
            ("FORTRESS_K4_NEGATIVE wrong_peer=DENIED canceled=DENIED revoked_queued=DENIED "
             "revoked_inflight=DENIED stale=DENIED early_wake=RETAINED overflow=DENIED"),
            "FORTRESS_K4_REAP process=STALE handle=STALE", "FORTRESS_K4_DONE",
        ]
        actual = RUNNER.classify_k4(trace, code)
        self.assertEqual([r["cr3"] for r in actual["ipc_traps"]], [0x1000, 0x2000, 0x1000, 0x1000])
        for index, value in ((2, "FORTRESS_K4_WAKE request=1"), (4, "FORTRESS_K4_WAKE request=2"),
                             (3, echo.replace("cr3=0x2000", "cr3=0x1000")),
                             (5, amplify.replace("rip=0x400006", "rip=0x400003")),
                             (6, deny.replace("DENY", "ALLOW")),
                             (8, trace[8].replace("overflow=DENIED", "overflow=ACCEPTED"))):
            with self.subTest(record=index):
                mutant = trace[:]
                mutant[index] = value
                with self.assertRaises(RUNNER.EvidenceError):
                    RUNNER.classify_k4(mutant, code)


class ProvenanceTests(unittest.TestCase):
    def test_exact_git_archive_identity(self):
        sha = RUNNER.git_output("rev-parse", "HEAD").decode().strip()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "source"
            evidence = RUNNER.extract_source(sha, target)
            self.assertEqual(evidence["commit"], sha)
            self.assertEqual((target / "boot/limine.conf").read_bytes(),
                             RUNNER.git_output("show", sha + ":boot/limine.conf"))

    def test_changed_firmware_pin_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "boot.efi"
            target.write_bytes(b"MZ")
            expected = RUNNER.sha256(target)
            target.write_bytes(b"MZ altered")
            with self.assertRaises(RUNNER.EvidenceError):
                RUNNER.verify_pin(target, expected)

    def test_capture_rejects_output_overflow_and_timeout(self):
        overflowing = RUNNER.capture(
            [sys.executable, "-c", "print('x' * 100000)"], PATH.parent, 2, 32)
        self.assertEqual(overflowing.error, "stdout exceeded size limit")
        self.assertEqual(len(overflowing.stdout), 32)
        timed_out = RUNNER.capture(
            [sys.executable, "-c", "import time; time.sleep(5)"], PATH.parent, 0.1, 32)
        self.assertEqual(timed_out.error, "timeout")


if __name__ == "__main__":
    unittest.main()
