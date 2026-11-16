#!/usr/bin/env python3
"""Fail-closed FortressOS boot fixtures require COM1 and the matching debug-exit."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ESP = ROOT / "build" / "esp"
QEMU_EXIT_OK = 33  # isa-debug-exit iobase=0xf4, guest writes 0x10
MAX_SERIAL = 1 << 20
MAX_LINE = 512
NEGATIVE_QEMU_EXIT = 35
CPU_FAULTS = {"cpu-ud": (6, 0), "cpu-gp": (13, 258)}
FIXTURES = ("normal", "map-zero", "map-overflow", "map-overlap",
            "fb-invalid", "fb-alias", "kernel-overflow", "no-fb", "late-panic", "hang",
            *CPU_FAULTS, "k2-ud", "k1-real")

def guest_lines(output: bytes | str) -> list[str] | None:
    raw = output.encode("utf-8") if isinstance(output, str) else output
    if len(raw) > MAX_SERIAL:
        return None
    # Real OVMF writes ANSI controls before kernel ENTRY to the same COM1.
    # Preserve complete raw COM1 on disk; allow a firmware prefix only *before*
    # a complete kernel ENTRY record. Independent QEMU exit is still required.
    start = raw.find(b"FORTRESS_ENTRY\n")
    crlf_start = raw.find(b"FORTRESS_ENTRY\r\n")
    if start < 0 or (crlf_start >= 0 and crlf_start < start):
        start = crlf_start
    if start < 0:
        return None
    # Do not discard an earlier kernel-like diagnostic or panic as "firmware".
    # A forged/prefixed guest record is ambiguous, therefore fail closed.
    if b"FORTRESS_" in raw[:start]:
        return None
    raw = raw[start:]
    if not raw.endswith(b"\n") or b"\0" in raw or b"\x1b" in raw:
        return None
    if any(len(line) > MAX_LINE for line in raw.split(b"\n")):
        return None
    try:
        lines = [line.removesuffix(b"\r").decode("ascii")
                 for line in raw.split(b"\n")[:-1]]
    except UnicodeDecodeError:
        return None
    if not lines or lines[0] != "FORTRESS_ENTRY" or lines.count("FORTRESS_ENTRY") != 1:
        return None
    return lines


def classify(output: bytes | str, timed_out: bool, code: int) -> tuple[str, int]:
    lines = guest_lines(output)
    if lines is None:
        return "SERIAL_INVALID", 4
    if any(line.startswith("FORTRESS_CPU_FAULT ") for line in lines):
        return "CPU_FAULT", 2
    # A late panic defeats earlier BOOT_OK, including timeout cases.
    # Expected negative guest diagnostics append an unprefixed reason line.
    if any(l == "FORTRESS_BOOT_PANIC" or l == "FORTRESS_PANIC" or l.startswith("FORTRESS_PANIC ") for l in lines):
        return "PANIC", 2
    if any(not line.startswith("FORTRESS_") for line in lines):
        return "SERIAL_INVALID", 4
    if timed_out:
        return "TIMEOUT", 3
    if code != QEMU_EXIT_OK:
        return f"FAIL (QEMU exit {code}, expected debug-exit {QEMU_EXIT_OK})", 4
    events = [l for l in lines if l.startswith("FORTRESS_")]
    if len(events) < 3 or events[0] != "FORTRESS_ENTRY" or events[-1] != "FORTRESS_BOOT_OK":
        return "SERIAL_INVALID", 4
    if events.count("FORTRESS_ENTRY") != 1 or events.count("FORTRESS_BOOT_OK") != 1:
        return "SERIAL_INVALID", 4
    mem = [i for i, e in enumerate(events) if e.startswith("FORTRESS_MEMMAP_OK ")]
    if len(mem) != 1 or mem[0] != 1:
        return "SERIAL_INVALID", 4
    parsed = re.fullmatch(r"FORTRESS_MEMMAP_OK entries=([0-9]+) modules=([0-9]+)", events[1])
    if parsed is None or not (1 <= int(parsed[1]) <= 256) or not (0 <= int(parsed[2]) <= 16):
        return "SERIAL_INVALID", 4
    tail = events[2:-1]
    allowed = {"FORTRESS_FRAMEBUFFER_OK", "FORTRESS_FRAMEBUFFER_ABSENT", "FORTRESS_RSDP_PRESENT"}
    if any(e not in allowed for e in tail) or len(tail) != len(set(tail)):
        return "SERIAL_INVALID", 4
    if "FORTRESS_FRAMEBUFFER_OK" in tail and "FORTRESS_FRAMEBUFFER_ABSENT" in tail:
        return "SERIAL_INVALID", 4
    if "FORTRESS_RSDP_PRESENT" in tail and tail[-1] != "FORTRESS_RSDP_PRESENT":
        return "SERIAL_INVALID", 4
    return "PASS", 0


def remove_guest_profile(output: bytes | str, fixture: str) -> bytes | None:
    """Require exact guest-origin profile line, once, immediately after ENTRY.

    The raw serial stream is retained untouched in artifacts. This helper only
    produces a temporary compatibility view for the original G1 grammar.
    Source/build provenance still needs independent BUILD ELF/feature attestation.
    """
    if fixture not in FIXTURES:
        return None
    lines = guest_lines(output)
    if lines is None or len(lines) < 3:
        return None
    expected = f"FORTRESS_G1_PROFILE {fixture}"
    if lines[1] != expected or sum(
        line.startswith("FORTRESS_G1_PROFILE ") for line in lines) != 1:
        return None
    return ("\n".join([lines[0]] + lines[2:]) + "\n").encode("ascii")


def validate_k1(lines: list[str]) -> bool:
    """Check the one-vCPU K1 CR3/PTE transition and terminal hardware #PF."""
    if len(lines) not in (11, 12):
        return False
    mem = re.fullmatch(r"FORTRESS_MEMMAP_OK entries=([1-9][0-9]?) modules=(0|[1-9][0-9]?)",
                       lines[1])
    if mem is None or not (1 <= int(mem[1]) <= 64 and 0 <= int(mem[2]) <= 16):
        return False
    if lines[2] not in ("FORTRESS_FRAMEBUFFER_OK", "FORTRESS_FRAMEBUFFER_ABSENT"):
        return False
    if len(lines) == 12 and lines[3] != "FORTRESS_RSDP_PRESENT":
        return False

    arch, ptes, switch, zero, invlpg, expect, fault, done = lines[-8:]
    if (zero, expect, done) != (
        "FORTRESS_K1_HW_READ_ZERO",
        "FORTRESS_K1_EXPECT_PAGE_FAULT",
        "FORTRESS_K1_TERMINAL_REJECT_OK",
    ):
        return False

    word = r"(0x(?:0|[1-9a-f][0-9a-f]{0,15}))"
    observed_arch = re.fullmatch(rf"FORTRESS_K1_ARCH cs=8 tr=56 idt={word} cr3={word}", arch)
    observed_ptes = re.fullmatch(
        rf"FORTRESS_K1_PTE_CHECK rw={word} rx={word} guard=0x0 borrowed=([1-9][0-9]{{0,2}})", ptes)
    observed_switch = re.fullmatch(rf"FORTRESS_K1_CR3 old={word} new={word} cs=8 tr=56", switch)
    observed_invlpg = re.fullmatch(
        rf"FORTRESS_K1_INVLPG_DONE cr3={word} va=0x40001000 leaf=0x0", invlpg)
    observed_fault = re.fullmatch(
        rf"FORTRESS_K1_PF vector=14 error=0 cr2=0x40001000 cpl=0 cr3={word}", fault)
    if not (observed_arch and observed_ptes and observed_switch and observed_invlpg and observed_fault):
        return False

    idt, old_at_install = (int(value, 16) for value in observed_arch.groups())
    old, active = (int(value, 16) for value in observed_switch.groups())
    addr_mask = 0x000f_ffff_ffff_f000
    if not (0xffff_8000_0000_0000 <= idt <= 0xffff_ffff_ffff_f000 and idt % 16 == 0
            and old != 0 and old & addr_mask == old and old == old_at_install
            and active != 0 and active & addr_mask == active and active != old
            and int(observed_invlpg[1], 16) == int(observed_fault[1], 16) == active):
        return False

    rw, rx = int(observed_ptes[1], 16), int(observed_ptes[2], 16)
    present, write, user, nx = 1, 2, 4, 1 << 63
    flags = present | write | user | nx
    frames = (rw & addr_mask, rx & addr_mask)
    return (rw & ~addr_mask == flags and rx & ~addr_mask == (present | user)
            and all(frame not in (0, old, active) for frame in frames)
            and frames[0] != frames[1] and int(observed_ptes[3]) <= 256)


def classify_fixture(output: bytes | str, timed_out: bool, code: int,
                     fixture: str) -> tuple[str, int]:
    """Check an *actual guest* fixture outcome, not merely an expected host error.

    Negative fixture PASS requires exact failure class AND exit 35; timeout
    fixture requires an observed watchdog expiration plus the guest marker.
    Unexpected QEMU death, firmware-only text, or wrong failure reason fail.
    """
    cleaned = remove_guest_profile(output, fixture)
    if cleaned is None:
        return "FIXTURE_ID_MISMATCH", 4
    if fixture == "normal":
        return classify(cleaned, timed_out, code)
    lines = guest_lines(cleaned)
    if lines is None:
        return "SERIAL_INVALID", 4
    if fixture == "no-fb":
        status, rc = classify(cleaned, timed_out, code)
        if rc == 0 and lines.count("FORTRESS_FRAMEBUFFER_ABSENT") == 1:
            return "PASS", 0
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    if fixture == "hang":
        if timed_out and code == -1 and len(lines) == 3 and (
                lines[0] == "FORTRESS_ENTRY" and
                lines[2] == "FORTRESS_G1_FIXTURE_HANG"):
            match = re.fullmatch(
                r"FORTRESS_MEMMAP_OK entries=([0-9]{1,3}) modules=([0-9]{1,2})",
                lines[1])
            if match and 1 <= int(match[1]) <= 256 and 0 <= int(match[2]) <= 16:
                return "EXPECTED_TIMEOUT", 0
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    if timed_out or code != NEGATIVE_QEMU_EXIT:
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    if fixture == "k1-real":
        if validate_k1(lines):
            return "EXPECTED_REJECT", 0
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    if fixture == "k2-ud":
        if lines == [
            "FORTRESS_ENTRY",
            "FORTRESS_K2_CPU_OK cs=8 ss=16 tr=56 gdtr_limit=71 idtr_limit=4095",
            "FORTRESS_K2_FAULT vector=6 error=0 cpl=0",
        ]:
            return "EXPECTED_REJECT", 0
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    if fixture in CPU_FAULTS:
        vector, error = CPU_FAULTS[fixture]
        if lines == ["FORTRESS_ENTRY", f"FORTRESS_CPU_FAULT vector={vector} error={error}"]:
            return "EXPECTED_REJECT", 0
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    reasons = {
        "map-zero": "MEMMAP_INVALID",
        "map-overflow": "MEMMAP_INVALID",
        "map-overlap": "MEMMAP_INVALID",
        "fb-invalid": "BOOTINFO_INVALID",
        "fb-alias": "BOOTINFO_INVALID",
        "kernel-overflow": "BOOTINFO_INVALID",
    }
    if fixture in reasons:
        if lines == ["FORTRESS_ENTRY", "FORTRESS_BOOT_PANIC", reasons[fixture]]:
            return "EXPECTED_REJECT", 0
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    if fixture == "late-panic":
        if (len(lines) >= 5 and lines[-2:] ==
                ["FORTRESS_BOOT_PANIC", "G1_FIXTURE_LATE_PANIC"]):
            before = ("\n".join(lines[:-2]) + "\n").encode("ascii")
            if classify(before, False, QEMU_EXIT_OK) == ("PASS", 0):
                return "EXPECTED_REJECT", 0
        return "UNEXPECTED_FIXTURE_OUTCOME", 4
    return "UNKNOWN_FIXTURE", 4


def observed_guest_profile(output: bytes | str) -> str | None:
    lines = guest_lines(output)
    if lines is None or len(lines) < 2:
        return None
    prefix = "FORTRESS_G1_PROFILE "
    return lines[1][len(prefix):] if lines[1].startswith(prefix) else None


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--esp", type=Path, default=ESP, help="file-only ESP tree")
    p.add_argument("--secure-ovmf", action="store_true", help="enable SMM-protected virtual pflash")
    p.add_argument("--ovmf-code", type=Path, required=True)
    p.add_argument("--ovmf-vars", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=45)
    p.add_argument("--fixture", choices=FIXTURES, default="normal")
    p.add_argument("--artifacts-dir", type=Path, default=ROOT / "build" / "g1-evidence")
    args = p.parse_args()
    if args.timeout < 1 or args.timeout > 600:
        p.error("timeout must be in 1..600 seconds")
    qemu = shutil.which("qemu-system-x86_64")
    if not qemu:
        p.error("qemu-system-x86_64 not installed")
    esp = args.esp.resolve()
    kernel = esp / "boot/fortress-kernel"
    firmware = esp / "EFI/BOOT/BOOTX64.EFI"
    config = esp / "limine.conf"
    for path in (args.ovmf_code, args.ovmf_vars, config, firmware, kernel):
        if not path.is_file():
            p.error(f"missing file: {path}")
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fortress-g1-qemu-") as temp:
        temp_path = Path(temp)
        vars_copy = temp_path / "OVMF_VARS.fd"
        shutil.copyfile(args.ovmf_vars, vars_copy)
        serial_path = temp_path / "COM1.bin"
        machine = (["-machine", "q35,smm=on,accel=tcg", "-global",
                    "driver=cfi.pflash01,property=secure,value=on"] if args.secure_ovmf else
                   ["-machine", "q35"])
        command = [qemu, *machine, "-m", "512M", "-smp", "1",
                   "-no-reboot", "-display", "none",
                   "-monitor", "none", "-serial", f"file:{serial_path}",
                   "-net", "none", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf_code.resolve()}",
                   "-drive", f"if=pflash,format=raw,file={vars_copy}",
                   "-drive", f"if=virtio,format=raw,readonly=on,file=fat:ro:{esp}"]
        start = time.monotonic()
        timed_out = False
        try:
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=args.timeout, check=False)
            code, stderr = done.returncode, done.stderr
        except subprocess.TimeoutExpired as ex:
            timed_out, code = True, -1
            stderr = ex.stderr or b""
        duration_ms = int((time.monotonic() - start) * 1000)
        raw = serial_path.read_bytes() if serial_path.exists() else b""
        status, result_code = classify_fixture(raw, timed_out, code, args.fixture)
        for_classify = remove_guest_profile(raw, args.fixture)
        raw_outcome = (classify(for_classify, timed_out, code)[0]
                       if for_classify is not None else "FIXTURE_ID_MISMATCH")
        serial_output = args.artifacts_dir / "COM1.bin"
        stderr_output = args.artifacts_dir / "qemu.stderr"
        serial_output.write_bytes(raw)
        stderr_output.write_bytes(stderr)
        qver = subprocess.run([qemu, "--version"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, check=False).stdout.strip()
        manifest = {
            "schema": "fortress.qa.boot.v1",
            "stage": "K1" if args.fixture == "k1-real" else "G1",
            "fixture": args.fixture,
            "expected_guest_profile": args.fixture,
            "observed_guest_profile": observed_guest_profile(raw),
            "guest_profile_verified": for_classify is not None,
            "required_cargo_features": (["g1-qemu-exit"] if args.fixture == "normal"
                                        else ["g1-qemu-exit", "g1-fixture-" + args.fixture]),
            "cargo_features_build_provenance": "BUILD_MANIFEST_REQUIRED",
            "result": "PASS" if result_code == 0 else "FAIL",
            "observed_outcome": status, "raw_boot_outcome": raw_outcome,
            "expected_outcome": ("SUCCESS" if args.fixture in ("normal", "no-fb")
                                 else "TIMEOUT" if args.fixture == "hang"
                                 else "EXPECTED_REJECT"),
            "command_argv": command, "qemu_version": qver,
            "qemu_exit_code": code, "timed_out": timed_out, "duration_ms": duration_ms,
            "timeout_seconds": args.timeout, "host_os": platform.platform(),
            "serial_artifact_path": str(serial_output),
            "serial_sha256": sha256(serial_output),
            "qemu_stderr_sha256": sha256(stderr_output),
            "ovmf_code_sha256": sha256(args.ovmf_code),
            "ovmf_vars_initial_sha256": sha256(args.ovmf_vars),
            "bootloader_efi_sha256": sha256(firmware), "kernel_sha256": sha256(kernel),
            "limine_config_sha256": sha256(config),
            "bootloader_version": "Limine 12.9.6 (external pin; verify build source)",
            "protocol_base_revision": 6,
        }
        (args.artifacts_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if raw:
            print(raw.decode("ascii", errors="backslashreplace"), end="" if raw.endswith(b"\n") else "\n")
        print(f"RESULT: {status}; QEMU_EXIT={code}; TIMEOUT={timed_out}; "
              f"SERIAL_SHA256={manifest['serial_sha256']}")
        print(f"EVIDENCE: {args.artifacts_dir / 'manifest.json'}")
        return result_code

if __name__ == "__main__":
    sys.exit(main())
