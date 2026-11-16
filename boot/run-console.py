#!/usr/bin/env python3
"""Launch the FortressOS diagnostic console or probe it with live serial input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
PROMPT = b"fortress> "
ENTRY = b"FORTRESS_ENTRY\r\n"
READY = re.compile(
    ENTRY + rb"FORTRESS_G1_PROFILE console\r\n"
    rb"FORTRESS_MEMMAP_OK entries=([1-9][0-9]{0,2}) modules=(0|[1-9][0-9]?)\r\n"
    rb"FORTRESS_FRAMEBUFFER_(OK|ABSENT)\r\n(?:FORTRESS_RSDP_PRESENT\r\n)?"
    rb"FORTRESS_BOOT_OK\r\nFORTRESS_CONSOLE_READY\r\n" + re.escape(PROMPT)
)
QEMU_EXIT_OK = 33  # isa-debug-exit, guest value 0x10
MAX_OUTPUT = 1 << 20  # independently for COM1 and QEMU stderr


class SerialProbe:
    def __init__(self, timeout):
        self.timeout = timeout
        self.serial = bytearray()
        self.stderr = bytearray()
        self.cursor = 0
        self.cases = []

    def remaining(self):
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("console smoke watchdog expired")
        return seconds

    def pump(self):
        if not self.selector.get_map():
            raise RuntimeError("QEMU closed output before the expected console response")
        ready = self.selector.select(self.remaining())
        if not ready:
            raise TimeoutError("console smoke watchdog expired")
        for key, _ in ready:
            data = os.read(key.fd, 4096)
            if not data:
                self.selector.unregister(key.fileobj)
                continue
            limit = MAX_OUTPUT - len(key.data)
            key.data.extend(data[:limit])
            if len(data) > limit:
                raise RuntimeError("QEMU output exceeded the evidence limit")

    def await_console(self):
        while (end := self.serial.find(PROMPT)) < 0:
            self.pump()
        self.cursor = end + len(PROMPT)
        start = self.serial.find(ENTRY, 0, self.cursor)
        match = READY.fullmatch(self.serial, start, self.cursor) if start >= 0 else None
        if match is None or b"FORTRESS_" in self.serial[:start]:
            raise RuntimeError("missing or unexpected console boot sequence")
        regions, modules, framebuffer = match.groups()
        if not (1 <= int(regions) <= 256 and 0 <= int(modules) <= 16):
            raise RuntimeError("BootInfo counts exceed the accepted limits")
        return (b"FORTRESS_CONSOLE_STATUS boot=ok regions=" + regions + b" modules=" + modules
                + b" framebuffer=" + (b"present" if framebuffer == b"OK" else b"absent"))

    def exchange(self, name, sent, expected):
        if len(self.serial) != self.cursor:
            raise RuntimeError(f"{name}: unsolicited serial output before input")
        if self.process.stdin.write(sent) != len(sent):
            raise RuntimeError(f"{name}: incomplete input write")
        while True:
            observed = self.serial[self.cursor:self.cursor + len(expected)]
            if not expected.startswith(observed):
                raise RuntimeError(f"{name}: unexpected serial response")
            if len(observed) == len(expected):
                self.cursor += len(expected)
                self.cases.append({"name": name, "input_hex": sent.hex()})
                return
            self.pump()

    def run(self, process):
        self.process = process
        self.deadline = time.monotonic() + self.timeout
        with selectors.DefaultSelector() as self.selector:
            self.selector.register(process.stdout, selectors.EVENT_READ, self.serial)
            self.selector.register(process.stderr, selectors.EVENT_READ, self.stderr)
            status = self.await_console() + b"\r\n" + PROMPT
            help_output = b"commands: help status version calc exit\r\n" + PROMPT
            invalid = b"error: invalid input\r\n" + PROMPT
            self.exchange("editing-and-crlf", b"heX\x08lp\r\nstatus\n", help_output + status)
            self.exchange("blank-line", b"\r\n", PROMPT)
            self.exchange("version", b"version\n", b"FortressOS diagnostic console v1\r\n" + PROMPT)
            self.exchange("unknown-command", b"exit now\r", b"error: unknown command\r\n" + PROMPT)
            self.exchange("overlong-line", b"x" * 65 + b"exit\r", invalid)
            self.exchange("escape-sequence", b"\x1b[31mexit\r", invalid)
            self.exchange("non-ascii-and-delete", b"ex\xff\x7fit\r", invalid)
            self.exchange("calc-add", b"calc 7+5\r", b"result: 12\r\n" + PROMPT)
            self.exchange("calc-signed-multiply", b"calc -7 * 6\r", b"result: -42\r\n" + PROMPT)
            self.exchange("calc-divide", b"calc 25 / 4\r", b"result: 6\r\n" + PROMPT)
            self.exchange("calc-modulo", b"calc 25 % 4\r", b"result: 1\r\n" + PROMPT)
            self.exchange("calc-zero-divisor", b"calc 7/0\r", b"error: division by zero\r\n" + PROMPT)
            self.exchange("calc-overflow", b"calc 9223372036854775807+1\r",
                          b"error: arithmetic overflow\r\n" + PROMPT)
            self.exchange("calc-invalid", b"calc 1 + 2 trailing\r",
                          b"error: invalid calculation\r\n" + PROMPT)
            self.exchange("status-after-errors", b"status\n", status)
            self.exchange("explicit-exit", b"exit\r", b"FORTRESS_CONSOLE_EXIT\r\n")
            while self.selector.get_map():
                self.pump()
            code = process.wait(timeout=self.remaining())
            if self.cursor != len(self.serial):
                raise RuntimeError("unexpected serial output after exit marker")
            if code != QEMU_EXIT_OK:
                raise RuntimeError(f"expected QEMU exit {QEMU_EXIT_OK}, got {code}")


def smoke(command, output, timeout, inputs):
    probe = SerialProbe(timeout)
    code = None
    timed_out = False
    error = None
    try:
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, bufsize=0) as process:
            try:
                probe.run(process)
            finally:
                if process.poll() is None:
                    process.kill()
                code = process.wait()
    except (TimeoutError, subprocess.TimeoutExpired) as exc:
        timed_out, error = True, str(exc)
    except (OSError, RuntimeError) as exc:
        error = str(exc)
    (output / "COM1.bin").write_bytes(probe.serial)
    (output / "qemu.stderr").write_bytes(probe.stderr)
    manifest = {
        "schema": "fortress.qa.console.v1",
        "result": "PASS" if error is None else "FAIL",
        "error": error,
        "qemu_exit_code": code,
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "command_argv": command,
        "cases_passed": probe.cases,
        "input_sha256": inputs,
        "serial_sha256": hashlib.sha256(probe.serial).hexdigest(),
        "stderr_sha256": hashlib.sha256(probe.stderr).hexdigest(),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"RESULT: {manifest['result']}; QEMU_EXIT={code}; CASES={len(probe.cases)}")
    if error is not None:
        print(f"CONSOLE_SMOKE_FAIL: {error}", file=sys.stderr)
    print(f"EVIDENCE: {output / 'manifest.json'}")
    return int(error is not None)


def snapshot(source, target, limit):
    if source.resolve(strict=True) != source or not source.is_file():
        raise ValueError(f"expected a regular file without symlink components: {source}")
    with source.open("rb") as stream:
        data = stream.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError(f"unexpected input size: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def interactive(command, timeout):
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    # Open separate descriptions so QEMU cannot leave file status flags on
    # the caller's terminal descriptors. Discard guest keystrokes on return.
    def terminal(fd, access, mode):
        return os.fdopen(os.open(os.ttyname(fd), access | os.O_NOCTTY), mode, buffering=0)

    try:
        with terminal(fd, os.O_RDONLY, "rb") as guest_input, terminal(
                sys.stdout.fileno(), os.O_WRONLY, "wb") as guest_output:
            code = subprocess.run(command, stdin=guest_input, stdout=guest_output,
                                  timeout=timeout, check=False).returncode
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, saved)
        # On Darwin, switching back to canonical mode can set PENDIN.
        # Flush input afterwards, without waiting for terminal output to drain.
        termios.tcflush(fd, termios.TCIFLUSH)
    if code != QEMU_EXIT_OK:
        raise RuntimeError(f"console exited unexpectedly (QEMU exit {code})")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--esp", type=Path, default=ROOT / "build" / "esp", help="staged console ESP")
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    parser.add_argument("--timeout", type=int, help="watchdog seconds (smoke: 45, interactive: 600)")
    parser.add_argument("--smoke", action="store_true", help="send commands and record raw UART evidence")
    parser.add_argument("--artifacts-dir", type=Path, help="new directory for smoke evidence")
    args = parser.parse_args()
    timeout = args.timeout if args.timeout is not None else (45 if args.smoke else 600)
    if not 1 <= timeout <= 3600:
        parser.error("--timeout must be in 1..3600 seconds")
    if not args.smoke:
        if args.artifacts_dir is not None:
            parser.error("--artifacts-dir requires --smoke")
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            parser.error("interactive mode requires a terminal; use --smoke for scripts")
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        parser.error("qemu-system-x86_64 not installed")
    esp = args.esp.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="fortress-console-") as directory:
        scratch = Path(directory).resolve()
        staged = scratch / "esp"
        inputs = {}
        for name, limit in (("EFI/BOOT/BOOTX64.EFI", 8 << 20), ("limine.conf", 64 << 10),
                            ("boot/fortress-kernel", 64 << 20)):
            inputs[name] = snapshot(esp / name, staged / name, limit)
        code, vars_copy = scratch / "OVMF_CODE.fd", scratch / "OVMF_VARS.fd"
        inputs["OVMF_CODE.fd"] = snapshot(args.ovmf_code.resolve(strict=True), code, 16 << 20)
        inputs["OVMF_VARS.fd"] = snapshot(args.ovmf_vars.resolve(strict=True), vars_copy, 16 << 20)
        # QEMU's comma-separated -drive values escape literal commas as `,,`.
        esp_arg, code_arg, vars_arg = (str(path).replace(",", ",,") for path in (staged, code, vars_copy))
        command = [qemu, "-machine", "q35,accel=tcg,i8042=off,usb=off", "-m", "512M", "-smp", "1",
                   "-no-reboot", "-display", "none", "-monitor", "none", "-serial", "stdio",
                   "-net", "none", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-drive", f"if=pflash,format=raw,readonly=on,file={code_arg}",
                   "-drive", f"if=pflash,format=raw,file={vars_arg}",
                   "-drive", f"if=virtio,format=raw,readonly=on,file=fat:ro:{esp_arg}"]
        if not args.smoke:
            print("QEMU diagnostic console. Enter help or exit. Input is not echoed.", flush=True)
            return interactive(command, timeout)
        output = args.artifacts_dir
        if output is None:
            parent = ROOT / "build" / "console-evidence"
            parent.mkdir(parents=True, exist_ok=True)
            output = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
        else:
            output.mkdir(parents=True, exist_ok=False)
        return smoke(command, output, timeout, inputs)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"CONSOLE_LAUNCH_FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
