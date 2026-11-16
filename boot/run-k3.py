#!/usr/bin/env python3
"""Build the pinned K3 source and check actual CPL3 evidence in QEMU."""
import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
KERNEL_REL = Path("boot/fortress-kernel")
EFI_REL = Path("EFI/BOOT/BOOTX64.EFI")
QEMU_EXIT_OK = 33
MAX_SERIAL = 1 << 20
MAX_BUILD_LOG = 4 << 20


class EvidenceError(Exception):
    pass


@dataclass
class Capture:
    code: int
    stdout: bytes
    stderr: bytes
    error: str | None
    duration_ms: int


def capture(command, cwd, timeout, limit, *, env=None):
    start = time.monotonic()
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    error = None
    with subprocess.Popen(
        command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    ) as process, selectors.DefaultSelector() as pipes:
        pipes.register(process.stdout, selectors.EVENT_READ, "stdout")
        pipes.register(process.stderr, selectors.EVENT_READ, "stderr")
        while pipes.get_map() and error is None:
            remaining = start + timeout - time.monotonic()
            if remaining <= 0:
                error = "timeout"
                break
            for key, _ in pipes.select(remaining):
                block = os.read(key.fd, 65536)
                if not block:
                    pipes.unregister(key.fileobj)
                    continue
                output = outputs[key.data]
                space = limit - len(output)
                output.extend(block[:space])
                if len(block) > space:
                    error = f"{key.data} exceeded size limit"
                    break
        if error is None:
            try:
                process.wait(timeout=max(0, start + timeout - time.monotonic()))
            except subprocess.TimeoutExpired:
                error = "timeout"
        if error is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        return Capture(process.returncode, bytes(outputs["stdout"]),
                       bytes(outputs["stderr"]), error,
                       int((time.monotonic() - start) * 1000))


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_pin(path, expected):
    digest = sha256(path)
    if digest != expected:
        raise EvidenceError(f"SHA-256 mismatch for {path}: got {digest}, expected {expected}")
    return digest


def pinned_copy(source, destination, expected):
    shutil.copyfile(source, destination)
    return verify_pin(destination, expected)


def git_output(*args):
    return subprocess.check_output(["git", "--no-replace-objects", "-C", str(ROOT), *args])


def extract_source(commit, destination):
    observed = git_output("rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if observed != commit:
        raise EvidenceError("source must resolve to the exact supplied commit")
    tree = git_output("rev-parse", "--verify", commit + "^{tree}").decode().strip()
    archive = git_output("archive", "--format=tar", commit)
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        if tar.pax_headers.get("comment") != commit:
            raise EvidenceError("Git archive lacks the requested commit identity")
        if any(not (entry.isfile() or entry.isdir()) for entry in tar.getmembers()):
            raise EvidenceError("source archive contains non-regular entries")
        tar.extractall(destination, filter="data")
    return {"commit": commit, "tree": tree,
            "archive_sha256": hashlib.sha256(archive).hexdigest()}


def tool_version(command, cwd, env=None):
    result = capture(command, cwd, 10, 32768, env=env)
    if result.error or result.code != 0 or not result.stdout:
        raise EvidenceError(f"could not read version for {command[0]}")
    return result.stdout.decode("utf-8").strip()


def verify_esp(source, esp, efi_sha256):
    kernel = esp / KERNEL_REL
    compiled = source / "kernel/target/x86_64-unknown-none/release/fortress-kernel"
    digest = verify_pin(kernel, sha256(compiled))
    verify_pin(esp / EFI_REL, efi_sha256)
    config = (esp / "limine.conf").read_bytes()
    base = (source / "boot/limine.conf").read_bytes()
    path = b"    path: boot():/boot/fortress-kernel\n"
    image_hash = hashlib.blake2b(kernel.read_bytes()).hexdigest().encode("ascii")
    if base.count(path) != 1 or config != base.replace(path, path[:-1] + b"#" + image_hash + b"\n"):
        raise EvidenceError("Limine configuration does not bind the staged kernel")
    return {"kernel_elf_sha256": digest, "boot_efi_sha256": efi_sha256,
            "limine_config_sha256": hashlib.sha256(config).hexdigest()}


def load_user_code(data):
    if len(data) < 120 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise EvidenceError("invalid ELF64 image")
    typ, machine, version, entry, phoff = struct.unpack_from("<HHIQQ", data, 16)
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    if (typ, machine, version, phsize, phnum) != (2, 62, 1, 56, 1) or phoff > len(data) - 56:
        raise EvidenceError("unexpected ELF program header geometry")
    kind, rights, offset, address, _, size, mem_size, align = struct.unpack_from(
        "<IIQQQQQQ", data, phoff)
    if (kind, rights, align) != (1, 5, 4096) or not (
        entry == address and 0 < address < 1 << 47 and address % 4096 == 0
        and offset % 4096 == 0 and 0 < size == mem_size <= 4096 and offset <= len(data) - size
    ):
        raise EvidenceError("invalid executable PT_LOAD")
    return address, data[offset:offset + size]


def image_evidence(source, esp, out, fixture):
    kernel = (esp / KERNEL_REL).read_bytes()
    images = {}
    code = {}
    for process in ("a", "b"):
        name = f"process-{process}.elf"
        data = (source / f"build/{fixture}-userland" / name).read_bytes()
        if kernel.count(data) != 1:
            raise EvidenceError(f"{name} does not occur exactly once in the linked kernel")
        code[process] = load_user_code(data)
        images[f"process_{process}_elf_sha256"] = hashlib.sha256(data).hexdigest()
        (out / name).write_bytes(data)
    if images["process_a_elf_sha256"] == images["process_b_elf_sha256"]:
        raise EvidenceError("user ELF images must be distinct")
    return images, code


def com1_lines(raw):
    if not raw or len(raw) > MAX_SERIAL:
        raise EvidenceError("missing or oversized COM1")
    # OVMF can switch cursor position without adding a newline before ENTRY.
    # Require a line boundary or complete cursor-position sequence there.
    start = re.search(rb"(?m)(?:^|\x1b\[[0-9]{1,3};[0-9]{1,3}H)(FORTRESS_ENTRY\r?\n)", raw)
    if start is None or b"FORTRESS_" in raw[:start.start(1)] or not raw.endswith(b"\n"):
        raise EvidenceError("missing, ambiguous or truncated guest COM1")
    lines = [line.removesuffix(b"\r") for line in raw[start.start(1):].split(b"\n")[:-1]]
    if any(not re.fullmatch(rb"[\x20-\x7e]{1,512}", line) for line in lines):
        raise EvidenceError("invalid guest COM1 line")
    return [line.decode("ascii") for line in lines]


def fields(line, marker, names):
    parts = line.split(" ")
    if parts[0] != marker or len(parts) != 1 + len(names):
        raise EvidenceError(f"expected {marker}")
    parsed = {}
    for key, part in zip(names, parts[1:]):
        name, sep, value = part.partition("=")
        if name != key or sep != "=" or not value:
            raise EvidenceError(f"expected {marker} field {key}")
        parsed[key] = value
    return parsed


def number(value, base):
    pattern = r"0x(?:0|[1-9a-f][0-9a-f]{0,15})" if base == 16 else r"(?:0|[1-9][0-9]{0,5})"
    if not re.fullmatch(pattern, value):
        raise EvidenceError(f"invalid CPU value {value!r}")
    return int(value, base)


def user_state(record, root, image):
    for key in ("vector", "error"):
        record[key] = number(record[key], 10)
    for key in ("cs", "ss", "rip", "rsp", "flags", "cr3"):
        record[key] = number(record[key], 16)
    address, code = image
    if (record["cs"], record["ss"], record["cr3"]) != (0x23, 0x1b, root):
        raise EvidenceError("CPU state does not identify the expected CPL3 domain")
    if not (address <= record["rip"] < address + len(code) and record["rsp"] == USER_STACK_TOP):
        raise EvidenceError("CPL3 RIP/RSP outside the expected userspace bounds")
    if record["flags"] & 2 == 0 or record["flags"] & ((1 << 9) | (3 << 12) | (1 << 17)):
        raise EvidenceError("CPL3 RFLAGS do not match the interrupt or privilege policy")


USER_STACK_TOP = 0x800000
PEER_PROBE_VA = 0x900000
CPU_KEYS = ("cs", "ss", "rip", "rsp", "flags")
A_CASES = {
    "supervisor-read": (14, 5),
    "supervisor-write": (14, 7),
    "peer-read": (14, 4),
    "ud": (6, 0),
}
UNSAFE_ENTRY_FLAGS = (1 << 9) | (1 << 10) | (1 << 14) | (1 << 18)


def classify(raw, qemu_exit, fixture, code):
    if qemu_exit != QEMU_EXIT_OK:
        raise EvidenceError(f"QEMU exit {qemu_exit}, expected debug-exit {QEMU_EXIT_OK}")
    lines = com1_lines(raw)
    if lines[:2] != ["FORTRESS_ENTRY", f"FORTRESS_G1_PROFILE {fixture}"] or len(lines) < 3:
        raise EvidenceError("guest profile mismatch")
    memmap = fields(lines[2], "FORTRESS_MEMMAP_OK", ("entries", "modules"))
    if not 1 <= number(memmap["entries"], 10) <= 256 or not 0 <= number(memmap["modules"], 10) <= 16:
        raise EvidenceError("invalid validated memory map counters")
    lines = lines[3:]
    if lines[:1] not in (["FORTRESS_FRAMEBUFFER_OK"], ["FORTRESS_FRAMEBUFFER_ABSENT"]):
        raise EvidenceError("missing framebuffer status")
    lines = lines[1:]
    for allowed in ("FORTRESS_RSDP_PRESENT", "FORTRESS_BOOT_OK"):
        if lines[:1] == [allowed]:
            lines = lines[1:]
    if fixture == "k4":
        return classify_k4(lines, code)
    expected_records = len(A_CASES) + 6
    if len(lines) != expected_records:
        raise EvidenceError(f"expected {expected_records} K3 records, got {len(lines)}")

    parsed = fields(lines[0], "FORTRESS_K3_ROOTS", ("boot", "a", "b"))
    roots = {name: number(value, 16) for name, value in parsed.items()}
    if len(set(roots.values())) != 3 or any(
            root == 0 or root >= 1 << 52 or root & 4095 for root in roots.values()):
        raise EvidenceError("invalid or shared CR3 roots")
    if lines[1] != "FORTRESS_K3_REJECT elf=INVALID wx=DENIED":
        raise EvidenceError("missing malformed ELF / W+X rejection")

    faults = []
    for line, (case, expected) in zip(lines[2:], A_CASES.items()):
        fault = fields(line, "FORTRESS_K3_A",
                       ("case", "vector", "error", *CPU_KEYS, "cr2", "cr3", "target"))
        user_state(fault, roots["a"], code["a"])
        if fault["case"] != case or (fault["vector"], fault["error"]) != expected:
            raise EvidenceError(f"wrong process A exception for {case}")
        for key in ("cr2", "target"):
            fault[key] = number(fault[key], 16)
        if case.startswith("supervisor-"):
            if fault["cr2"] != fault["target"] or fault["target"] < 0xffff800000000000:
                raise EvidenceError("supervisor access fault target mismatch")
        if case == "peer-read":
            if fault["cr2"] != PEER_PROBE_VA or fault["target"] != PEER_PROBE_VA:
                raise EvidenceError("peer access fault target mismatch")
        if case == "ud":
            offset = fault["rip"] - code["a"][0]
            if fault["target"] != 0 or code["a"][1][offset:offset + 2] != b"\x0f\x0b":
                raise EvidenceError("process A exception did not identify its UD2 instruction")
        faults.append(fault)

    if lines[-4] != "FORTRESS_K3_REAP pid=STALE cap=STALE":
        raise EvidenceError("missing stale process and capability rejection")
    syscalls = []
    for step, line in enumerate(lines[-3:-1], 1):
        call = fields(line, "FORTRESS_K3_B",
                      ("step", "vector", "error", *CPU_KEYS, "live_flags", "cr3", "rax"))
        user_state(call, roots["b"], code["b"])
        for key in ("live_flags", "rax"):
            call[key] = number(call[key], 16)
        call["step"] = number(call["step"], 10)
        offset = call["rip"] - code["b"][0]
        if ((call["step"], call["vector"], call["error"]) != (step, 128, 0)
                or call["rax"] != 0x4b335f425f4f4b30 + step
                or call["live_flags"] & UNSAFE_ENTRY_FLAGS
                or bool(call["flags"] & (1 << 10)) != (step == 1)
                or offset < 2 or code["b"][1][offset - 2:offset] != b"\xcd\x80"):
            raise EvidenceError(f"invalid process B hardware trap at step {step}")
        syscalls.append(call)
    if syscalls[0]["rip"] >= syscalls[1]["rip"] or syscalls[0]["rsp"] != syscalls[1]["rsp"]:
        raise EvidenceError("process B did not resume on its original userspace stack")
    if lines[-1] != "FORTRESS_K3_DONE":
        raise EvidenceError("missing terminal K3 record")
    return {"roots": roots, "process_a_faults": faults, "process_b_syscalls": syscalls}


def classify_k4(lines, code):
    if len(lines) != 11 or lines[-1] != "FORTRESS_K4_DONE":
        raise EvidenceError("missing terminal K4 record")
    parsed = fields(lines[0], "FORTRESS_K4_ROOTS", ("boot", "a", "b"))
    roots = {name: number(value, 16) for name, value in parsed.items()}
    if len(set(roots.values())) != 3 or any(
            root == 0 or root >= 1 << 52 or root & 4095 for root in roots.values()):
        raise EvidenceError("invalid or shared K4 CR3 roots")
    phases = (
        ("send", "a", 0x40, 0x4b345f5041594c44),
        ("echo", "b", 0x41, 0x4b345f5041594c44),
        ("amplify", "a", 0x42, 2),
        ("done", "a", 0x43, 1),
    )
    witnesses = {
        2: "FORTRESS_K4_BLOCK request=1",
        4: "FORTRESS_K4_WAKE request=1",
        6: "FORTRESS_K4_DENY rights=0x2",
        8: ("FORTRESS_K4_NEGATIVE wrong_peer=DENIED canceled=DENIED "
            "revoked_queued=DENIED revoked_inflight=DENIED stale=DENIED early_wake=RETAINED overflow=DENIED"),
        9: "FORTRESS_K4_REAP process=STALE handle=STALE",
    }
    for pos, witness in witnesses.items():
        if lines[pos] != witness:
            raise EvidenceError(f"missing ordered K4 witness: {witness}")
    traps = [lines[i] for i in (1, 3, 5, 7)]
    parsed_traps = []
    for line, (phase, process, opcode, payload) in zip(traps, phases):
        record = fields(line, "FORTRESS_K4_TRAP",
                        ("phase", "vector", "error", *CPU_KEYS, "cr3", "rax", "rdi"))
        user_state(record, roots[process], code[process])
        for key in ("rax", "rdi"):
            record[key] = number(record[key], 16)
        address, text = code[process]
        rip = record["rip"] - address
        if (record["phase"], record["vector"], record["error"], record["rax"], record["rdi"]) != (
                phase, 128, 0, opcode, payload) or rip < 2 or text[rip - 2:rip] != b"\xcd\x80":
            raise EvidenceError(f"K4 CPU proof mismatch at {phase}")
        parsed_traps.append(record)
    if len({r["rip"] for r in parsed_traps if r["cr3"] == roots["a"]}) != 3:
        raise EvidenceError("K4 A phases did not take distinct software interrupt instructions")
    return {"roots": roots, "ipc_traps": parsed_traps}


def exact_hex(length):
    def parse(value):
        if not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
            raise argparse.ArgumentTypeError(f"expected {length} lowercase hex digits")
        return value
    return parse


def clean_build_env(work, limine_dir, fixture):
    env = {key: os.environ[key] for key in ("PATH", "HOME", "RUSTUP_HOME")
           if key in os.environ}
    env.update({"CARGO_HOME": str(work / "cargo-home"), "CARGO_NET_OFFLINE": "true",
                "LC_ALL": "C", "LIMINE_DIR": str(limine_dir),
                "G1_QEMU_TEST": "1", "G1_FIXTURE": fixture})
    return env


def drive(path, prefix):
    # In QEMU's comma-separated option syntax, doubled commas are literal.
    return prefix + str(path).replace(",", ",,")


def run(args, out, evidence):
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        raise EvidenceError("qemu-system-x86_64 is unavailable")
    with tempfile.TemporaryDirectory(prefix="fortress-k3-") as tmp:
        work = Path(tmp).resolve()
        source = work / "source"
        evidence["source"] = extract_source(args.source_commit, source)
        evidence["runner_sha256"] = sha256(Path(__file__))
        if evidence["runner_sha256"] != sha256(source / "boot/run-k3.py"):
            raise EvidenceError("runner differs from the evidence source commit")
        lock = source / "boot/kernel-integration-sources.json"
        deps = json.loads(lock.read_text(encoding="utf-8"))
        if deps.get("schema") != "fortress.integration.sources.v1" or not all(
            isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha)
            for sha in deps["sources"].values()
        ):
            raise EvidenceError("invalid integration source ledger")
        evidence["module_sources"] = deps
        evidence["module_source_ledger_sha256"] = sha256(lock)
        limine = work / "limine"
        limine.mkdir()
        vars_copy = work / "ovmf-vars.fd"
        code_copy = work / "ovmf-code.fd"
        firmware = evidence["firmware"] = {}
        firmware["limine_efi_sha256"] = pinned_copy(
            args.limine_efi, limine / "BOOTX64.EFI", args.limine_sha256)
        firmware["ovmf_code_sha256"] = pinned_copy(
            args.ovmf_code, code_copy, args.ovmf_code_sha256)
        firmware["ovmf_vars_initial_sha256"] = pinned_copy(
            args.ovmf_vars, vars_copy, args.ovmf_vars_sha256)
        env = clean_build_env(work, limine, args.fixture)
        kernel_dir = source / "kernel"
        toolchain = tomllib.loads((kernel_dir / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        rustc = tool_version(["rustc", "--version", "--verbose"], kernel_dir, env)
        cargo = tool_version(["cargo", "--version"], kernel_dir, env)
        if rustc.splitlines()[0].split()[1] != toolchain or cargo.split()[1] != toolchain:
            raise EvidenceError("Rust/Cargo version does not match kernel/rust-toolchain.toml")
        command = ["bash", "boot/build-standalone.sh"]
        evidence["build"] = {
            "command": command, "rustc": rustc, "cargo": cargo,
            "env": {key: env[key] for key in ("CARGO_NET_OFFLINE", "G1_QEMU_TEST", "G1_FIXTURE")},
            "target": "x86_64-unknown-none", "profile": "release",
        }
        build = capture(command, source, 180, MAX_BUILD_LOG, env=env)
        (out / "build.stdout").write_bytes(build.stdout)
        (out / "build.stderr").write_bytes(build.stderr)
        evidence["build"].update(exit_code=build.code, error=build.error)
        if build.error or build.code != 0:
            raise EvidenceError(f"kernel build failed ({build.error or build.code})")
        esp = source / "build/esp"
        evidence["images"] = verify_esp(source, esp, args.limine_sha256)
        images, code = image_evidence(source, esp, out, args.fixture)
        evidence["images"].update(images)
        for relative, name in ((KERNEL_REL, "fortress-kernel.elf"),
                               (EFI_REL, "BOOTX64.EFI"), ("limine.conf", "limine.conf")):
            shutil.copyfile(esp / relative, out / name)
        command = [
            qemu, "-machine", "q35,accel=tcg", "-m", "512M", "-smp", "1",
            "-no-reboot", "-display", "none", "-monitor", "none", "-serial", "stdio",
            "-net", "none", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-drive", drive(code_copy, "if=pflash,format=raw,readonly=on,file="),
            "-drive", drive(vars_copy, "if=pflash,format=raw,file="),
            "-drive", drive(esp, "if=virtio,format=raw,readonly=on,file=fat:ro:"),
        ]
        qemu_env = {"HOME": str(work), "PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"}
        evidence["qemu"] = {
            "command": command, "version": tool_version([qemu, "--version"], work, qemu_env),
            "sha256": sha256(Path(qemu)), "timeout_seconds": args.timeout,
        }
        guest = capture(command, work, args.timeout, MAX_SERIAL, env=qemu_env)
        (out / "COM1.bin").write_bytes(guest.stdout)
        (out / "qemu.stderr").write_bytes(guest.stderr)
        evidence["qemu"].update(exit_code=guest.code, error=guest.error, duration_ms=guest.duration_ms,
                                com1_sha256=hashlib.sha256(guest.stdout).hexdigest())
        if guest.error:
            raise EvidenceError(f"QEMU {guest.error}")
        evidence["cpu"] = classify(guest.stdout, guest.code, args.fixture, code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True, type=exact_hex(40))
    parser.add_argument("--fixture", choices=("k3", "k4"), default="k3")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    for name in ("limine-efi", "ovmf-code", "ovmf-vars"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("limine", "ovmf-code", "ovmf-vars"):
        parser.add_argument("--" + name + "-sha256", required=True, type=exact_hex(64))
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be in 1..600 seconds")
    out = args.artifacts_dir.resolve()
    out.mkdir(parents=True)
    evidence = {"schema": "fortress.qa.k3.v1", "fixture": args.fixture,
                "scope": "EXPERIMENTAL_VM_ONLY", "status": "FAIL"}
    try:
        run(args, out, evidence)
    except (EvidenceError, OSError, subprocess.CalledProcessError, ValueError) as error:
        evidence["reason"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr)
    else:
        evidence["status"] = "PASS"
        print(f"PASS: {args.fixture} GUEST COM1 + QEMU exit {QEMU_EXIT_OK}")
    (out / "manifest.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"EVIDENCE: {out / 'manifest.json'}")
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
