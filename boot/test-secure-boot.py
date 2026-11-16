#!/usr/bin/env python3
"""Exercise the Limine trust chain in disposable OVMF with a hash-only db."""
import argparse
from hashlib import blake2b, sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

LOADER = "EFI/BOOT/BOOTX64.EFI"
CONFIG = "limine.conf"
KERNEL = "boot/fortress-kernel"
KERNEL_PATH = b"    path: boot():/boot/fortress-kernel#"
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
RUNNER = Path(__file__).with_name("run-qemu.py")


def read_esp(root):
    bundle = {}
    limits = {LOADER: 8 << 20, CONFIG: 64 << 10, KERNEL: 64 << 20}
    for name, limit in limits.items():
        path = root / name
        if path.resolve() != path or not path.is_file():
            raise ValueError(f"expected a regular ESP file without symlink components: {name}")
        with path.open("rb") as stream:
            payload = stream.read(limit + 1)
        if not 0 < len(payload) <= limit:
            raise ValueError(f"unexpected ESP file size: {name}")
        bundle[name] = payload
    expected = KERNEL_PATH + blake2b(bundle[KERNEL]).hexdigest().encode("ascii")
    if bundle[CONFIG].splitlines().count(expected) != 1:
        raise ValueError("ESP config must bind the staged kernel digest")
    return bundle


def run_case(args, case, esp, vars_file, rejection=None):
    output = args.out / case
    output.mkdir()
    with (output / "runner.log").open("wb") as log:
        proc = subprocess.run([
            sys.executable, "-B", str(RUNNER), "--esp", str(esp), "--secure-ovmf",
            "--ovmf-code", str(args.ovmf_code), "--ovmf-vars", str(vars_file),
            "--timeout", str(args.timeout), "--artifacts-dir", str(output),
        ], stdout=log, stderr=subprocess.STDOUT)
    result = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    raw = (output / "COM1.bin").read_bytes()
    serial = ANSI.sub(b"", raw)
    if rejection is None:
        ok = proc.returncode == 0 and result["qemu_exit_code"] == 33 and result["result"] == "PASS"
    else:
        # Reject unrelated failures (startup error, empty log, random timeout).
        # A pre-kernel failure has an exact firmware/loader message and no entry.
        ok = (proc.returncode == 4 and result["observed_outcome"] == "FIXTURE_ID_MISMATCH"
              and b"FORTRESS_ENTRY" not in raw and rejection.search(serial) is not None)
    if not ok:
        raise RuntimeError(f"{case} failed; inspect {output / 'runner.log'}")
    print(f"PASS {case}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--esp", type=Path, required=True, help="staged normal G1 test ESP")
    parser.add_argument("--limine", type=Path, required=True, help="verified host Limine utility")
    parser.add_argument("--ovmf-code", type=Path, required=True, help="Secure Boot capable OVMF code")
    parser.add_argument("--ovmf-vars", type=Path, required=True, help="blank virtual OVMF VARS template")
    parser.add_argument("--out", type=Path, required=True, help="new directory for raw evidence")
    parser.add_argument("--timeout", type=int, default=25)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be in 1..600 seconds")
    import pefile
    from virt.firmware.varstore import autodetect
    from virt.peutils.pesign import pe_authenticode_hash

    vars_tool = Path(sys.executable).with_name("virt-fw-vars")
    if not vars_tool.is_file():
        vars_tool = shutil.which("virt-fw-vars")
    if vars_tool is None:
        raise ValueError("virt-fw-vars from virt-firmware is required")
    bundle = read_esp(args.esp.resolve(strict=True))
    args.out.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="fortress-sb-") as scratch:
        scratch = Path(scratch)
        esp = scratch / "esp"
        for name, payload in bundle.items():
            path = esp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        loader = esp / LOADER
        config = esp / CONFIG
        kernel = esp / KERNEL
        cfg_digest = blake2b(bundle[CONFIG]).hexdigest()
        subprocess.run([str(args.limine.resolve(strict=True)), "enroll-config", str(loader), cfg_digest], check=True)
        efi_digest = pe_authenticode_hash(pefile.PE(str(loader))).hex()
        if efi_digest == pe_authenticode_hash(pefile.PE(data=bundle[LOADER])).hex():
            raise RuntimeError("enrolling the config did not change the authorized EFI image")

        # Test-only PK. db contains just the exact enrolled EFI image digest.
        # Each QEMU case gets its own copy of the virtual variable store.
        cert, key = scratch / "pk.pem", scratch / "pk.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                        "-days", "1", "-subj", "/CN=FortressOS disposable OVMF test/",
                        "-out", str(cert), "-keyout", str(key)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        template = scratch / "blank.fd"
        shutil.copyfile(args.ovmf_vars, template)
        store = autodetect.open_varstore(str(template))
        if store is None or any(name in store.get_varlist() for name in ("PK", "KEK", "db", "dbx")):
            raise ValueError("expected a blank virtual OVMF VARS template")
        vars_file = scratch / "enrolled.fd"
        owner = str(uuid.uuid4())
        subprocess.run([str(vars_tool), "--input", str(template), "--output", str(vars_file),
                        "--set-pk", owner, str(cert), "--add-db-hash", owner, efi_digest,
                        "--secure-boot"], check=True)
        (args.out / "trust-inputs.json").write_text(json.dumps({
            "db_authenticode_sha256": efi_digest,
            "enrolled_config_blake2b": cfg_digest,
            "initial_ovmf_vars_sha256": sha256(vars_file.read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")

        run_case(args, "authorized", esp, vars_file)
        changed = bytearray(bundle[KERNEL])
        changed[-1] ^= 1
        kernel.write_bytes(changed)
        run_case(args, "kernel-tamper", esp, vars_file, re.compile(re.escape(
            b"PANIC: Blake2b hash for URI `boot():/boot/fortress-kernel` does not match!")))
        config.write_bytes(bundle[CONFIG].replace(blake2b(bundle[KERNEL]).hexdigest().encode("ascii"),
                                                  blake2b(changed).hexdigest().encode("ascii")))
        run_case(args, "kernel-and-config-tamper", esp, vars_file,
                 re.compile(b"PANIC: !!! CHECKSUM MISMATCH FOR CONFIG FILE !!!"))
        kernel.write_bytes(bundle[KERNEL])
        config.write_bytes(bundle[CONFIG])
        loader.write_bytes(bundle[LOADER])
        run_case(args, "unapproved-efi", esp, vars_file, re.compile(
            rb"(?m)^BdsDxe: failed to load Boot[0-9A-Fa-f]{4} [^\r\n]*: "
            rb"(?:Access Denied|Security Violation)\r?$"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ImportError, OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"SECURE_BOOT_LAB_FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
