#!/usr/bin/env bash
# This script only writes into the local build/ directory, never block devices.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${LIMINE_DIR:?Set LIMINE_DIR to a verified and built Limine v12.9.6 release}"
if [[ "${G1_QEMU_TEST:-0}" == 1 && "${G1_FIXTURE:-}" == k3 ]]; then
    bash userland/k3-fixtures/build.sh
    export K3_A_ELF="$PWD/build/k3-userland/process-a.elf"
    export K3_B_ELF="$PWD/build/k3-userland/process-b.elf"
fi
if [[ "${G1_QEMU_TEST:-0}" == 1 && "${G1_FIXTURE:-}" == k4 ]]; then
    bash userland/k4-fixtures/build.sh
    export K3_A_ELF="$PWD/build/k4-userland/process-a.elf"
    export K3_B_ELF="$PWD/build/k4-userland/process-b.elf"
fi
# Enter kernel/ so rustup honors its explicitly pinned toolchain.
# Linker script is resolved through kernel/build.rs, independent of cwd.
(
  cd kernel
  if [[ "${G1_QEMU_TEST:-0}" == "1" ]]; then
      features="g1-qemu-exit"
      if [[ -n "${G1_FIXTURE:-}" ]]; then
          case "${G1_FIXTURE}" in
              map-zero|map-overflow|map-overlap|fb-invalid|fb-alias|kernel-overflow|no-fb|late-panic|hang|cpu-ud|cpu-gp|console|k2-ud|k1-real|k3|k4) ;;
              *) echo "Unknown G1_FIXTURE: ${G1_FIXTURE}" >&2; exit 2 ;;
          esac
          features="g1-qemu-exit,g1-fixture-${G1_FIXTURE}"
      fi
      cargo build --release --target x86_64-unknown-none --features "$features"
  else
      if [[ -n "${G1_FIXTURE:-}" ]]; then
          echo "G1_FIXTURE requires G1_QEMU_TEST=1; no physical/hardware fixtures" >&2; exit 2
      fi
      cargo build --release --target x86_64-unknown-none
  fi
)
python3 boot/check-kernel-elf.py kernel/target/x86_64-unknown-none/release/fortress-kernel
if [[ "${G1_QEMU_TEST:-0}" != "1" ]]; then
    # Default hardware profile must not retain ISA debug-exit or fixture code.
    python3 boot/check-production-elf.py kernel/target/x86_64-unknown-none/release/fortress-kernel
fi
mkdir -p build/esp/EFI/BOOT build/esp/boot
cp kernel/target/x86_64-unknown-none/release/fortress-kernel build/esp/boot/fortress-kernel
if [[ -f "$LIMINE_DIR/BOOTX64.EFI" ]]; then
    cp "$LIMINE_DIR/BOOTX64.EFI" build/esp/EFI/BOOT/BOOTX64.EFI
elif [[ -f "$LIMINE_DIR/usr/share/limine/BOOTX64.EFI" ]]; then
    cp "$LIMINE_DIR/usr/share/limine/BOOTX64.EFI" build/esp/EFI/BOOT/BOOTX64.EFI
else
    echo "Missing BOOTX64.EFI; build Limine with UEFI x86-64 enabled" >&2; exit 2
fi
# Bind the exact staged kernel to the loader config. Authenticating this config
# requires an enrolled config digest and enforcing UEFI Secure Boot.
python3 - <<'LIMINE_CONFIG'
from hashlib import blake2b
from pathlib import Path

esp = Path("build/esp")
config = Path("boot/limine.conf").read_bytes()
path = b"    path: boot():/boot/fortress-kernel\n"
if config.count(path) != 1:
    raise SystemExit("expected exactly one FortressOS kernel path in Limine config")
kernel_hash = blake2b((esp / "boot/fortress-kernel").read_bytes()).hexdigest().encode("ascii")
(esp / "limine.conf").write_bytes(config.replace(path, path[:-1] + b"#" + kernel_hash + b"\n"))
LIMINE_CONFIG
echo "Prepared local virtual ESP tree: build/esp/"
