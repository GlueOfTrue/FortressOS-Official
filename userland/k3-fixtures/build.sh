#!/usr/bin/env bash
# Build real, independent x86_64-unknown-none ELF user fixtures.
set -euo pipefail
source_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$source_dir/../.." && pwd)"
output_dir="${1:-$repo_dir/build/k3-userland}"
fixture_dir="$(cd "${2:-$source_dir}" && pwd)"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
staging="$(mktemp -d "$output_dir/.k3-build.XXXXXXXX")"
trap 'rm -rf "$staging"' EXIT
cd "$repo_dir/kernel"
for process in a b; do
    FORTRESS_FIXTURE_A="$fixture_dir/process-a.S" \
    FORTRESS_FIXTURE_B="$fixture_dir/process-b.S" \
    "${RUSTC:-rustc}" "$source_dir/entry.rs" \
        --crate-name "k3_process_$process" \
        --edition 2021 \
        --target x86_64-unknown-none \
        --cfg "k3_process_$process" \
        -C panic=abort \
        -C relocation-model=static \
        -C strip=symbols \
        -C "link-arg=-T$source_dir/linker.ld" \
        -C link-arg=--no-eh-frame-hdr \
        -C link-arg=--build-id=none \
        -C link-arg=-z \
        -C link-arg=max-page-size=4096 \
        -C link-arg=--orphan-handling=error \
        -o "$staging/process-$process.elf"
done

for process in a b; do
    mv -f "$staging/process-$process.elf" "$output_dir/process-$process.elf"
done
