#!/usr/bin/env bash
# Build the cooperative IPC fixture with the same static ELF profile as K3.
set -euo pipefail
source_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$source_dir/../.." && pwd)"
exec bash "$repo_dir/userland/k3-fixtures/build.sh" "${1:-$repo_dir/build/k4-userland}" "$source_dir"
