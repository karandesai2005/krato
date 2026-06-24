#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I ebpf/ -c ebpf/dpi.c -o internal/dpi/dpi_bpf.o

echo "✅ built ${ROOT}/internal/dpi/dpi_bpf.o"