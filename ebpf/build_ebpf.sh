#!/usr/bin/env bash
set -euo pipefail

# Build slurp_ebpf.o using clang/llvm. Requires linux headers and clang with bpf target.
# Example:
#   sudo pacman -S llvm bpf clang libelf linux-headers 
#   ./build_ebpf.sh

OUT=../slurp_ebpf.o
SRC=slurp_ebpf.c
CC=clang

$CC -O2 -g -target bpf -c "$SRC" -o "$OUT"
echo "Built $OUT (from bpf/$SRC)"
