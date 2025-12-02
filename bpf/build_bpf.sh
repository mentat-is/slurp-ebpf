#!/usr/bin/env bash
set -euo pipefail

# Build slurp_bpf.o using clang/llvm. Requires linux headers and clang with bpf target.
# Example:
#   sudo apt install clang llvm libelf-dev gcc make
#   ./build_bpf.sh

OUT=../slurp_bpf.o
SRC=slurp_bpf.c
CC=clang

$CC -O2 -g -target bpf -c "$SRC" -o "$OUT"
echo "Built $OUT (from bpf/$SRC)"
