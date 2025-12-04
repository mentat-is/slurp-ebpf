#!/usr/bin/env bash
set -euo pipefail

# Build slurp_ebpf.o using clang/llvm. Requires linux headers and clang with bpf target.
# Example:
#   sudo pacman -S llvm bpf clang libelf linux-headers 
#   ./build_ebpf.sh

OUT=../slurp_ebpf.o
SRC=slurp_ebpf.c
CC=clang

# -D__TARGET_ARCH_x86 is needed for CO-RE on x86_64
# -Wno-compare-distinct-pointer-types suppresses harmless warnings
$CC -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -Wno-compare-distinct-pointer-types \
    -c "$SRC" -o "$OUT"
echo "Built $OUT (from bpf/$SRC)"
