#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

echo "[slurp-ebpf] Building BPF object..."
if [ -x "./ebpf/build_ebpf.sh" ]; then
  (cd ebpf && ./build_ebpf.sh)
else
  ./ebpf/build_ebpf.sh
fi
if [ $? -ne 0 ]; then
  echo "[slurp-ebpf] Error: Failed to build BPF object."
  exit 1
fi

echo "[slurp-ebpf] Building Go binary..."
./build.sh
if [ $? -ne 0 ]; then
  echo "[slurp-ebpf] Error: Failed to build Go binary."
  exit 1
fi  

echo "[slurp-ebpf] Ready to run. Note: loading BPF objects requires root privileges."
ARGS="$@"

if [ "$(id -u)" -ne 0 ]; then
  echo "[slurp-ebpf] Not running as root; using sudo to execute slurp-ebpf. You may be prompted for a password."
  sudo ./slurp-ebpf $ARGS
else
  ./slurp $ARGS
fi

