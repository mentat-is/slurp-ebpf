#!/usr/bin/env bash
_ver=$BUILD_VERSION
if [ -z "$_ver" ]; then
  go build -o slurp-ebpf ./cmd/slurp-ebpf
else
  go build -ldflags="-X 'main.AppVersion=$_ver'" -o slurp-ebpf ./cmd/slurp-ebpf
fi
