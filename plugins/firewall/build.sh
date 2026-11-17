#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
: "${BPF_CLANG:=clang}"
# BPF v1, as scripts/build-ebpf.sh pins the core objects: newer clang
# defaults to v3, which old kernels reject.
: "${BPF_CPU:=v1}"
: "${BPF_EXTRA_CFLAGS:=}"

# shellcheck disable=SC2086
"$BPF_CLANG" -O2 -g -target bpf -mcpu="$BPF_CPU" $BPF_EXTRA_CFLAGS -c firewall.bpf.c -o firewall.o
if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip -g firewall.o
fi
echo "built firewall.o"
