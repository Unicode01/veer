#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
: "${BPF_CLANG:=clang}"
# BPF v1, as scripts/build-ebpf.sh pins the core objects: newer clang
# defaults to v3, which old kernels reject.
: "${BPF_CPU:=v1}"
: "${BPF_EXTRA_CFLAGS:=}"

# shellcheck disable=SC2086
"$BPF_CLANG" -O2 -g -target bpf -mcpu="$BPF_CPU" $BPF_EXTRA_CFLAGS -c tunnel_adapter.bpf.c -o tunnel_adapter.o
if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip -g tunnel_adapter.o
fi
echo "built tunnel_adapter.o"

# Optional host capability selects this object at runtime.
# shellcheck disable=SC2086
"$BPF_CLANG" -O2 -g -target bpf -mcpu="$BPF_CPU" $BPF_EXTRA_CFLAGS -DVEER_KFUNCS=1 -c tunnel_adapter.bpf.c -o tunnel_adapter-kfuncs.o
# The separate object keeps older helper modules loadable.
# shellcheck disable=SC2086
"$BPF_CLANG" -O2 -g -target bpf -mcpu="$BPF_CPU" $BPF_EXTRA_CFLAGS -DVEER_KFUNCS=1 -DVEER_KFUNCS_DIRECT=1 -c tunnel_adapter.bpf.c -o tunnel_adapter-direct.o
