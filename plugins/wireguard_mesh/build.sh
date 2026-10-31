#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
: "${BPF_CLANG:=clang}"
: "${BPF_EXTRA_CFLAGS:=}"

# shellcheck disable=SC2086
"$BPF_CLANG" -O2 -g -target bpf $BPF_EXTRA_CFLAGS -c wg_adapter.bpf.c -o wg_adapter.o
if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip -g wg_adapter.o
fi
echo "built wg_adapter.o"
