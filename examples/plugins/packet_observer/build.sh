#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
: "${BPF_CLANG:=clang}"

"$BPF_CLANG" -O2 -g -target bpf -c packet_observer.bpf.c -o packet_observer.o
echo "built packet_observer.o"
