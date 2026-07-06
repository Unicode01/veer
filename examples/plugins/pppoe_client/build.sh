#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
: "${BPF_CLANG:=clang}"

"$BPF_CLANG" -O2 -g -target bpf -c pppoe_tunnel.bpf.c -o pppoe_tunnel.o
echo "built pppoe_tunnel.o"
