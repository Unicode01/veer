#!/usr/bin/env sh
# Compiles the probes a `-tags veer_kfuncs` binary embeds. They call the module's
# kfuncs through BTF resolved at load time, so they do not depend on the kernel
# the module is later built for; releases build them without any module.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
: "${BPF_CLANG:=clang}"
# BPF v1, as scripts/build-ebpf.sh pins the core objects: newer clang
# defaults to v3, which old kernels reject.
: "${BPF_CPU:=v1}"
for probe in veer-kfuncs-probe-bpf veer-kfuncs-ingress-probe-bpf veer-kfuncs-wan-probe-bpf; do
	"$BPF_CLANG" -O2 -g -target bpf -mcpu="$BPF_CPU" -c "$ROOT_DIR/internal/app/ebpf/$probe.c" -o "$ROOT_DIR/internal/app/ebpf/$probe.o"
done
