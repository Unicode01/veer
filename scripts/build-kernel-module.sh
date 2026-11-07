#!/usr/bin/env sh
# Native, matching-kernel build. Default releases never invoke kbuild.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
: "${BPF_CLANG:=clang}"
# KDIR, VMLINUX_BTF and RESOLVE_BTFIDS pass through to the module build.
sh "$ROOT_DIR/kernel/veer_kfuncs/build.sh"
module="$ROOT_DIR/kernel/veer_kfuncs/veer_kfuncs.ko"
release=$(modinfo -F vermagic "$module" | awk '{print $1}')
case "$release" in ''|*[!a-zA-Z0-9._+-]*) echo "invalid kernel release" >&2; exit 1 ;; esac
mkdir -p "$ROOT_DIR/kernel/$release"
install -m 0644 "$module" "$ROOT_DIR/kernel/$release/veer_kfuncs.ko"
"$BPF_CLANG" -O2 -g -target bpf -c "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-probe-bpf.c" -o "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-probe-bpf.o"
"$BPF_CLANG" -O2 -g -target bpf -c "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-ingress-probe-bpf.c" -o "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-ingress-probe-bpf.o"
"$BPF_CLANG" -O2 -g -target bpf -c "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-wan-probe-bpf.c" -o "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-wan-probe-bpf.o"
echo "optional kernel module: kernel/$release/veer_kfuncs.ko (build Go with -tags veer_kfuncs)"
