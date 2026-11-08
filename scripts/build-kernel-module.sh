#!/usr/bin/env sh
# Native, matching-kernel build. Default releases never invoke kbuild.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# KDIR, VMLINUX_BTF and RESOLVE_BTFIDS pass through to the module build.
sh "$ROOT_DIR/kernel/veer_kfuncs/build.sh"
module="$ROOT_DIR/kernel/veer_kfuncs/veer_kfuncs.ko"
release=$(modinfo -F vermagic "$module" | awk '{print $1}')
case "$release" in ''|*[!a-zA-Z0-9._+-]*) echo "invalid kernel release" >&2; exit 1 ;; esac
mkdir -p "$ROOT_DIR/kernel/$release"
install -m 0644 "$module" "$ROOT_DIR/kernel/$release/veer_kfuncs.ko"
sh "$ROOT_DIR/scripts/build-kfuncs-probes.sh"
echo "optional kernel module: kernel/$release/veer_kfuncs.ko (build Go with -tags veer_kfuncs)"
