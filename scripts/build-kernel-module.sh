#!/usr/bin/env sh
# Native, matching-kernel build. Default releases never invoke kbuild.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
: "${KDIR:=/lib/modules/$(uname -r)/build}"
: "${BPF_CLANG:=clang}"
[ -f "$KDIR/Makefile" ] || { echo "matching kernel headers are required: $KDIR" >&2; exit 1; }
make -C "$ROOT_DIR/kernel/veer_kfuncs" KDIR="$KDIR"
# Some distro header packages omit the vmlinux ELF and kbuild skips module
# BTF. For a native build, the running kernel supplies the exact base BTF.
# Never regenerate BTF that kbuild already emitted: that changes resolved IDs.
module="$ROOT_DIR/kernel/veer_kfuncs/veer_kfuncs.ko"
# Debian headers can report the upstream version from `make kernelrelease`.
# The actual module vermagic identifies the distribution kernel ABI.
release=$(modinfo -F vermagic "$module" | awk '{print $1}')
case "$release" in ''|*[!a-zA-Z0-9._+-]*) echo "invalid kernel release" >&2; exit 1 ;; esac
if ! readelf -S "$module" | grep -q '\.BTF '; then
    if [ -z "${VMLINUX_BTF:-}" ]; then
        [ "$release" = "$(uname -r)" ] || {
            echo "cross-kernel BTF generation requires matching VMLINUX_BTF" >&2; exit 1;
        }
        VMLINUX_BTF=/sys/kernel/btf/vmlinux
    fi
    [ -r "$VMLINUX_BTF" ] || { echo "matching base kernel BTF is required" >&2; exit 1; }
    tool_version=$(printf '%s\n' "$release" | cut -d . -f 1,2)
    resolver=${RESOLVE_BTFIDS:-}
    for candidate in "$resolver" "$KDIR/tools/bpf/resolve_btfids/resolve_btfids" \
        /usr/lib/linux-kbuild-"$tool_version"*/tools/bpf/resolve_btfids/resolve_btfids \
        /usr/src/linux-kbuild-"$tool_version"*/tools/bpf/resolve_btfids/resolve_btfids
    do
        if [ -x "$candidate" ]; then resolver=$candidate; break; fi
    done
    if [ -z "$resolver" ] || [ ! -x "$resolver" ]; then
        echo "matching kernel resolve_btfids tool is required (set RESOLVE_BTFIDS for a kernel source build)" >&2; exit 1;
    fi
    # Resolve in an isolated directory so old sidecars from a previous build
    # cannot be mistaken for this invocation's output. Older resolvers patch
    # the ELF in place; newer ones emit both sections as separate files.
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT INT TERM
    resolved="$work/veer_kfuncs.ko"
    cp "$module" "$resolved"
    pahole -J --btf_base "$VMLINUX_BTF" "$resolved"
    "$resolver" -b "$VMLINUX_BTF" "$resolved"
    if [ -f "$resolved.BTF" ]; then
        [ -f "$resolved.BTF_ids" ] || { echo "resolver omitted .BTF_ids output" >&2; exit 1; }
        objcopy --update-section ".BTF=$resolved.BTF" \
            --update-section ".BTF_ids=$resolved.BTF_ids" "$resolved"
    fi
    install -m 0644 "$resolved" "$module"
fi
mkdir -p "$ROOT_DIR/kernel/$release"
install -m 0644 "$ROOT_DIR/kernel/veer_kfuncs/veer_kfuncs.ko" "$ROOT_DIR/kernel/$release/veer_kfuncs.ko"
"$BPF_CLANG" -O2 -g -target bpf -c "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-probe-bpf.c" -o "$ROOT_DIR/internal/app/ebpf/veer-kfuncs-probe-bpf.o"
echo "optional kernel module: kernel/$release/veer_kfuncs.ko (build Go with -tags veer_kfuncs)"
