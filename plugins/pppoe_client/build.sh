#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
: "${BPF_CLANG:=clang}"
: "${BPF_EXTRA_CFLAGS:=}"
: "${PPPOE_TUNNEL_DIAG:=0}"

target_arch() {
	case "$(uname -m)" in
		x86_64|amd64) printf '%s\n' x86 ;;
		aarch64|arm64) printf '%s\n' arm64 ;;
		armv7*|armv6*|armhf|arm) printf '%s\n' arm ;;
		riscv64) printf '%s\n' riscv ;;
		s390x) printf '%s\n' s390 ;;
		ppc64le) printf '%s\n' powerpc ;;
		*) printf '%s\n' x86 ;;
	esac
}

if [ "$PPPOE_TUNNEL_DIAG" = "1" ]; then
	BPF_EXTRA_CFLAGS="$BPF_EXTRA_CFLAGS -DPPPOE_TUNNEL_DIAG=1"
fi

# shellcheck disable=SC2086
"$BPF_CLANG" -O2 -target bpf -D__TARGET_ARCH_"$(target_arch)" $BPF_EXTRA_CFLAGS -c pppoe_tunnel.bpf.c -o pppoe_tunnel.o
if command -v llvm-strip >/dev/null 2>&1; then
	llvm-strip -g pppoe_tunnel.o || true
fi
echo "built pppoe_tunnel.o"
