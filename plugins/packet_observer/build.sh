#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
: "${BPF_CLANG:=clang}"
# BPF v1, as scripts/build-ebpf.sh pins the core objects: newer clang
# defaults to v3, which old kernels reject.
: "${BPF_CPU:=v1}"
: "${BPF_EXTRA_CFLAGS:=}"

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

# shellcheck disable=SC2086
"$BPF_CLANG" -O2 -g -target bpf -mcpu="$BPF_CPU" -D__TARGET_ARCH_"$(target_arch)" $BPF_EXTRA_CFLAGS -c packet_observer.bpf.c -o packet_observer.o
if command -v llvm-strip >/dev/null 2>&1; then
	llvm-strip -g packet_observer.o || true
fi
echo "built packet_observer.o"
