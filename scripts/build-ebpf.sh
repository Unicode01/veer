#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
: "${BPF_CLANG:=clang}"
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

arch_include_flags() {
	seen=""
	add_include_dir() {
		dir=$1
		if [ -n "$dir" ] && [ -d "$dir" ]; then
			case " $seen " in
				*" $dir "*) ;;
				*)
					seen="$seen $dir"
					printf '%s\n' "-I$dir"
					;;
			esac
		fi
	}

	if command -v gcc >/dev/null 2>&1; then
		triplet=$(gcc -dumpmachine 2>/dev/null || true)
		add_include_dir "/usr/include/$triplet"
	fi
	if command -v cc >/dev/null 2>&1; then
		triplet=$(cc -dumpmachine 2>/dev/null || true)
		add_include_dir "/usr/include/$triplet"
	fi
	if command -v "$BPF_CLANG" >/dev/null 2>&1; then
		triplet=$("$BPF_CLANG" -print-multiarch 2>/dev/null || true)
		add_include_dir "/usr/include/$triplet"
	fi
	case "$(uname -m)" in
		x86_64|amd64) add_include_dir /usr/include/x86_64-linux-gnu ;;
		aarch64|arm64) add_include_dir /usr/include/aarch64-linux-gnu ;;
		armv7*|armv6*|armhf|arm) add_include_dir /usr/include/arm-linux-gnueabihf ;;
		riscv64) add_include_dir /usr/include/riscv64-linux-gnu ;;
		s390x) add_include_dir /usr/include/s390x-linux-gnu ;;
		ppc64le) add_include_dir /usr/include/powerpc64le-linux-gnu ;;
	esac
}

build_core() {
	src=$1
	out=$2
	shift 2
	# arch_include_flags and BPF_EXTRA_CFLAGS intentionally expand to argument lists.
	# shellcheck disable=SC2046,SC2086
	"$BPF_CLANG" -O2 -g -target bpf -D__TARGET_ARCH_"$(target_arch)" -I"$EBPF_DIR/include" $(arch_include_flags) $BPF_EXTRA_CFLAGS "$@" -c "$src" -o "$out"
	if command -v llvm-strip >/dev/null 2>&1; then
		llvm-strip -g "$out" || true
	fi
	printf 'built %s\n' "$out"
}

EBPF_DIR="$ROOT_DIR/internal/app/ebpf"
build_core "$EBPF_DIR/forward-tc-bpf.c" "$EBPF_DIR/forward-tc-bpf.o"
build_core "$EBPF_DIR/forward-tc-bpf.c" "$EBPF_DIR/forward-tc-bpf-stats.o" -DFORWARD_ENABLE_TRAFFIC_STATS=1
build_core "$EBPF_DIR/forward-xdp-bpf.c" "$EBPF_DIR/forward-xdp-bpf.o"
build_core "$EBPF_DIR/forward-xdp-bpf.c" "$EBPF_DIR/forward-xdp-bpf-stats.o" -DFORWARD_ENABLE_TRAFFIC_STATS=1
build_core "$EBPF_DIR/plugin-xdp-dispatcher-bpf.c" "$EBPF_DIR/plugin-xdp-dispatcher-bpf.o"
