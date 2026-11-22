#!/usr/bin/env sh
# Builds what the tests and a development binary need besides Go code: the
# core and bundled plugin eBPF objects, and the native plugins with the
# plugin worker veer embeds (for this host's target; VEER_NATIVE_TRIPLES
# overrides it).
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

sh "$ROOT_DIR/scripts/build-ebpf.sh"
sh "$ROOT_DIR/scripts/build-plugin-ebpf.sh"

if [ -z "${VEER_NATIVE_TRIPLES:-}" ]; then
	case "$(uname -m)" in
		x86_64|amd64) VEER_NATIVE_TRIPLES=x86_64-linux-gnu ;;
		aarch64|arm64) VEER_NATIVE_TRIPLES=aarch64-linux-gnu ;;
		*) VEER_NATIVE_TRIPLES= ;;
	esac
fi
if [ -n "$VEER_NATIVE_TRIPLES" ]; then
	if ! command -v cargo >/dev/null 2>&1; then
		echo "cargo is required to build the native plugins and the plugin worker" >&2
		exit 1
	fi
	# shellcheck disable=SC2086
	bash "$ROOT_DIR/scripts/build-native-plugins.sh" $VEER_NATIVE_TRIPLES
fi
