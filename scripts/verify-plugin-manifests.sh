#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PLUGIN_SOURCE_DIR=${VEER_PLUGIN_SOURCE_DIR:-"$ROOT_DIR/plugins"}
VERIFY_OS=${VEER_PLUGIN_VERIFY_OS:-linux}
VERIFY_ARCH=${VEER_PLUGIN_VERIFY_ARCH:-amd64}
VERIFY_KERNEL=${VEER_PLUGIN_VERIFY_KERNEL:-6.6.0}
VERIFY_BIN=${VEER_PLUGIN_VERIFY_BINARY:-}
TMP_DIR=

cleanup() {
	if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
		rm -rf -- "$TMP_DIR"
	fi
}

trap cleanup EXIT INT TERM

if [ ! -d "$PLUGIN_SOURCE_DIR" ]; then
	echo "plugin directory does not exist: $PLUGIN_SOURCE_DIR" >&2
	exit 1
fi

if [ -n "$VERIFY_BIN" ]; then
	if [ ! -x "$VERIFY_BIN" ]; then
		echo "VEER_PLUGIN_VERIFY_BINARY is not executable: $VERIFY_BIN" >&2
		exit 1
	fi
else
	TMP_DIR=$(mktemp -d "$ROOT_DIR/.veer-plugin-verify.XXXXXX")
	VERIFY_BIN="$TMP_DIR/veer-plugin-verify"
	case "$(go env GOOS)" in
		windows) VERIFY_BIN="${VERIFY_BIN}.exe" ;;
	esac
	(
		cd "$ROOT_DIR"
		go build -trimpath -o "$VERIFY_BIN" .
	)
fi

checked=0
for manifest_path in "$PLUGIN_SOURCE_DIR"/*/plugin.json; do
	[ -f "$manifest_path" ] || continue
	plugin_dir=${manifest_path%/plugin.json}
	"$VERIFY_BIN" plugin test \
		--source "$plugin_dir" \
		--os "$VERIFY_OS" \
		--architecture "$VERIFY_ARCH" \
		--kernel "$VERIFY_KERNEL" \
		>/dev/null
	checked=$((checked + 1))
done

if [ "$checked" -eq 0 ]; then
	echo "no plugin manifests found under $PLUGIN_SOURCE_DIR" >&2
	exit 1
fi

echo "verified $checked plugin manifest(s) with the Go conformance runtime"
