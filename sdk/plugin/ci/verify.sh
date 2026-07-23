#!/usr/bin/env sh
set -eu

PLUGIN_DIR=${1:-.}
VEER_BIN=${VEER_BIN:-veer}
TARGET_KERNEL=${VEER_PLUGIN_TARGET_KERNEL:-6.6.0}
TARGET_ARCHITECTURES=${VEER_PLUGIN_TARGET_ARCHITECTURES:-"amd64 arm64"}
BUILD_ARCHITECTURES=${VEER_PLUGIN_BUILD_ARCHITECTURES:-all}

find_python() {
	if [ -n "${PYTHON:-}" ]; then
		"$PYTHON" -c 'import sys' >/dev/null 2>&1 || {
			echo "configured PYTHON cannot execute Python code: $PYTHON" >&2
			exit 1
		}
		printf '%s\n' "$PYTHON"
		return
	fi
	for candidate in python3 python; do
		if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	echo "python3 or python is required to verify a plugin" >&2
	exit 1
}

PYTHON_BIN=$(find_python)

set -- $TARGET_ARCHITECTURES
if [ "$#" -eq 0 ]; then
	echo "VEER_PLUGIN_TARGET_ARCHITECTURES cannot be empty" >&2
	exit 1
fi
LINT_ARCHITECTURE=$1

if [ ! -f "$PLUGIN_DIR/plugin.json" ]; then
	echo "plugin.json was not found in $PLUGIN_DIR" >&2
	exit 1
fi

kind=$("$PYTHON_BIN" - "$PLUGIN_DIR/plugin.json" <<'PY'
import json
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("r", encoding="utf-8") as stream:
    value = json.load(stream)
print(str(value.get("kind") or "control").strip().lower())
PY
)

case "$kind" in
	pipeline)
		if find "$PLUGIN_DIR" -type f -name '*.bpf.c' -print -quit | grep -q .; then
			"$VEER_BIN" plugin build --source "$PLUGIN_DIR" --architectures "$BUILD_ARCHITECTURES"
		fi
		;;
	control)
		;;
	*)
		echo "unsupported plugin kind: $kind" >&2
		exit 1
		;;
esac

"$VEER_BIN" plugin lint --source "$PLUGIN_DIR" --os linux --architecture "$LINT_ARCHITECTURE" --kernel "$TARGET_KERNEL"

for architecture in $TARGET_ARCHITECTURES; do
	"$VEER_BIN" plugin test --source "$PLUGIN_DIR" --os linux --architecture "$architecture" --kernel "$TARGET_KERNEL"
done

output_dir=$(mktemp -d)
trap 'rm -rf -- "$output_dir"' EXIT INT TERM
"$VEER_BIN" plugin pack --source "$PLUGIN_DIR" --output "$output_dir/plugin.tar.gz"

echo "plugin verification passed"
