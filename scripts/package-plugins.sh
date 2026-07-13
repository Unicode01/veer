#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PLUGIN_SOURCE_DIR="$ROOT_DIR/plugins"
OUT_DIR=${VEER_PLUGIN_PACKAGE_DIR:-"$ROOT_DIR/dist/plugins"}
PACKAGE_STABILITY=${VEER_PLUGIN_PACKAGE_STABILITY:-"stable"}
TMP_DIR=
PLUGIN_LIST=

find_python() {
	if [ -n "${PYTHON:-}" ]; then
		if "$PYTHON" -c 'import sys' >/dev/null 2>&1; then
			printf '%s\n' "$PYTHON"
			return
		fi
		echo "configured PYTHON cannot execute Python code: $PYTHON" >&2
		exit 1
	fi
	for candidate in python3 python python.exe py py.exe; do
		if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	echo "python3 or python is required to inject plugin control sha256 values" >&2
	exit 1
}

write_plugin_list() {
	out_file=$1
	"$PYTHON_BIN" - "$PLUGIN_SOURCE_DIR" "$PACKAGE_STABILITY" >"$out_file" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
selector = str(sys.argv[2] or "").strip().lower()
if not selector:
    raise SystemExit("VEER_PLUGIN_PACKAGE_STABILITY cannot be empty")
if selector == "all":
    allowed = None
else:
    allowed = {item.strip() for item in selector.replace(",", " ").split() if item.strip()}
    valid = {"lab", "preview", "stable", "deprecated"}
    unknown = sorted(allowed - valid)
    if unknown:
        raise SystemExit("unknown plugin stability in VEER_PLUGIN_PACKAGE_STABILITY: " + ", ".join(unknown))

for manifest_path in sorted(root.glob("*/plugin.json")):
    with manifest_path.open("r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    stability = str(manifest.get("stability") or "lab").strip().lower() or "lab"
    if allowed is not None and stability not in allowed:
        continue
    print(manifest_path.parent.name)
PY
	if [ ! -s "$out_file" ]; then
		echo "no plugins match VEER_PLUGIN_PACKAGE_STABILITY=$PACKAGE_STABILITY" >&2
		exit 1
	fi
}

case "$OUT_DIR" in
	""|"/"|"$ROOT_DIR"|"$ROOT_DIR/"|"$PLUGIN_SOURCE_DIR"|"$PLUGIN_SOURCE_DIR/")
		echo "refusing unsafe output directory: $OUT_DIR" >&2
		exit 1
		;;
esac

mkdir -p "$(dirname "$OUT_DIR")"

if [ "${VEER_PLUGIN_PACKAGE_SKIP_BUILD:-0}" != "1" ]; then
	PYTHON_BIN=$(find_python)
	PLUGIN_LIST="${OUT_DIR}.plugins.$$"
	rm -f "$PLUGIN_LIST"
	trap 'rm -rf "$TMP_DIR" "$PLUGIN_LIST"' EXIT INT TERM
	write_plugin_list "$PLUGIN_LIST"
	while IFS= read -r plugin_name; do
		[ -n "$plugin_name" ] || continue
		plugin_dir="$PLUGIN_SOURCE_DIR/$plugin_name"
		if [ -x "$plugin_dir/build.sh" ]; then
			(cd "$plugin_dir" && ./build.sh)
		elif [ -f "$plugin_dir/build.sh" ]; then
			(cd "$plugin_dir" && sh ./build.sh)
		fi
	done <"$PLUGIN_LIST"
else
	PYTHON_BIN=$(find_python)
fi

TMP_DIR="${OUT_DIR}.tmp.$$"
rm -rf "$TMP_DIR"
PLUGIN_LIST="${OUT_DIR}.plugins.$$"
rm -f "$PLUGIN_LIST"
trap 'rm -rf "$TMP_DIR" "$PLUGIN_LIST"' EXIT INT TERM
mkdir -p "$TMP_DIR"

write_plugin_list "$PLUGIN_LIST"

while IFS= read -r name; do
	[ -n "$name" ] || continue
	plugin_dir="$PLUGIN_SOURCE_DIR/$name"
	mkdir -p "$TMP_DIR/$name"
	"$PYTHON_BIN" - "$plugin_dir" "$TMP_DIR/$name" <<'PY'
import pathlib
import shutil
import sys

src = pathlib.Path(sys.argv[1]).resolve()
dst = pathlib.Path(sys.argv[2]).resolve()

ignored_dirs = {"__pycache__", ".pytest_cache", ".tmp", "node_modules"}

def ignore_runtime_junk(_dir, names):
    ignored = set()
    for name in names:
        if name in ignored_dirs:
            ignored.add(name)
            continue
        if name.startswith("test-"):
            ignored.add(name)
            continue
        if name.endswith((".test", ".log", ".tmp", ".bak", ".orig")):
            ignored.add(name)
    return ignored

if dst.exists():
    shutil.rmtree(dst)
shutil.copytree(src, dst, ignore=ignore_runtime_junk, symlinks=True)
PY
done <"$PLUGIN_LIST"

if [ -d "$PLUGIN_SOURCE_DIR/include" ]; then
	"$PYTHON_BIN" - "$PLUGIN_SOURCE_DIR/include" "$TMP_DIR/include" <<'PY'
import pathlib
import shutil
import sys

src = pathlib.Path(sys.argv[1]).resolve()
dst = pathlib.Path(sys.argv[2]).resolve()
if dst.exists():
    shutil.rmtree(dst)
shutil.copytree(src, dst, symlinks=True)
PY
fi

"$PYTHON_BIN" - "$TMP_DIR" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()

for manifest_path in sorted(root.glob("*/plugin.json")):
    plugin_dir = manifest_path.parent.resolve()
    with manifest_path.open("r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    changed = False
    control = manifest.get("control") if isinstance(manifest.get("control"), dict) else None
    if control is not None:
        main_path = str(control.get("main") or "").strip()
        if main_path:
            control_file = (plugin_dir / main_path).resolve()
            try:
                control_file.relative_to(plugin_dir)
            except ValueError:
                raise SystemExit(f"{manifest_path}: control.main escapes plugin directory: {main_path}")
            if not control_file.is_file():
                raise SystemExit(f"{manifest_path}: control.main is missing: {main_path}")
            digest = hashlib.sha256(control_file.read_bytes()).hexdigest()
            if control.get("sha256") != digest:
                control["sha256"] = digest
                changed = True
    if changed:
        with manifest_path.open("w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
PY

VEER_PLUGIN_SOURCE_DIR="$TMP_DIR" sh "$ROOT_DIR/scripts/verify-plugin-manifests.sh" >/dev/null

rm -rf "$OUT_DIR"
mv "$TMP_DIR" "$OUT_DIR"
trap - EXIT INT TERM
rm -f "$PLUGIN_LIST"

echo "packaged plugins into $OUT_DIR (stability=$PACKAGE_STABILITY)"
