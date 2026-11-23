#!/usr/bin/env bash
# Builds a native plugin's library for the targets its plugin.json lists in
# control.library, into the paths it names there.
#
# Usage: build-plugin.sh [plugin dir] [triple ...]
#   triple: x86_64-linux-gnu x86_64-linux-musl aarch64-linux-gnu aarch64-linux-musl
#   default: every target in control.library
#
# glibc builds target glibc 2.17 and musl builds link musl dynamically (the
# worker that loads the library is dynamically linked); both need
# cargo-zigbuild (pip install ziglang cargo-zigbuild). Without it only the
# host target builds, with cargo. VEER_NATIVE_PROFILE=debug skips
# optimizations.
set -euo pipefail

PLUGIN_DIR="$(cd "${1:-.}" && pwd)"
shift || true
PROFILE="${VEER_NATIVE_PROFILE:-release}"
[ -f "$PLUGIN_DIR/plugin.json" ] || { echo "plugin.json was not found in $PLUGIN_DIR" >&2; exit 1; }
[ -f "$PLUGIN_DIR/Cargo.toml" ] || { echo "Cargo.toml was not found in $PLUGIN_DIR" >&2; exit 1; }

PYTHON_BIN=
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
        PYTHON_BIN=$candidate
        break
    fi
done
[ -n "$PYTHON_BIN" ] || { echo "python3 or python is required" >&2; exit 1; }

# "<triple> <path>" for each control.library target.
targets="$("$PYTHON_BIN" - "$PLUGIN_DIR/plugin.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    manifest = json.load(stream)
library = (manifest.get("control") or {}).get("library") or {}
for triple in sorted(library):
    print(triple, str((library[triple] or {}).get("path") or ""))
PY
)"
[ -n "$targets" ] || { echo "plugin.json declares no control.library" >&2; exit 1; }
library_name="$(sed -n '/^\[lib\]/,/^\[/s/^name *= *"\(.*\)"/\1/p' "$PLUGIN_DIR/Cargo.toml" | head -n1)"
[ -n "$library_name" ] || { echo "Cargo.toml needs a [lib] name" >&2; exit 1; }

rust_target() {
    case "$1" in
        x86_64-linux-gnu) echo x86_64-unknown-linux-gnu ;;
        x86_64-linux-musl) echo x86_64-unknown-linux-musl ;;
        aarch64-linux-gnu) echo aarch64-unknown-linux-gnu ;;
        aarch64-linux-musl) echo aarch64-unknown-linux-musl ;;
        *) echo "unknown target $1" >&2; exit 2 ;;
    esac
}

profile_flag=(--release)
profile_dir=release
if [ "$PROFILE" = debug ]; then
    profile_flag=()
    profile_dir=debug
fi
target_dir="${CARGO_TARGET_DIR:-$PLUGIN_DIR/target}"

while read -r triple path; do
    # python on Windows ends its lines with CRLF.
    path="$(printf '%s' "$path" | tr -d '\r')"
    if [ "$#" -gt 0 ] && ! printf '%s\n' "$@" | grep -qx "$triple"; then
        continue
    fi
    [ -n "$path" ] || { echo "control.library.$triple has no path" >&2; exit 1; }
    target="$(rust_target "$triple")"
    rustflags=""
    case "$triple" in
        *-musl) rustflags="-C target-feature=-crt-static" ;;
    esac
    echo "==> building $library_name for $triple"
    if command -v cargo-zigbuild >/dev/null 2>&1; then
        zig_target="$target"
        case "$triple" in
            *-gnu) zig_target="$target.2.17" ;;
        esac
        RUSTFLAGS="$rustflags ${RUSTFLAGS:-}" cargo zigbuild "${profile_flag[@]}" --manifest-path "$PLUGIN_DIR/Cargo.toml" --target "$zig_target"
    else
        RUSTFLAGS="$rustflags ${RUSTFLAGS:-}" cargo build "${profile_flag[@]}" --manifest-path "$PLUGIN_DIR/Cargo.toml" --target "$target"
    fi
    mkdir -p "$PLUGIN_DIR/$(dirname "$path")"
    install -m 0644 "$target_dir/$target/$profile_dir/lib$library_name.so" "$PLUGIN_DIR/$path"
    echo "    $path"
done <<<"$targets"
