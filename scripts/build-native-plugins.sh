#!/usr/bin/env bash
# Builds the native plugin worker and every native plugin for one or more
# targets, and puts the results where the host looks for them:
#
#   plugins/<id>/lib/<triple>/lib<id>.so
#   internal/app/pluginworker/<triple>/veer-plugin-worker   (embedded by go build)
#
# Usage: scripts/build-native-plugins.sh [triple ...]
#   triple: x86_64-linux-gnu x86_64-linux-musl aarch64-linux-gnu aarch64-linux-musl
#   default: x86_64-linux-gnu
#
# glibc builds target glibc 2.17 through cargo-zigbuild when it is
# available, so they load on any glibc distribution in use; otherwise the
# host toolchain is used. musl builds need cargo-zigbuild or a musl cross
# toolchain.
#
# VEER_NATIVE_PROFILE=debug builds without optimizations.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/rust-env.sh"
PROFILE="${VEER_NATIVE_PROFILE:-release}"
TRIPLES=("$@")
if [ "${#TRIPLES[@]}" -eq 0 ]; then
    TRIPLES=(x86_64-linux-gnu)
fi

# cargo-zigbuild finds zig on PATH, in $ZIG or as the ziglang Python
# package (pip install ziglang cargo-zigbuild).
have_zigbuild=0
if command -v cargo-zigbuild >/dev/null 2>&1; then
    have_zigbuild=1
fi

# The dynamic loader each worker must name: a static worker cannot load
# plugin libraries (musl's static dlopen always fails).
worker_interpreter() {
    case "$1" in
        x86_64-linux-gnu) echo /lib64/ld-linux-x86-64.so.2 ;;
        x86_64-linux-musl) echo /lib/ld-musl-x86_64.so.1 ;;
        aarch64-linux-gnu) echo /lib/ld-linux-aarch64.so.1 ;;
        aarch64-linux-musl) echo /lib/ld-musl-aarch64.so.1 ;;
    esac
}

rust_target() {
    case "$1" in
        x86_64-linux-gnu) echo x86_64-unknown-linux-gnu ;;
        x86_64-linux-musl) echo x86_64-unknown-linux-musl ;;
        aarch64-linux-gnu) echo aarch64-unknown-linux-gnu ;;
        aarch64-linux-musl) echo aarch64-unknown-linux-musl ;;
        *) echo "unknown target $1" >&2; exit 2 ;;
    esac
}

# Native plugins are the plugin directories with a Cargo.toml; the library
# name is the plugin id.
plugins=()
for manifest in "$ROOT"/plugins/*/Cargo.toml; do
    [ -f "$manifest" ] || continue
    plugins+=("$(basename "$(dirname "$manifest")")")
done

profile_flag=(--release)
profile_dir=release
if [ "$PROFILE" = debug ]; then
    profile_flag=()
    profile_dir=debug
fi

packages=(-p veer-plugin-worker)
for id in "${plugins[@]}"; do
    packages+=(-p "$(sed -n 's/^name = "\(.*\)"/\1/p' "$ROOT/plugins/$id/Cargo.toml" | head -n1)")
done

cd "$ROOT"
for triple in "${TRIPLES[@]}"; do
    target="$(rust_target "$triple")"
    rustflags=""
    case "$triple" in
        *-musl)
            # Plugins are shared libraries loaded by a dynamically linked
            # worker: link musl dynamically.
            rustflags="-C target-feature=-crt-static"
            ;;
    esac
    echo "==> building native plugins for $triple"
    if [ "$have_zigbuild" = 1 ]; then
        zig_target="$target"
        zig_flags=""
        case "$triple" in
            *-gnu) zig_target="$target.2.17" ;;
            # zig links musl executables statically unless told otherwise,
            # even without crt-static.
            *-musl) zig_flags="-C link-arg=-dynamic" ;;
        esac
        RUSTFLAGS="$rustflags $zig_flags ${RUSTFLAGS:-}" cargo zigbuild "${profile_flag[@]}" --target "$zig_target" "${packages[@]}"
    else
        RUSTFLAGS="$rustflags ${RUSTFLAGS:-}" cargo build "${profile_flag[@]}" --target "$target" "${packages[@]}"
    fi
    out="$ROOT/target/$target/$profile_dir"
    interpreter="$(worker_interpreter "$triple")"
    if ! LC_ALL=C grep -q -a -F "$interpreter" "$out/veer-plugin-worker"; then
        echo "veer-plugin-worker for $triple is not dynamically linked against $interpreter; it could not load plugins" >&2
        exit 1
    fi
    for id in "${plugins[@]}"; do
        mkdir -p "$ROOT/plugins/$id/lib/$triple"
        install -m 0644 "$out/lib$id.so" "$ROOT/plugins/$id/lib/$triple/lib$id.so"
    done
    mkdir -p "$ROOT/internal/app/pluginworker/$triple"
    install -m 0755 "$out/veer-plugin-worker" "$ROOT/internal/app/pluginworker/$triple/veer-plugin-worker"
    echo "    worker: internal/app/pluginworker/$triple/veer-plugin-worker"
    for id in "${plugins[@]}"; do
        echo "    plugin: plugins/$id/lib/$triple/lib$id.so"
    done
done
