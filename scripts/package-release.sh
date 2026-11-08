#!/usr/bin/env sh
# Packages release.sh output into the assets bootstrap.sh installs:
#   dist/release/veer-linux-<arch>.tar.gz   binary, deploy.sh, config template, plugins
#   dist/release/veer-plugin-sdk.tar.gz
#   dist/release/sha256sums.txt
# Each archive holds one veer-linux-<arch>/ directory that deploy.sh runs from.
# Usage: sh scripts/package-release.sh <version> [arch...]
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=${1:-}
case "$version" in
	v[0-9]*) ;;
	*) echo "usage: $0 <version, e.g. v1.2.3> [amd64|arm64...]" >&2; exit 2 ;;
esac
shift
[ "$#" -gt 0 ] || set -- amd64 arm64

for required in veer-plugins.tar.gz veer-plugin-sdk.tar.gz deploy.sh config.example.json LICENSE; do
	[ -f "$ROOT_DIR/$required" ] || { echo "missing $ROOT_DIR/$required; run release.sh first" >&2; exit 1; }
done

out="$ROOT_DIR/dist/release"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT INT TERM
rm -rf "$out"
mkdir -p "$out"
# Fixed timestamps and owners keep archives byte-identical across rebuilds.
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT_DIR" log -1 --format=%ct 2>/dev/null || date +%s)}

for arch do
	case "$arch" in
		amd64|arm64) ;;
		*) echo "unsupported architecture: $arch" >&2; exit 1 ;;
	esac
	name="veer-linux-$arch"
	[ -f "$ROOT_DIR/$name" ] || { echo "missing $ROOT_DIR/$name; run release.sh $arch first" >&2; exit 1; }
	dir="$stage/$name"
	mkdir -p "$dir"
	install -m 0755 "$ROOT_DIR/$name" "$dir/$name"
	install -m 0755 "$ROOT_DIR/deploy.sh" "$dir/deploy.sh"
	install -m 0644 "$ROOT_DIR/config.example.json" "$ROOT_DIR/LICENSE" "$ROOT_DIR/veer-plugins.tar.gz" "$dir/"
	printf '%s\n' "$version" >"$dir/VERSION"
	chmod 0644 "$dir/VERSION"
	tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" -cf - "$name" |
		gzip -n -9 >"$out/$name.tar.gz"
done
install -m 0644 "$ROOT_DIR/veer-plugin-sdk.tar.gz" "$out/veer-plugin-sdk.tar.gz"
(cd "$out" && sha256sum -- *.tar.gz >sha256sums.txt)
cat "$out/sha256sums.txt"
