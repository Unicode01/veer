#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
DRY_RUN=0
INCLUDE_DIST=0

usage() {
	printf 'usage: %s [--dry-run] [--include-dist]\n' "$0"
}

fail() {
	printf 'artifact cleanup refused: %s\n' "$*" >&2
	exit 1
}

for arg in "$@"; do
	case "$arg" in
		--dry-run) DRY_RUN=1 ;;
		--include-dist) INCLUDE_DIST=1 ;;
		-h|--help) usage; exit 0 ;;
		*) usage >&2; fail "unknown option: $arg" ;;
	esac
done

[ -e "$ROOT_DIR/.git" ] || fail "repository marker is missing: $ROOT_DIR/.git"

is_allowed_target() {
	case "$1" in
		"$ROOT_DIR/.tmp"|"$ROOT_DIR/test-results"|"$ROOT_DIR/playwright-report"|"$ROOT_DIR/coverage.out") return 0 ;;
		"$ROOT_DIR"/.veer-plugin-release.*) return 0 ;;
		"$ROOT_DIR/dist"/.veer-plugin-*) return 0 ;;
		"$ROOT_DIR/dist") [ "$INCLUDE_DIST" -eq 1 ] && return 0 ;;
	esac
	return 1
}

remove_target() {
	target=$1
	if [ ! -e "$target" ] && [ ! -L "$target" ]; then
		return
	fi
	is_allowed_target "$target" || fail "target is outside the owned artifact set: $target"
	if [ "$DRY_RUN" -eq 1 ]; then
		printf 'would remove %s\n' "$target"
		return
	fi
	printf 'removing %s\n' "$target"
	rm -rf -- "$target"
}

printf 'repository: %s\n' "$ROOT_DIR"
remove_target "$ROOT_DIR/.tmp"
remove_target "$ROOT_DIR/test-results"
remove_target "$ROOT_DIR/playwright-report"
remove_target "$ROOT_DIR/coverage.out"

for target in "$ROOT_DIR"/.veer-plugin-release.* "$ROOT_DIR/dist"/.veer-plugin-*; do
	remove_target "$target"
done

if [ "$INCLUDE_DIST" -eq 1 ]; then
	remove_target "$ROOT_DIR/dist"
fi
