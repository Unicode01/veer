#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

build_if_present() {
	dir=$1
	if [ -x "$dir/build.sh" ]; then
		(cd "$dir" && ./build.sh)
	elif [ -f "$dir/build.sh" ]; then
		(cd "$dir" && sh ./build.sh)
	fi
}

build_if_present "$ROOT_DIR/plugins/packet_observer"
build_if_present "$ROOT_DIR/plugins/pppoe_client"
