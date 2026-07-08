#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/lib-plugin-test-env.sh"

if [ "$(id -u)" != "0" ]; then
	echo "plugin production acceptance tests require root" >&2
	exit 1
fi

: "${FORWARD_PLUGIN_PRODUCTION_REPEAT:=20}"
: "${FORWARD_PLUGIN_EXAMPLE_REPEAT:=$FORWARD_PLUGIN_PRODUCTION_REPEAT}"
: "${FORWARD_PLUGIN_PIPELINE_REPEAT:=$FORWARD_PLUGIN_PRODUCTION_REPEAT}"

export FORWARD_PLUGIN_EXAMPLE_REPEAT
export FORWARD_PLUGIN_PIPELINE_REPEAT

cd "$ROOT_DIR"

sh "$ROOT_DIR/scripts/test-plugin-scripts.sh"

forward_configure_plugin_test_go_env

sh "$ROOT_DIR/scripts/test-plugin-examples-linux.sh"

if [ "${FORWARD_RUN_PLUGIN_PPPOE_TEST:-0}" = "1" ]; then
	sh "$ROOT_DIR/scripts/test-plugin-pppoe-linux.sh"
else
	echo "skip PPPoE plugin integration tests because FORWARD_RUN_PLUGIN_PPPOE_TEST is not 1"
fi

if [ "${FORWARD_SKIP_PLUGIN_STABILITY_TEST:-0}" = "1" ]; then
	echo "skip plugin long-flow stability test because FORWARD_SKIP_PLUGIN_STABILITY_TEST=1"
else
	sh "$ROOT_DIR/scripts/test-plugin-stability-linux.sh"
fi

if [ "${FORWARD_SKIP_PLUGIN_PERF_TEST:-0}" = "1" ]; then
	echo "skip plugin performance smoke because FORWARD_SKIP_PLUGIN_PERF_TEST=1"
	exit 0
fi

sh "$ROOT_DIR/scripts/test-plugin-perf-linux.sh"
