#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/lib-plugin-test-env.sh"

if [ "$(id -u)" != "0" ]; then
	echo "plugin stability tests require root" >&2
	exit 1
fi

forward_configure_plugin_test_go_env

cd "$ROOT_DIR"

run_internal_app_test() {
	test_name=$1
	test_count=$2

	if [ -n "${FORWARD_APP_TEST_BINARY:-}" ]; then
		if [ ! -x "$FORWARD_APP_TEST_BINARY" ]; then
			echo "FORWARD_APP_TEST_BINARY must point to an executable go test -c binary" >&2
			exit 1
		fi
		"$FORWARD_APP_TEST_BINARY" -test.run "$test_name" -test.count="$test_count" -test.v
		return
	fi

	go test ./internal/app -run "$test_name" -count="$test_count" -v
}

case "${FORWARD_PLUGIN_STABILITY_REPEAT:-1}" in
	''|*[!0-9]*|0)
		echo "FORWARD_PLUGIN_STABILITY_REPEAT must be a positive integer" >&2
		exit 1
		;;
esac
: "${FORWARD_PLUGIN_STABILITY_REPEAT:=1}"

WORK_DIR=
if [ -z "${FORWARD_PERF_BINARY:-}" ]; then
	sh "$ROOT_DIR/scripts/build-all-ebpf.sh"
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/forward-plugin-stability.XXXXXX")
	trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

	go build -o "$WORK_DIR/forward" .
	FORWARD_PERF_BINARY="$WORK_DIR/forward"
else
	if [ ! -x "$FORWARD_PERF_BINARY" ]; then
		echo "FORWARD_PERF_BINARY must point to an executable forward binary" >&2
		exit 1
	fi
fi

: "${FORWARD_PLUGIN_STABILITY_SECONDS:=20}"
: "${FORWARD_PLUGIN_STABILITY_LONG_CONNECTIONS:=8}"
: "${FORWARD_PLUGIN_STABILITY_LONG_ACTIVE:=4}"
: "${FORWARD_PLUGIN_STABILITY_NEW_CONNECTIONS:=8}"
: "${FORWARD_PLUGIN_STABILITY_NEW_CONCURRENCY:=2}"
: "${FORWARD_PLUGIN_STABILITY_NEW_INTERVAL_MS:=1000}"
: "${FORWARD_PERF_PLUGIN_PIPELINE:=1}"
: "${FORWARD_PERF_PLUGIN_PIPELINE_COUNT:=1}"

export FORWARD_PERF_BINARY
export FORWARD_PLUGIN_STABILITY_SECONDS
export FORWARD_PLUGIN_STABILITY_LONG_CONNECTIONS
export FORWARD_PLUGIN_STABILITY_LONG_ACTIVE
export FORWARD_PLUGIN_STABILITY_NEW_CONNECTIONS
export FORWARD_PLUGIN_STABILITY_NEW_CONCURRENCY
export FORWARD_PLUGIN_STABILITY_NEW_INTERVAL_MS
export FORWARD_PERF_PLUGIN_PIPELINE
export FORWARD_PERF_PLUGIN_PIPELINE_COUNT

FORWARD_RUN_PLUGIN_STABILITY_TEST=1 \
	run_internal_app_test TestDataplanePluginPipelineStability "$FORWARD_PLUGIN_STABILITY_REPEAT"
