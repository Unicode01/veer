#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/lib-plugin-test-env.sh"

if [ "$(id -u)" != "0" ]; then
	echo "plugin dataplane performance tests require root" >&2
	exit 1
fi

case "${FORWARD_PLUGIN_PERF_COUNTS:-0 1 4}" in
	*"	"*)
		echo "FORWARD_PLUGIN_PERF_COUNTS must be a space-separated list, not tab-separated" >&2
		exit 1
		;;
esac

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

sh "$ROOT_DIR/scripts/build-all-ebpf.sh"

WORK_DIR=
if [ -z "${FORWARD_PERF_BINARY:-}" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/forward-plugin-perf.XXXXXX")
	trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

	go build -o "$WORK_DIR/forward" .
	FORWARD_PERF_BINARY="$WORK_DIR/forward"
else
	if [ ! -x "$FORWARD_PERF_BINARY" ]; then
		echo "FORWARD_PERF_BINARY must point to an executable forward binary" >&2
		exit 1
	fi
fi

: "${FORWARD_PLUGIN_PERF_COUNTS:=0 1 4}"
: "${FORWARD_PERF_MODES:=tc}"
: "${FORWARD_PERF_CONNECTIONS:=128}"
: "${FORWARD_PERF_CONCURRENCY:=16}"
: "${FORWARD_PERF_BYTES_PER_CONN:=1048576}"
: "${FORWARD_PERF_IO_CHUNK_BYTES:=16384}"
: "${FORWARD_PERF_WARMUP_CONNECTIONS:=8}"
: "${FORWARD_PERF_WARMUP_BYTES_PER_CONN:=65536}"

export FORWARD_PERF_MODES
export FORWARD_PERF_CONNECTIONS
export FORWARD_PERF_CONCURRENCY
export FORWARD_PERF_BYTES_PER_CONN
export FORWARD_PERF_IO_CHUNK_BYTES
export FORWARD_PERF_WARMUP_CONNECTIONS
export FORWARD_PERF_WARMUP_BYTES_PER_CONN
export FORWARD_PERF_BINARY

for count in $FORWARD_PLUGIN_PERF_COUNTS; do
	case "$count" in
		''|*[!0-9]*)
			echo "invalid plugin perf count: $count" >&2
			exit 1
			;;
	esac

	if [ "$count" = "0" ]; then
		echo "running TC baseline performance smoke without plugin pipeline"
		FORWARD_RUN_PERF_TEST=1 \
			FORWARD_PERF_PLUGIN_PIPELINE=0 \
			run_internal_app_test TestDataplanePerfMatrix 1
		continue
	fi

	echo "running TC plugin pipeline performance smoke with $count plugin(s)"
	FORWARD_RUN_PERF_TEST=1 \
		FORWARD_PERF_PLUGIN_PIPELINE=1 \
		FORWARD_PERF_PLUGIN_PIPELINE_COUNT="$count" \
		run_internal_app_test TestDataplanePerfMatrix 1
done
