#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/lib-plugin-test-env.sh"

if [ "$(id -u)" != "0" ]; then
	echo "plugin example integration tests require root" >&2
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

case "${FORWARD_PLUGIN_EXAMPLE_REPEAT:-1}" in
	''|*[!0-9]*|0)
		echo "FORWARD_PLUGIN_EXAMPLE_REPEAT must be a positive integer" >&2
		exit 1
		;;
esac
: "${FORWARD_PLUGIN_EXAMPLE_REPEAT:=1}"

: "${FORWARD_PLUGIN_PIPELINE_REPEAT:=1}"
case "$FORWARD_PLUGIN_PIPELINE_REPEAT" in
	''|*[!0-9]*|0)
		echo "FORWARD_PLUGIN_PIPELINE_REPEAT must be a positive integer" >&2
		exit 1
		;;
esac

FORWARD_RUN_PLUGIN_EXAMPLE_TEST=1 \
	run_internal_app_test TestPluginExample "$FORWARD_PLUGIN_EXAMPLE_REPEAT"

if [ "${FORWARD_SKIP_PLUGIN_DATAPLANE_ATTACH_TEST:-0}" = "1" ]; then
	echo "skip external TC plugin attach test because FORWARD_SKIP_PLUGIN_DATAPLANE_ATTACH_TEST=1"
else
	FORWARD_RUN_PLUGIN_DATAPLANE_TEST=1 \
		run_internal_app_test TestPluginDataplaneRuntimeAttachesTCObservePlugin 1
fi

if [ "${FORWARD_SKIP_PLUGIN_PIPELINE_TEST:-0}" = "1" ]; then
	echo "skip TC plugin pipeline lifecycle tests because FORWARD_SKIP_PLUGIN_PIPELINE_TEST=1"
else
	FORWARD_RUN_PLUGIN_PIPELINE_TEST=1 \
		run_internal_app_test TestKernelPluginPipelineRuntime "$FORWARD_PLUGIN_PIPELINE_REPEAT"
fi

if [ "${FORWARD_SKIP_PLUGIN_EGRESS_NAT_TEST:-0}" = "1" ]; then
	echo "skip plugin-generated Egress NAT traffic tests because FORWARD_SKIP_PLUGIN_EGRESS_NAT_TEST=1"
	exit 0
fi

sh "$ROOT_DIR/scripts/build-all-ebpf.sh"

FORWARD_RUN_EGRESS_NAT_TEST=1 \
	run_internal_app_test 'TestPluginLANCore(Generated|ResolvesWANCore)EgressNATTCIntegration' "$FORWARD_PLUGIN_EXAMPLE_REPEAT"
