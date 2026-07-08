#!/usr/bin/env sh

forward_plugin_test_mem_kb() {
	if [ ! -r /proc/meminfo ]; then
		echo 0
		return
	fi
	awk '/^MemTotal:/ { print $2; found=1; exit } END { if (!found) print 0 }' /proc/meminfo 2>/dev/null || echo 0
}

forward_plugin_test_low_memory_enabled() {
	mode=${FORWARD_PLUGIN_TEST_LOW_MEMORY:-auto}
	case "$mode" in
		1|true|TRUE|yes|YES|on|ON)
			return 0
			;;
		0|false|FALSE|no|NO|off|OFF)
			return 1
			;;
		auto|'')
			mem_kb=$(forward_plugin_test_mem_kb)
			threshold_kb=${FORWARD_PLUGIN_TEST_LOW_MEMORY_THRESHOLD_KB:-2097152}
			case "$mem_kb:$threshold_kb" in
				*[!0-9:]*|0:*)
					return 1
					;;
			esac
			[ "$mem_kb" -gt 0 ] && [ "$mem_kb" -lt "$threshold_kb" ]
			return
			;;
		*)
			echo "FORWARD_PLUGIN_TEST_LOW_MEMORY must be auto, 1, or 0" >&2
			exit 1
			;;
	esac
}

forward_configure_plugin_test_go_env() {
	if [ "${FORWARD_PLUGIN_TEST_GO_ENV_CONFIGURED:-0}" = "1" ]; then
		return
	fi

	if ! forward_plugin_test_low_memory_enabled; then
		return
	fi

	: "${GOMAXPROCS:=2}"
	case " ${GOFLAGS:-} " in
		*" -p="*|*" -p "*)
			;;
		*)
			GOFLAGS="${GOFLAGS:+$GOFLAGS }-p=1"
			;;
	esac

	export GOMAXPROCS
	export GOFLAGS
	FORWARD_PLUGIN_TEST_GO_ENV_CONFIGURED=1
	export FORWARD_PLUGIN_TEST_GO_ENV_CONFIGURED
	echo "plugin test low-memory mode: GOMAXPROCS=$GOMAXPROCS GOFLAGS=${GOFLAGS:-}"
}
