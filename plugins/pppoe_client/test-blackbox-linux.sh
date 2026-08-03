#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
PLUGIN_DIR="$ROOT_DIR/plugins/pppoe_client"

if [ "$(id -u)" != "0" ]; then
	echo "PPPoE blackbox test requires root" >&2
	exit 1
fi

: "${VEER_PPPOE_BLACKBOX_SECONDS:=8}"
: "${VEER_PPPOE_BLACKBOX_PARALLEL:=1}"
: "${VEER_PPPOE_BLACKBOX_PORT:=0}"
: "${VEER_PPPOE_BLACKBOX_TOKEN:=pppoe-blackbox-token}"
: "${VEER_PPPOE_BLACKBOX_CAPTURE:=0}"
: "${VEER_PPPOE_BLACKBOX_SETTLE_SECONDS:=0}"
: "${VEER_PPPOE_BLACKBOX_RUN_IPERF:=1}"
: "${VEER_PPPOE_BLACKBOX_TEST_IPV6:=0}"
: "${VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE:=0}"
: "${VEER_PPPOE_BLACKBOX_TEST_AUTO_REDIAL:=0}"
: "${VEER_PPPOE_BLACKBOX_CAPTURE_SNAPLEN:=0}"
: "${VEER_PPPOE_BLACKBOX_SYSTEMD:=auto}"
: "${VEER_PPPOE_BLACKBOX_DECAP_MODE:=auto}"

missing=
for tool in ip tc clang pppd pppoe-server curl sed grep timeout ss ethtool pkill; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		missing="${missing:+$missing }$tool"
	fi
done
if [ "$VEER_PPPOE_BLACKBOX_RUN_IPERF" = "1" ] && ! command -v iperf3 >/dev/null 2>&1; then
	missing="${missing:+$missing }iperf3"
fi
if [ "$VEER_PPPOE_BLACKBOX_CAPTURE" = "1" ] && ! command -v tcpdump >/dev/null 2>&1; then
	missing="${missing:+$missing }tcpdump"
fi
if [ -n "$missing" ]; then
	echo "PPPoE blackbox test requires: $missing" >&2
	exit 1
fi

case "$VEER_PPPOE_BLACKBOX_SECONDS" in
	''|*[!0-9]*|0)
		echo "VEER_PPPOE_BLACKBOX_SECONDS must be a positive integer" >&2
		exit 1
		;;
esac
case "$VEER_PPPOE_BLACKBOX_PARALLEL" in
	''|*[!0-9]*|0)
		echo "VEER_PPPOE_BLACKBOX_PARALLEL must be a positive integer" >&2
		exit 1
		;;
esac
case "$VEER_PPPOE_BLACKBOX_RUN_IPERF" in
	0|1) ;;
	*)
		echo "VEER_PPPOE_BLACKBOX_RUN_IPERF must be 0 or 1" >&2
		exit 1
		;;
esac
case "$VEER_PPPOE_BLACKBOX_TEST_IPV6" in
	0|1) ;;
	*)
		echo "VEER_PPPOE_BLACKBOX_TEST_IPV6 must be 0 or 1" >&2
		exit 1
		;;
esac
case "$VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE" in
	0|1) ;;
	*)
		echo "VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE must be 0 or 1" >&2
		exit 1
		;;
esac
case "$VEER_PPPOE_BLACKBOX_TEST_AUTO_REDIAL" in
	0|1) ;;
	*)
		echo "VEER_PPPOE_BLACKBOX_TEST_AUTO_REDIAL must be 0 or 1" >&2
		exit 1
		;;
esac
if [ "$VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE" = "1" ] && [ "$VEER_PPPOE_BLACKBOX_RUN_IPERF" = "1" ]; then
	echo "timer-fence and iperf are separate tests; set VEER_PPPOE_BLACKBOX_RUN_IPERF=0" >&2
	exit 1
fi
if [ "$VEER_PPPOE_BLACKBOX_TEST_AUTO_REDIAL" = "1" ]; then
	if [ "$VEER_PPPOE_BLACKBOX_RUN_IPERF" = "1" ] || [ "$VEER_PPPOE_BLACKBOX_TEST_IPV6" = "1" ] || [ "$VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE" = "1" ]; then
		echo "auto-redial is a separate IPv4 test; disable iperf, IPv6, and timer-fence" >&2
		exit 1
	fi
fi
case "$VEER_PPPOE_BLACKBOX_CAPTURE_SNAPLEN" in
	''|*[!0-9]*)
		echo "VEER_PPPOE_BLACKBOX_CAPTURE_SNAPLEN must be a non-negative integer" >&2
		exit 1
		;;
esac
case "$VEER_PPPOE_BLACKBOX_SYSTEMD" in
	auto|0|1) ;;
	*)
		echo "VEER_PPPOE_BLACKBOX_SYSTEMD must be auto, 0, or 1" >&2
		exit 1
		;;
esac
case "$VEER_PPPOE_BLACKBOX_DECAP_MODE" in
	auto|manual) ;;
	*)
		echo "VEER_PPPOE_BLACKBOX_DECAP_MODE must be auto or manual" >&2
		exit 1
		;;
esac

if [ "$VEER_PPPOE_BLACKBOX_PORT" = "0" ]; then
	VEER_PPPOE_BLACKBOX_PORT=$((18080 + ($$ % 1000)))
fi

suffix=$$
server_ns="fwpppsrv$suffix"
wan_host="wanbb0$suffix"
wan_peer="wanbb1$suffix"
local_if="veerl${suffix}"
local_if=$(printf '%.15s' "$local_if")
pipeline_if="veerp${suffix}"
pipeline_if=$(printf '%.15s' "$pipeline_if")
lan_host="lanbb0${suffix}"
lan_host=$(printf '%.15s' "$lan_host")
lan_peer="lanbb1${suffix}"
lan_peer=$(printf '%.15s' "$lan_peer")
lan_bridge="brbb${suffix}"
lan_bridge=$(printf '%.15s' "$lan_bridge")
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/veer-pppoe-blackbox.XXXXXX")
veer_pid=
veer_unit=
pppoe_pid=
iperf_pid=
capture_pid=
capture_local_pid=
capture_pipeline_pid=
capture_server_pid=
capture_file=

cleanup() {
	set +e
	if [ -n "$iperf_pid" ]; then kill "$iperf_pid" 2>/dev/null || true; fi
	if [ -n "$capture_pid" ]; then kill "$capture_pid" 2>/dev/null || true; fi
	if [ -n "$capture_local_pid" ]; then kill "$capture_local_pid" 2>/dev/null || true; fi
	if [ -n "$capture_pipeline_pid" ]; then kill "$capture_pipeline_pid" 2>/dev/null || true; fi
	if [ -n "$capture_server_pid" ]; then kill "$capture_server_pid" 2>/dev/null || true; fi
	if [ -n "$veer_unit" ]; then
		systemctl stop "$veer_unit" >/dev/null 2>&1 || true
		systemctl reset-failed "$veer_unit" >/dev/null 2>&1 || true
		veer_pid=
	fi
	if [ -n "$veer_pid" ]; then kill "$veer_pid" 2>/dev/null || true; fi
	if [ -n "$pppoe_pid" ]; then kill "$pppoe_pid" 2>/dev/null || true; fi
	if [ -f "$work_dir/pppoe-server.pid" ]; then kill "$(cat "$work_dir/pppoe-server.pid")" 2>/dev/null || true; fi
	pkill -f "[p]ppoe-server .*${wan_peer}" 2>/dev/null || true
	ip netns pids "$server_ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
	ip netns del "$server_ns" 2>/dev/null || true
	ip link del "$local_if" 2>/dev/null || true
	ip link del "$pipeline_if" 2>/dev/null || true
	ip link del "$lan_bridge" 2>/dev/null || true
	ip link del "$lan_host" 2>/dev/null || true
	ip link del "$wan_host" 2>/dev/null || true
	if [ "${VEER_PPPOE_BLACKBOX_KEEP_WORKDIR:-0}" = "1" ]; then
		echo "keeping PPPoE blackbox work dir: $work_dir" >&2
	else
		rm -rf "$work_dir"
	fi
}
trap cleanup EXIT INT TERM

use_systemd_veer() {
	case "$VEER_PPPOE_BLACKBOX_SYSTEMD" in
		0) return 1 ;;
		1)
			command -v systemd-run >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
			return
			;;
	esac
	command -v systemd-run >/dev/null 2>&1 &&
		command -v systemctl >/dev/null 2>&1 &&
		[ -d /run/systemd/system ] &&
		systemctl show-environment >/dev/null 2>&1
}

copy_plugin() {
	mkdir -p "$work_dir/plugins"
	rm -rf "$work_dir/plugins/pppoe_client"
	rm -rf "$work_dir/plugins/wan_core"
	rm -rf "$work_dir/plugins/lan_core"
	cp -R "$PLUGIN_DIR" "$work_dir/plugins/pppoe_client"
	cp -R "$ROOT_DIR/plugins/wan_core" "$work_dir/plugins/wan_core"
	cp -R "$ROOT_DIR/plugins/lan_core" "$work_dir/plugins/lan_core"
}

start_topology() {
	ip netns add "$server_ns"
	ip link add "$wan_host" type veth peer name "$wan_peer"
	ip link set "$wan_peer" netns "$server_ns"
	ip link set "$wan_host" up
	ip netns exec "$server_ns" ip link set lo up
	ip netns exec "$server_ns" ip link set "$wan_peer" up
	disable_offloads "$wan_host"
	ip netns exec "$server_ns" ethtool -K "$wan_peer" rx off tx off sg off tso off gso off gro off lro off >/dev/null 2>&1 || true
}

disable_offloads() {
	iface=$1
	ethtool -K "$iface" rx off tx off sg off tso off gso off gro off lro off >/dev/null 2>&1 || true
}

start_pppoe_server() {
	cat >"$work_dir/pppoe-server-options" <<'EOF'
noauth
mtu 1492
mru 1492
lcp-echo-interval 2
lcp-echo-failure 30
nodefaultroute
noipdefault
debug
EOF
	ip netns exec "$server_ns" pppoe-server \
		-I "$wan_peer" \
		-L 8.8.8.8 \
		-R 198.18.0.2 \
		-N 1 \
		-C veer-test-ac \
		-O "$work_dir/pppoe-server-options" \
		-T 0 \
		-X "$work_dir/pppoe-server.pid" \
		>"$work_dir/pppoe-server.log" 2>&1
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		if [ -s "$work_dir/pppoe-server.pid" ] && kill -0 "$(cat "$work_dir/pppoe-server.pid")" 2>/dev/null; then
			pppoe_pid=$(cat "$work_dir/pppoe-server.pid")
			return
		fi
		sleep 0.1
	done
	echo "pppoe-server did not start" >&2
	cat "$work_dir/pppoe-server.log" >&2
	exit 1
}

build_veer_binary() {
	if [ -n "${VEER_BINARY:-}" ]; then
		if [ ! -x "$VEER_BINARY" ]; then
			echo "VEER_BINARY must point to an executable veer binary" >&2
			exit 1
		fi
		return
	fi
	(cd "$ROOT_DIR" && go build -o "$work_dir/veer" .)
	VEER_BINARY="$work_dir/veer"
}

start_veer() {
	cat >"$work_dir/config.json" <<EOF
{
  "web_bind": "127.0.0.1",
  "web_port": $VEER_PPPOE_BLACKBOX_PORT,
  "web_token": "$VEER_PPPOE_BLACKBOX_TOKEN",
  "plugins_enabled": true,
  "plugins_dataplane_enabled": true,
  "plugins_dir": "$work_dir/plugins",
  "default_engine": "auto"
}
EOF
	if use_systemd_veer; then
		veer_unit="veer-pppoe-blackbox-$suffix.service"
		# Positional parameters are intentionally expanded by the child shell.
		# shellcheck disable=SC2016
		if ! systemd-run \
			--unit="$veer_unit" \
			--property=Delegate=yes \
			--property=KillMode=control-group \
			--property=TimeoutStopSec=5s \
			--service-type=exec \
			--collect \
			--quiet \
			/bin/sh -c 'cd "$1" && exec "$2" -config "$3" >"$4" 2>&1' \
			veer-pppoe-blackbox "$work_dir" "$VEER_BINARY" "$work_dir/config.json" "$work_dir/veer.log"; then
			echo "failed to start Veer in an isolated transient systemd service" >&2
			exit 1
		fi
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			veer_pid=$(systemctl show -p MainPID --value "$veer_unit" 2>/dev/null || true)
			case "$veer_pid" in
				''|0|*[!0-9]*) sleep 0.1 ;;
				*) break ;;
			esac
		done
		case "$veer_pid" in
			''|0|*[!0-9]*)
				echo "transient Veer service did not publish a main PID" >&2
				systemctl status "$veer_unit" --no-pager >&2 || true
				exit 1
				;;
		esac
	else
		(
			cd "$work_dir"
			exec "$VEER_BINARY" -config "$work_dir/config.json" >"$work_dir/veer.log" 2>&1
		) &
		veer_pid=$!
	fi
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
		if ! kill -0 "$veer_pid" 2>/dev/null; then
			echo "veer exited before API became ready" >&2
			cat "$work_dir/veer.log" >&2
			exit 1
		fi
		if curl -fsS -H "Authorization: Bearer $VEER_PPPOE_BLACKBOX_TOKEN" "http://127.0.0.1:$VEER_PPPOE_BLACKBOX_PORT/api/plugins" >/dev/null 2>&1; then
			return
		fi
		sleep 0.2
	done
	echo "veer API did not become ready" >&2
	cat "$work_dir/veer.log" >&2
	exit 1
}

api_post_plugin_action() {
	api_plugin=$1
	api_action=$2
	api_payload=$3
	curl -sS --fail-with-body \
		-H "Authorization: Bearer $VEER_PPPOE_BLACKBOX_TOKEN" \
		-H "Content-Type: application/json" \
		-d "{\"payload\":$api_payload}" \
		"http://127.0.0.1:$VEER_PPPOE_BLACKBOX_PORT/api/plugins/$api_plugin/actions/$api_action"
}

api_post_action() {
	api_post_plugin_action pppoe_client "$1" "$2"
}

api_get_plugin_resource() {
	api_plugin=$1
	api_resource=$2
	api_key=$3
	curl -sS --fail-with-body \
		-H "Authorization: Bearer $VEER_PPPOE_BLACKBOX_TOKEN" \
		"http://127.0.0.1:$VEER_PPPOE_BLACKBOX_PORT/api/plugins/$api_plugin/resources/$api_resource/$api_key"
}

api_get_resource() {
	api_resource=$1
	api_key=$2
	api_get_plugin_resource pppoe_client "$api_resource" "$api_key"
}

assert_gro_enabled() {
	if ! ethtool -k "$1" | grep -q '^generic-receive-offload: on'; then
		echo "expected GRO to remain enabled on $1" >&2
		ethtool -k "$1" >&2 || true
		exit 1
	fi
}

json_string() {
	printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

session_is_up() {
	grep -q '"tunnel_installed":true' "$1" && grep -q '"up":true' "$1"
}

wait_for_session_up() {
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		if api_get_resource sessions last >"$work_dir/session.json" 2>/dev/null; then
			if session_is_up "$work_dir/session.json"; then
				return
			fi
		fi
		sleep 0.2
	done
	echo "PPPoE session did not become usable" >&2
	cat "$work_dir/session.json" 2>/dev/null >&2 || true
	cat "$work_dir/veer.log" >&2
	exit 1
}

wait_for_session_disconnected() {
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if api_get_resource sessions last >"$work_dir/session-disconnect.json" 2>/dev/null; then
			if grep -q '"phase":"disconnected"' "$work_dir/session-disconnect.json" && grep -q '"padt_sent":true' "$work_dir/session-disconnect.json"; then
				return
			fi
		fi
		sleep 0.2
	done
	echo "PPPoE session did not report disconnected state" >&2
	cat "$work_dir/session-disconnect.json" 2>/dev/null >&2 || true
	cat "$work_dir/veer.log" >&2
	exit 1
}

wait_for_server_session_release() {
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		if ! ip netns exec "$server_ns" ip -o link show 2>/dev/null | grep -Eq 'ppp[0-9]+:'; then
			return
		fi
		sleep 0.25
	done
	echo "PPPoE server did not release the previous session after PADT" >&2
	ip netns exec "$server_ns" ip -d link show >&2 || true
	dump_dataplane_state
	exit 1
}

test_automatic_redial() {
	api_get_resource sessions last >"$work_dir/session-before-auto-redial.json"
	previous_generation=$(sed -n 's/.*"session_generation":"\([^"]*\)".*/\1/p' "$work_dir/session-before-auto-redial.json" | head -n 1)
	if [ -z "$previous_generation" ]; then
		echo "PPPoE session has no generation before automatic redial test" >&2
		dump_dataplane_state
		exit 1
	fi
	if ! ip netns exec "$server_ns" pkill -TERM -x pppd; then
		echo "failed to terminate the PPPoE server session for automatic redial" >&2
		dump_dataplane_state
		exit 1
	fi

	attempt=0
	while [ "$attempt" -lt 80 ]; do
		attempt=$((attempt + 1))
		if api_get_resource sessions last >"$work_dir/session-auto-redial.json" 2>/dev/null; then
			generation=$(sed -n 's/.*"session_generation":"\([^"]*\)".*/\1/p' "$work_dir/session-auto-redial.json" | head -n 1)
			if [ -n "$generation" ] && [ "$generation" != "$previous_generation" ] && session_is_up "$work_dir/session-auto-redial.json"; then
				if api_get_resource sessions redial_last >"$work_dir/auto-redial-status.json" 2>/dev/null && grep -q '"phase":"redial_ok"' "$work_dir/auto-redial-status.json"; then
					cp "$work_dir/session-auto-redial.json" "$work_dir/session.json"
					if ping -I "$local_if" -c 3 -W 2 8.8.8.8; then
						return
					fi
					break
				fi
			fi
		fi
		sleep 0.25
	done
	echo "PPPoE automatic redial did not establish a new usable session" >&2
	dump_dataplane_state
	exit 1
}

dump_dataplane_state() {
	set +e
	api_post_action debug_stats '{}' >"$work_dir/debug-stats-action.json" 2>&1
	api_get_resource sessions debug_stats >"$work_dir/debug-stats.json" 2>&1
	{
		echo '=== links ==='
		ip -s -s -d link show dev "$local_if"
		ip -s -s -d link show dev "$pipeline_if"
		ip -s -s -d link show dev "$wan_host"
		echo '=== server links ==='
		ip netns exec "$server_ns" ip -s -s -d link show
		echo '=== routes ==='
		ip -4 route show dev "$local_if"
		echo '=== segmented pipeline ingress ==='
		tc -s filter show dev "$pipeline_if" ingress
		echo '=== wan ingress ==='
		tc -s filter show dev "$wan_host" ingress
		echo '=== session ==='
		cat "$work_dir/session.json"
		echo '=== tunnel stats ==='
		cat "$work_dir/debug-stats.json"
		for pcap in "$work_dir"/wan-*.pcap; do
			if [ ! -s "$pcap" ]; then continue; fi
			echo "=== captured WAN traffic: $(basename "$pcap") ==="
			tcpdump -nn -e -vv -r "$pcap"
		done
		echo '=== veer log ==='
		tail -200 "$work_dir/veer.log"
	} >"$work_dir/dataplane-state.log" 2>&1
	cat "$work_dir/dataplane-state.log" >&2
	set -e
}

start_capture() {
	if [ "$VEER_PPPOE_BLACKBOX_CAPTURE" != "1" ]; then return; fi
	capture_file=$1
	tcpdump -U -i "$wan_host" -s "$VEER_PPPOE_BLACKBOX_CAPTURE_SNAPLEN" -w "$capture_file" >/dev/null 2>&1 &
	capture_pid=$!
	tcpdump -U -i "$local_if" -s "$VEER_PPPOE_BLACKBOX_CAPTURE_SNAPLEN" -w "${capture_file%.pcap}-local.pcap" >/dev/null 2>&1 &
	capture_local_pid=$!
	tcpdump -U -i "$pipeline_if" -s "$VEER_PPPOE_BLACKBOX_CAPTURE_SNAPLEN" -w "${capture_file%.pcap}-pipeline.pcap" >/dev/null 2>&1 &
	capture_pipeline_pid=$!
	server_capture_if=$(ip netns exec "$server_ns" ip -o link show | sed -n 's/^[0-9][0-9]*: \(ppp[0-9][0-9]*\):.*/\1/p' | head -n 1)
	if [ -n "$server_capture_if" ]; then
		ip netns exec "$server_ns" tcpdump -U -i "$server_capture_if" -s "$VEER_PPPOE_BLACKBOX_CAPTURE_SNAPLEN" -w "${capture_file%.pcap}-server-ppp.pcap" >/dev/null 2>&1 &
		capture_server_pid=$!
	fi
	sleep 0.3
}

stop_capture() {
	if [ -z "$capture_pid$capture_local_pid$capture_pipeline_pid$capture_server_pid" ]; then return; fi
	for pid in "$capture_pid" "$capture_local_pid" "$capture_pipeline_pid" "$capture_server_pid"; do
		if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
	done
	for pid in "$capture_pid" "$capture_local_pid" "$capture_pipeline_pid" "$capture_server_pid"; do
		if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; fi
	done
	capture_pid=
	capture_local_pid=
	capture_pipeline_pid=
	capture_server_pid=
}

run_blackbox() {
	sh "$PLUGIN_DIR/build.sh"
	copy_plugin
	start_topology
	start_pppoe_server
	build_veer_binary
	start_veer

	wan_payload=$(cat <<EOF
{
  "wan_id": "blackbox",
  "profile_key": "blackbox",
  "driver": "pppoe",
  "driver_plugin": "pppoe_client",
  "state": "prepared",
  "usable": false,
  "real_interface": $(json_string "$wan_host"),
  "local_interface": $(json_string "$local_if"),
  "pipeline_interface": $(json_string "$pipeline_if"),
  "handoff_mode": "segmented_veth",
  "mtu": 1492,
  "addresses": ["198.18.0.2/32"],
  "routes": [{"dst":"8.8.8.8/32","dev":$(json_string "$local_if"),"src":"198.18.0.2"}]
}
EOF
)
	api_post_plugin_action wan_core prepare_handoff "$wan_payload" >"$work_dir/wan-prepare-action.json"
	ip -d link show dev "$local_if" | grep -q 'veth'
	ip -d link show dev "$pipeline_if" | grep -q 'veth'
	ip -d link show dev "$local_if" | grep -q 'NOARP'
	if ip -d link show dev "$pipeline_if" | grep -q 'NOARP'; then
		echo "segmented pipeline peer unexpectedly has NOARP enabled" >&2
		exit 1
	fi

	negotiate_ipv6=false
	if [ "$VEER_PPPOE_BLACKBOX_TEST_IPV6" = "1" ]; then negotiate_ipv6=true; fi
	keepalive_test_fields=
	if [ "$VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE" = "1" ]; then
		keepalive_test_fields=$(cat <<'EOF'
  "keepalive_interval_ms": 10,
  "keepalive_failure_threshold": 1,
  "keepalive_failure_grace_ms": 0,
  "keepalive_confirm_timeout_ms": 100,
  "auto_redial": true,
  "redial_retry_initial_ms": 250,
  "redial_retry_max_ms": 1000,
  "disconnect_drain_ms": 500,
EOF
)
	elif [ "$VEER_PPPOE_BLACKBOX_TEST_AUTO_REDIAL" = "1" ]; then
		keepalive_test_fields=$(cat <<'EOF'
  "keepalive_interval_ms": 250,
  "keepalive_failure_threshold": 2,
  "keepalive_failure_grace_ms": 500,
  "keepalive_confirm_timeout_ms": 250,
  "auto_redial": true,
  "redial_retry_initial_ms": 250,
  "redial_retry_max_ms": 1000,
EOF
)
	fi
	payload=$(cat <<EOF
{
  "interface": $(json_string "$wan_host"),
  "wan_interface": $(json_string "$wan_host"),
  "local_interface": $(json_string "$local_if"),
  "pipeline_interface": $(json_string "$pipeline_if"),
  "wan_id": "blackbox",
  "profile_key": "blackbox",
  "timeout_ms": 1000,
  "control_ack_timeout_ms": 100,
  "control_idle_timeout_ms": 10,
  "max_frames": 8,
  "negotiate_ipv4": true,
  "negotiate_ipv6": $negotiate_ipv6,
  "request_ipv6_address": false,
  "request_ipv6_router": false,
  "request_pd": false,
  "prepare_interfaces": true,
  "sync_hook_bindings": true,
  "apply_hook_bindings": true,
  "send_padt": false,
  "post_session_control_ms": 5000,
$keepalive_test_fields
  "decap_mode": $(json_string "$VEER_PPPOE_BLACKBOX_DECAP_MODE"),
  "wan_core_sync": true,
  "wan_core_required": true,
  "wan_core_apply": true
}
EOF
)
	api_post_action traffic_probe "$payload" >"$work_dir/action.json"
	wait_for_session_up
	api_get_plugin_resource wan_core status blackbox >"$work_dir/wan-status.json"
	grep -q '"segmentation_ready":true' "$work_dir/wan-status.json"
	grep -q '"noarp_ready":true' "$work_dir/wan-status.json"
	if ip -details link show dev "$wan_host" | grep -q 'prog/xdp'; then
		echo "PPPoE TC path unexpectedly attached XDP to $wan_host" >&2
		exit 1
	fi
	if ip -details link show dev "$local_if" | grep -q 'prog/xdp'; then
		echo "PPPoE TC path unexpectedly attached XDP to $local_if" >&2
		exit 1
	fi

	ip -4 addr show dev "$local_if" | grep -q '198.18.0.2/32'
	ip -4 route show dev "$local_if" | grep -q '8.8.8.8'
	tc filter show dev "$pipeline_if" ingress | grep -q bpf
	tc filter show dev "$wan_host" ingress | grep -q bpf
	api_post_action traffic_stats '{"profile_key":"blackbox"}' >"$work_dir/traffic-before.json"
	grep -q '"available":true' "$work_dir/traffic-before.json"
	if [ "$VEER_PPPOE_BLACKBOX_TEST_IPV6" != "1" ]; then
		grep -q '"rx_bytes":0' "$work_dir/traffic-before.json"
		grep -q '"tx_bytes":0' "$work_dir/traffic-before.json"
	fi

	ip link add "$lan_host" type veth peer name "$lan_peer"
	ip link set "$lan_host" up
	ip link set "$lan_peer" up
	ethtool -K "$lan_host" gro on >/dev/null
	assert_gro_enabled "$lan_host"
	lan_payload=$(cat <<EOF
{
  "lan_id": "blackbox",
  "bridge": $(json_string "$lan_bridge"),
  "ports": [$(json_string "$lan_host")],
  "addresses": ["192.0.2.1/24"],
  "mtu": 1500,
  "wan_ref": "blackbox",
  "wan_egress_interface": $(json_string "$local_if"),
  "protocol": "tcp+udp",
  "auto_egress_nat": true,
  "dhcpv4_enabled": false
}
EOF
)
	api_post_plugin_action lan_core apply_network "$lan_payload" >"$work_dir/lan-apply-action.json"
	api_get_plugin_resource lan_core status blackbox >"$work_dir/lan-status.json"
	grep -q '"segmentation_ready":true' "$work_dir/lan-status.json"
	grep -q '"member_gro":{"applied":false' "$work_dir/lan-status.json"
	assert_gro_enabled "$lan_host"
	if [ "$VEER_PPPOE_BLACKBOX_SETTLE_SECONDS" != "0" ]; then
		sleep "$VEER_PPPOE_BLACKBOX_SETTLE_SECONDS"
	fi
	start_capture "$work_dir/wan-data.pcap"
	if ! ping -I "$local_if" -c 3 -W 2 8.8.8.8; then
		stop_capture
		dump_dataplane_state
		exit 1
	fi
	ping -I "$local_if" -c 2 -W 2 -s 1400 8.8.8.8
	if [ "$VEER_PPPOE_BLACKBOX_TEST_IPV6" = "1" ]; then
		server_ppp=$(ip netns exec "$server_ns" ip -o link show | sed -n 's/^[0-9][0-9]*: \(ppp[0-9][0-9]*\):.*/\1/p' | head -n 1)
		if [ -z "$server_ppp" ]; then
			echo "PPPoE server has no PPP interface for IPv6 data test" >&2
			dump_dataplane_state
			exit 1
		fi
		ip netns exec "$server_ns" ip -6 addr replace 2001:db8:ffff::1/128 dev "$server_ppp" nodad
		ip netns exec "$server_ns" ip -6 route replace 2001:db8:ffff::2/128 dev "$server_ppp"
		ip -6 addr replace 2001:db8:ffff::2/128 dev "$local_if" nodad
		ip -6 route replace 2001:db8:ffff::1/128 dev "$local_if" src 2001:db8:ffff::2
		ping -6 -I "$local_if" -c 3 -W 2 2001:db8:ffff::1
	fi
	if [ "$VEER_PPPOE_BLACKBOX_TEST_AUTO_REDIAL" = "1" ]; then
		test_automatic_redial
	fi

	if [ "$VEER_PPPOE_BLACKBOX_RUN_IPERF" = "1" ]; then
	iperf_port=$((56000 + ($$ % 1000)))
	ip netns exec "$server_ns" iperf3 -s -B 8.8.8.8 -p "$iperf_port" --one-off >"$work_dir/iperf-server.log" 2>&1 &
	iperf_pid=$!
	sleep 0.3
	ip netns exec "$server_ns" ss -ltnp "sport = :$iperf_port" >"$work_dir/iperf-listen.log" 2>&1 || true
	if ! timeout "$((VEER_PPPOE_BLACKBOX_SECONDS + 15))" iperf3 -c 8.8.8.8 -B 198.18.0.2 -p "$iperf_port" --connect-timeout 3000 -t "$VEER_PPPOE_BLACKBOX_SECONDS" -P "$VEER_PPPOE_BLACKBOX_PARALLEL" >"$work_dir/iperf-client.log" 2>&1; then
		stop_capture
		dump_dataplane_state
		cat "$work_dir/iperf-client.log" >&2 || true
		cat "$work_dir/iperf-server.log" >&2 || true
		cat "$work_dir/iperf-listen.log" >&2 || true
		kill "$iperf_pid" 2>/dev/null || true
		iperf_pid=
		exit 1
	fi
	cat "$work_dir/iperf-client.log"
	if [ "$VEER_PPPOE_BLACKBOX_PARALLEL" -gt 1 ]; then
		zero_intervals=$(grep -Ec '^\[SUM\].*0\.00 Bytes[[:space:]]+0\.00 bits/sec' "$work_dir/iperf-client.log" || true)
	else
		zero_intervals=$(grep -Ec '^\[[[:space:]]*[0-9]+\].*0\.00 Bytes[[:space:]]+0\.00 bits/sec' "$work_dir/iperf-client.log" || true)
	fi
	if [ "$zero_intervals" -gt 1 ]; then
		stop_capture
		dump_dataplane_state
		echo "iperf3 observed $zero_intervals zero-throughput interval(s)" >&2
		exit 1
	fi
	stop_capture
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if ! kill -0 "$iperf_pid" 2>/dev/null; then
			wait "$iperf_pid" || true
			iperf_pid=
			break
		fi
		sleep 0.2
	done
	if [ -n "$iperf_pid" ]; then
		cat "$work_dir/iperf-server.log" >&2 || true
		kill "$iperf_pid" 2>/dev/null || true
		iperf_pid=
		echo "iperf3 server did not exit after client completed" >&2
		exit 1
	fi
	iperf_pid=
	fi
	api_post_action traffic_stats '{"profile_key":"blackbox"}' >"$work_dir/traffic-after.json"
	grep -q '"available":true' "$work_dir/traffic-after.json"
	grep -Eq '"rx_bytes":[1-9][0-9]*' "$work_dir/traffic-after.json"
	grep -Eq '"tx_bytes":[1-9][0-9]*' "$work_dir/traffic-after.json"
	{
		echo '=== local ==='
		ip -s -s link show dev "$local_if"
		echo '=== pipeline ==='
		ip -s -s link show dev "$pipeline_if"
		echo '=== wan host ==='
		ip -s -s link show dev "$wan_host"
		echo '=== wan peer ==='
		ip netns exec "$server_ns" ip -s -s link show dev "$wan_peer"
		echo '=== server ppp ==='
		ip netns exec "$server_ns" ip -s -s link show | grep -A8 -E 'ppp[0-9]+:' || true
		echo '=== pipeline tc ==='
		tc -s filter show dev "$pipeline_if" ingress
		echo '=== wan tc ==='
		tc -s filter show dev "$wan_host" ingress
	} >"$work_dir/link-stats-after.txt" 2>&1
	assert_gro_enabled "$lan_host"
	api_post_plugin_action lan_core teardown '{"key":"blackbox"}' >"$work_dir/lan-teardown.json"
	assert_gro_enabled "$lan_host"

	api_post_action debug_stats '{}' >"$work_dir/debug-stats-action.json"
	api_get_resource sessions debug_stats >"$work_dir/debug-stats.json"
	grep -q '"local_encap_path":' "$work_dir/debug-stats.json"
	grep -q '"pppoe_seen":' "$work_dir/debug-stats.json"

	start_capture "$work_dir/wan-control.pcap"
	api_post_action disconnect "{\"profile_key\":\"blackbox\",\"interface\":$(json_string "$wan_host")}" >"$work_dir/disconnect-action.json"
	wait_for_session_disconnected
	wait_for_server_session_release
	if [ "$VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE" = "1" ]; then
		sleep 1
		api_get_resource sessions last >"$work_dir/session-disconnect-settled.json"
		grep -q '"phase":"disconnected"' "$work_dir/session-disconnect-settled.json"
		if ip netns exec "$server_ns" ip -o link show 2>/dev/null | grep -Eq 'ppp[0-9]+:'; then
			echo "queued PPPoE timer revived the manually disconnected session" >&2
			exit 1
		fi
	fi
	redial_ok=0
	for attempt in 1 2 3 4 5; do
		sleep 1
		if api_post_action traffic_probe "$payload" >"$work_dir/redial-action-$attempt.json" 2>"$work_dir/redial-action-$attempt.err"; then
			cp "$work_dir/redial-action-$attempt.json" "$work_dir/redial-action.json"
			redial_ok=1
			break
		fi
	done
	if [ "$redial_ok" != "1" ]; then
		stop_capture
		for result in "$work_dir"/redial-action-*.json "$work_dir"/redial-action-*.err; do
			cat "$result" >&2 || true
		done
		dump_dataplane_state
		exit 1
	fi
	wait_for_session_up
	if ! ping -I "$local_if" -c 3 -W 2 8.8.8.8; then
		dump_dataplane_state
		exit 1
	fi
	api_post_action disconnect "{\"profile_key\":\"blackbox\",\"interface\":$(json_string "$wan_host")}" >"$work_dir/redial-disconnect-action.json"
	wait_for_session_disconnected
	wait_for_server_session_release
	if [ "$VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE" = "1" ]; then
		sleep 1
		api_get_resource sessions last >"$work_dir/redial-disconnect-settled.json"
		grep -q '"phase":"disconnected"' "$work_dir/redial-disconnect-settled.json"
		if ip netns exec "$server_ns" ip -o link show 2>/dev/null | grep -Eq 'ppp[0-9]+:'; then
			echo "queued PPPoE timer revived the final disconnected session" >&2
			exit 1
		fi
	fi
	stop_capture
	api_post_plugin_action wan_core teardown "{\"wan_id\":\"blackbox\",\"profile_key\":\"blackbox\",\"local_interface\":$(json_string "$local_if"),\"pipeline_interface\":$(json_string "$pipeline_if"),\"handoff_mode\":\"segmented_veth\"}" >"$work_dir/wan-teardown.json"
	if ip link show dev "$local_if" >/dev/null 2>&1; then
		echo "wan_core teardown left $local_if behind" >&2
		exit 1
	fi
	if ip link show dev "$pipeline_if" >/dev/null 2>&1; then
		echo "wan_core teardown left $pipeline_if behind" >&2
		exit 1
	fi
}

run_blackbox
