#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
PLUGIN_DIR="$ROOT_DIR/examples/plugins/pppoe_client"

if [ "$(id -u)" != "0" ]; then
	echo "PPPoE blackbox test requires root" >&2
	exit 1
fi

missing=
for tool in ip tc clang iperf3 pppd pppoe-server curl sed grep timeout ss ethtool; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		missing="${missing:+$missing }$tool"
	fi
done
if [ -n "$missing" ]; then
	echo "PPPoE blackbox test requires: $missing" >&2
	exit 1
fi

: "${FORWARD_PPPOE_BLACKBOX_SECONDS:=8}"
: "${FORWARD_PPPOE_BLACKBOX_PARALLEL:=1}"
: "${FORWARD_PPPOE_BLACKBOX_PORT:=0}"
: "${FORWARD_PPPOE_BLACKBOX_TOKEN:=pppoe-blackbox-token}"

case "$FORWARD_PPPOE_BLACKBOX_SECONDS" in
	''|*[!0-9]*|0)
		echo "FORWARD_PPPOE_BLACKBOX_SECONDS must be a positive integer" >&2
		exit 1
		;;
esac
case "$FORWARD_PPPOE_BLACKBOX_PARALLEL" in
	''|*[!0-9]*|0)
		echo "FORWARD_PPPOE_BLACKBOX_PARALLEL must be a positive integer" >&2
		exit 1
		;;
esac

if [ "$FORWARD_PPPOE_BLACKBOX_PORT" = "0" ]; then
	FORWARD_PPPOE_BLACKBOX_PORT=$((18080 + ($$ % 1000)))
fi

suffix=$$
client_ns="fwpppbb$suffix"
lan_host="lanbb0$suffix"
lan_client="lanbb1$suffix"
wan_host="wanbb0$suffix"
wan_peer="wanbb1$suffix"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/forward-pppoe-blackbox.XXXXXX")
forward_pid=
pppoe_pid=
iperf_pid=

cleanup() {
	set +e
	if [ "${FORWARD_PPPOE_BLACKBOX_KEEP_WORKDIR:-0}" = "1" ]; then
		echo "keeping PPPoE blackbox work dir: $work_dir" >&2
		return
	fi
	if [ -n "$iperf_pid" ]; then kill "$iperf_pid" 2>/dev/null || true; fi
	if [ -n "$forward_pid" ]; then kill "$forward_pid" 2>/dev/null || true; fi
	if [ -n "$pppoe_pid" ]; then kill "$pppoe_pid" 2>/dev/null || true; fi
	if [ -f "$work_dir/pppoe-server.pid" ]; then kill "$(cat "$work_dir/pppoe-server.pid")" 2>/dev/null || true; fi
	pkill -f "[p]ppoe-server .*${wan_peer}" 2>/dev/null || true
	ip netns pids "$client_ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
	ip netns del "$client_ns" 2>/dev/null || true
	ip link del "$lan_host" 2>/dev/null || true
	ip link del "$wan_host" 2>/dev/null || true
	rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

copy_plugin() {
	mkdir -p "$work_dir/plugins"
	rm -rf "$work_dir/plugins/pppoe_client"
	cp -R "$PLUGIN_DIR" "$work_dir/plugins/pppoe_client"
}

start_topology() {
	ip netns add "$client_ns"
	ip link add "$lan_host" type veth peer name "$lan_client"
	ip link add "$wan_host" type veth peer name "$wan_peer"
	ip link set "$lan_client" netns "$client_ns"
	ip addr add 198.18.0.1/24 dev "$lan_host"
	ip link set "$lan_host" up
	ip link set "$wan_host" up
	ip link set "$wan_peer" up
	ip netns exec "$client_ns" ip link set lo up
	ip netns exec "$client_ns" ip addr add 198.18.0.2/24 dev "$lan_client"
	ip netns exec "$client_ns" ip link set "$lan_client" up
	ip netns exec "$client_ns" ip route replace default via 198.18.0.1 dev "$lan_client"
	ip link set dev "$lan_host" mtu 1492
	ip netns exec "$client_ns" ip link set dev "$lan_client" mtu 1492
	disable_offloads "$lan_host"
	disable_offloads "$wan_host"
	disable_offloads "$wan_peer"
	ip netns exec "$client_ns" ethtool -K "$lan_client" rx off tx off sg off tso off gso off gro off lro off >/dev/null 2>&1 || true
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
lcp-echo-interval 0
lcp-echo-failure 0
nodefaultroute
noipdefault
debug
EOF
	pppoe-server \
		-I "$wan_peer" \
		-L 8.8.8.8 \
		-R 198.18.0.2 \
		-N 1 \
		-C forward-test-ac \
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

build_forward_binary() {
	if [ -n "${FORWARD_BINARY:-}" ]; then
		if [ ! -x "$FORWARD_BINARY" ]; then
			echo "FORWARD_BINARY must point to an executable forward binary" >&2
			exit 1
		fi
		return
	fi
	(cd "$ROOT_DIR" && go build -o "$work_dir/forward" .)
	FORWARD_BINARY="$work_dir/forward"
}

start_forward() {
	cat >"$work_dir/config.json" <<EOF
{
  "web_bind": "127.0.0.1",
  "web_port": $FORWARD_PPPOE_BLACKBOX_PORT,
  "web_token": "$FORWARD_PPPOE_BLACKBOX_TOKEN",
  "plugins_enabled": true,
  "plugins_dataplane_enabled": true,
  "plugins_dir": "$work_dir/plugins",
  "default_engine": "auto"
}
EOF
	(
		cd "$work_dir"
		"$FORWARD_BINARY" -config "$work_dir/config.json" >"$work_dir/forward.log" 2>&1
	) &
	forward_pid=$!
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
		if ! kill -0 "$forward_pid" 2>/dev/null; then
			echo "forward exited before API became ready" >&2
			cat "$work_dir/forward.log" >&2
			exit 1
		fi
		if curl -fsS -H "Authorization: Bearer $FORWARD_PPPOE_BLACKBOX_TOKEN" "http://127.0.0.1:$FORWARD_PPPOE_BLACKBOX_PORT/api/plugins" >/dev/null 2>&1; then
			return
		fi
		sleep 0.2
	done
	echo "forward API did not become ready" >&2
	cat "$work_dir/forward.log" >&2
	exit 1
}

api_post_action() {
	action=$1
	payload=$2
	curl -fsS \
		-H "Authorization: Bearer $FORWARD_PPPOE_BLACKBOX_TOKEN" \
		-H "Content-Type: application/json" \
		-d "{\"payload\":$payload}" \
		"http://127.0.0.1:$FORWARD_PPPOE_BLACKBOX_PORT/api/plugins/pppoe_client/actions/$action"
}

api_get_resource() {
	resource=$1
	key=$2
	curl -fsS \
		-H "Authorization: Bearer $FORWARD_PPPOE_BLACKBOX_TOKEN" \
		"http://127.0.0.1:$FORWARD_PPPOE_BLACKBOX_PORT/api/plugins/pppoe_client/resources/$resource/$key"
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
	cat "$work_dir/forward.log" >&2
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
	cat "$work_dir/forward.log" >&2
	exit 1
}

run_blackbox() {
	sh "$PLUGIN_DIR/build.sh"
	copy_plugin
	start_topology
	start_pppoe_server
	build_forward_binary
	start_forward

	lan_dst_mac=$(ip netns exec "$client_ns" cat "/sys/class/net/$lan_client/address")
	payload=$(cat <<EOF
{
  "interface": $(json_string "$wan_host"),
  "wan_interface": $(json_string "$wan_host"),
  "lan_interface": $(json_string "$lan_host"),
  "lan_dst_mac": $(json_string "$lan_dst_mac"),
  "timeout_ms": 1000,
  "control_ack_timeout_ms": 100,
  "control_idle_timeout_ms": 10,
  "max_frames": 8,
  "negotiate_ipv4": true,
  "negotiate_ipv6": false,
  "request_pd": false,
  "prepare_interfaces": true,
  "sync_hook_bindings": true,
  "apply_hook_bindings": true,
  "send_padt": false,
  "post_session_control_ms": 200,
  "decap_mode": "manual",
  "wan_core_sync": false
}
EOF
)
	api_post_action traffic_probe "$payload" >"$work_dir/action.json"
	wait_for_session_up

	tc filter show dev "$lan_host" ingress | grep -q bpf
	tc filter show dev "$wan_host" ingress | grep -q bpf
	ip netns exec "$client_ns" ping -c 3 -W 2 8.8.8.8
	ip netns exec "$client_ns" ping -c 2 -W 2 -s 1400 8.8.8.8

	iperf_port=$((56000 + ($$ % 1000)))
	iperf3 -s -B 8.8.8.8 -p "$iperf_port" --one-off >"$work_dir/iperf-server.log" 2>&1 &
	iperf_pid=$!
	sleep 0.3
	ss -ltnp "sport = :$iperf_port" >"$work_dir/iperf-listen.log" 2>&1 || true
	if ! ip netns exec "$client_ns" timeout "$((FORWARD_PPPOE_BLACKBOX_SECONDS + 15))" iperf3 -c 8.8.8.8 -p "$iperf_port" --connect-timeout 3000 -t "$FORWARD_PPPOE_BLACKBOX_SECONDS" -P "$FORWARD_PPPOE_BLACKBOX_PARALLEL" >"$work_dir/iperf-client.log" 2>&1; then
		cat "$work_dir/iperf-client.log" >&2 || true
		cat "$work_dir/iperf-server.log" >&2 || true
		cat "$work_dir/iperf-listen.log" >&2 || true
		kill "$iperf_pid" 2>/dev/null || true
		iperf_pid=
		exit 1
	fi
	cat "$work_dir/iperf-client.log"
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

	api_post_action debug_stats '{}' >"$work_dir/debug-stats-action.json"
	api_get_resource sessions debug_stats >"$work_dir/debug-stats.json"
	grep -q '"lan_encap_path":' "$work_dir/debug-stats.json"
	grep -q '"pppoe_seen":' "$work_dir/debug-stats.json"

	api_post_action disconnect "{\"interface\":$(json_string "$wan_host")}" >"$work_dir/disconnect-action.json"
	wait_for_session_disconnected
}

run_blackbox
