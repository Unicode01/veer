#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/lib-plugin-test-env.sh"

if [ "$(id -u)" != "0" ]; then
	echo "PPPoE plugin integration tests require root" >&2
	exit 1
fi

missing=
for tool in ip tc clang iperf3 pppd pppoe-server curl sed grep timeout ss ethtool; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		missing="${missing:+$missing }$tool"
	fi
done
if [ -n "$missing" ]; then
	echo "PPPoE plugin integration tests require: $missing" >&2
	exit 1
fi

if [ ! -c /dev/net/tun ]; then
	echo "PPPoE plugin integration tests require /dev/net/tun" >&2
	exit 1
fi

cd "$ROOT_DIR"

if command -v node >/dev/null 2>&1; then
	node "$ROOT_DIR/examples/plugins/pppoe_client/test-control-node.js" >/dev/null
else
	echo "skip PPPoE control-plane self-test because node is unavailable"
fi

case "${FORWARD_PLUGIN_PPPOE_REPEAT:-1}" in
	''|*[!0-9]*|0)
		echo "FORWARD_PLUGIN_PPPOE_REPEAT must be a positive integer" >&2
		exit 1
		;;
esac
: "${FORWARD_PLUGIN_PPPOE_REPEAT:=1}"
: "${FORWARD_PPPOE_BLACKBOX_SECONDS:=${FORWARD_PPPOE_INTEGRATION_IPERF_SECONDS:-8}}"
: "${FORWARD_PPPOE_BLACKBOX_PARALLEL:=${FORWARD_PPPOE_INTEGRATION_IPERF_PARALLEL:-1}}"

export FORWARD_PPPOE_BLACKBOX_SECONDS
export FORWARD_PPPOE_BLACKBOX_PARALLEL

i=1
while [ "$i" -le "$FORWARD_PLUGIN_PPPOE_REPEAT" ]; do
	echo "running PPPoE plugin blackbox integration test ($i/$FORWARD_PLUGIN_PPPOE_REPEAT)"
	sh "$ROOT_DIR/examples/plugins/pppoe_client/test-blackbox-linux.sh"
	i=$((i + 1))
done
