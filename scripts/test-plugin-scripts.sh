#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package_test_dir=
verify_test_dir=
trap 'rm -rf "$package_test_dir" "$verify_test_dir"' EXIT INT TERM

for script in \
	"$ROOT_DIR/scripts/lib-plugin-test-env.sh" \
	"$ROOT_DIR/scripts/build-ebpf.sh" \
	"$ROOT_DIR/scripts/build-plugin-ebpf.sh" \
	"$ROOT_DIR/scripts/package-example-plugins.sh" \
	"$ROOT_DIR/scripts/verify-example-plugin-manifests.sh" \
	"$ROOT_DIR/scripts/build-all-ebpf.sh" \
	"$ROOT_DIR/scripts/test-plugin-examples-linux.sh" \
	"$ROOT_DIR/scripts/test-plugin-pppoe-linux.sh" \
	"$ROOT_DIR/scripts/test-plugin-stability-linux.sh" \
	"$ROOT_DIR/scripts/test-plugin-perf-linux.sh" \
	"$ROOT_DIR/scripts/test-plugin-production-linux.sh"
do
	sh -n "$script"
done

sh "$ROOT_DIR/scripts/verify-example-plugin-manifests.sh" >/dev/null

if command -v node >/dev/null 2>&1; then
	node --check "$ROOT_DIR/examples/plugins/pppoe_client/control.js" >/dev/null
	node --check "$ROOT_DIR/examples/plugins/pppoe_client/test-control-node.js" >/dev/null
	node "$ROOT_DIR/examples/plugins/pppoe_client/test-control-node.js" >/dev/null
fi

verify_test_dir=$(mktemp -d "${TMPDIR:-/tmp}/forward-plugin-verify.XXXXXX")
mkdir -p "$verify_test_dir/bad_plugin"
cat >"$verify_test_dir/bad_plugin/plugin.json" <<'JSON'
{
  "api_version": "v1",
  "id": "bad_plugin",
  "name": "Bad Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [
    {
      "id": "apply",
      "runtime_update": "root"
    }
  ],
  "control": {
    "main": "control.js",
    "permissions": ["net.admin"]
  }
}
JSON
cat >"$verify_test_dir/bad_plugin/control.js" <<'JS'
exports.onAction = function () {};
JS
if FORWARD_PLUGIN_EXAMPLE_DIR="$verify_test_dir" sh "$ROOT_DIR/scripts/verify-example-plugin-manifests.sh" >/dev/null 2>&1; then
	echo "manifest verifier accepted an invalid plugin manifest" >&2
	exit 1
fi

package_test_dir=$(mktemp -d "${TMPDIR:-/tmp}/forward-plugin-package.XXXXXX")
FORWARD_PLUGIN_PACKAGE_DIR="$package_test_dir" FORWARD_PLUGIN_PACKAGE_SKIP_BUILD=1 sh "$ROOT_DIR/scripts/package-example-plugins.sh" >/dev/null
FORWARD_PLUGIN_EXAMPLE_DIR="$package_test_dir" sh "$ROOT_DIR/scripts/verify-example-plugin-manifests.sh" >/dev/null

for plugin in lan_core pppoe_client vtolocal wan_core; do
	if [ ! -d "$package_test_dir/$plugin" ]; then
		echo "stable package is missing $plugin" >&2
		exit 1
	fi
	if ! grep -q '"sha256"' "$package_test_dir/$plugin/plugin.json"; then
		echo "stable package did not include control sha256 for $plugin" >&2
		exit 1
	fi
done

for plugin in packet_observer; do
	if [ -e "$package_test_dir/$plugin" ]; then
		echo "stable package should not include lab plugin $plugin by default" >&2
		exit 1
	fi
done

low_memory_output=$(
	FORWARD_PLUGIN_TEST_LOW_MEMORY=1 GOMAXPROCS= GOFLAGS= sh -c '
		. "$1"
		forward_configure_plugin_test_go_env
		forward_configure_plugin_test_go_env
		printf "GOMAXPROCS=%s\n" "$GOMAXPROCS"
		printf "GOFLAGS=%s\n" "$GOFLAGS"
		printf "CONFIGURED=%s\n" "$FORWARD_PLUGIN_TEST_GO_ENV_CONFIGURED"
	' sh "$ROOT_DIR/scripts/lib-plugin-test-env.sh"
)

case "$low_memory_output" in
	*"GOMAXPROCS=2"* )
		;;
	*)
		echo "low-memory helper did not default GOMAXPROCS=2" >&2
		echo "$low_memory_output" >&2
		exit 1
		;;
esac

case " $low_memory_output " in
	*"GOFLAGS=-p=1"* )
		;;
	*)
		echo "low-memory helper did not append GOFLAGS=-p=1" >&2
		echo "$low_memory_output" >&2
		exit 1
		;;
esac

case "$low_memory_output" in
	*"CONFIGURED=1"* )
		;;
	*)
		echo "low-memory helper did not mark the Go env as configured" >&2
		echo "$low_memory_output" >&2
		exit 1
		;;
esac

low_memory_lines=$(printf '%s\n' "$low_memory_output" | grep -c '^plugin test low-memory mode:' || true)
if [ "$low_memory_lines" != "1" ]; then
	echo "low-memory helper should print once when called twice, got $low_memory_lines" >&2
	echo "$low_memory_output" >&2
	exit 1
fi

FORWARD_PLUGIN_TEST_LOW_MEMORY=0 sh -c '
	. "$1"
	if forward_plugin_test_low_memory_enabled; then
		echo "low-memory helper ignored FORWARD_PLUGIN_TEST_LOW_MEMORY=0" >&2
		exit 1
	fi
' sh "$ROOT_DIR/scripts/lib-plugin-test-env.sh"

existing_p_output=$(
	FORWARD_PLUGIN_TEST_LOW_MEMORY=1 GOMAXPROCS=4 GOFLAGS='-mod=mod -p 4' sh -c '
		. "$1"
		forward_configure_plugin_test_go_env
		printf "GOMAXPROCS=%s\n" "$GOMAXPROCS"
		printf "GOFLAGS=%s\n" "$GOFLAGS"
	' sh "$ROOT_DIR/scripts/lib-plugin-test-env.sh"
)

case "$existing_p_output" in
	*"GOMAXPROCS=4"* )
		;;
	*)
		echo "low-memory helper should preserve explicit GOMAXPROCS" >&2
		echo "$existing_p_output" >&2
		exit 1
		;;
esac

case "$existing_p_output" in
	*"GOFLAGS=-mod=mod -p 4"* )
		;;
	*)
		echo "low-memory helper should preserve existing GOFLAGS -p value" >&2
		echo "$existing_p_output" >&2
		exit 1
		;;
esac

echo "plugin scripts self-test passed"
