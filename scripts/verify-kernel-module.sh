#!/usr/bin/env sh
# Requires root, matching headers, clang, pahole, kmod and network test tools.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "kernel module integration requires root" >&2; exit 1; }
[ ! -d /sys/module/veer_kfuncs ] || { echo "use an isolated test host without an existing veer_kfuncs module" >&2; exit 1; }
work=$(mktemp -d)
loaded=0
cleanup() {
    if [ "$loaded" = 1 ]; then
        attempts=0
        while ! rmmod veer_kfuncs; do
            attempts=$((attempts+1))
            [ "$attempts" -lt 30 ] || break
            sleep 0.1
        done
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT INT TERM
cd "$ROOT_DIR"
sh scripts/build-kernel-module.sh
sh scripts/build-all-ebpf.sh
CGO_ENABLED=0 go build -tags veer_kfuncs -o "$work/veer" .
CGO_ENABLED=0 go build -o "$work/loader" ./scripts/kfuncs-test-loader
insmod "kernel/$(uname -r)/veer_kfuncs.ko"
loaded=1
VEER_RUN_KFUNCS_TESTS=1 FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 go test -tags veer_kfuncs ./internal/app -run '^(TestOptionalKernelModule.*|TestPluginControlNetOwnedLinkMACLinuxIntegration)$' -count=1 -v
python3 scripts/verify-kfuncs-packets.py --loader "$work/loader"
python3 scripts/verify-kfuncs-packets.py --loader "$work/loader" --direct --veer "$work/veer"
VEER_RUN_KFUNCS_TESTS=1 VEER_RUN_WIREGUARD_TESTS=1 FORWARD_PERF_BINARY="$work/veer" \
    go test -tags veer_kfuncs ./internal/app -run '^TestWireGuardMeshLinuxIntegration$' -count=1 -v -timeout=5m
FORWARD_PERF_BINARY="$work/veer" VEER_VPN_EXPECT_DIRECT=1 sh scripts/verify-vpn-cores.sh
