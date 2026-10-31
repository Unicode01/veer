#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/veer-vpn-cores.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM

if [ -z "${VEER_TEST_MIHOMO:-}" ] || [ -z "${VEER_TEST_SING_BOX:-}" ]; then
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) echo 'Provide VEER_TEST_MIHOMO and VEER_TEST_SING_BOX for this architecture' >&2; exit 1 ;;
    esac
    curl -fL --retry 2 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-compatible-v1.19.33.gz' -o "$WORK_DIR/mihomo.gz"
    curl -fL --retry 2 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz' -o "$WORK_DIR/sing-box.tar.gz"
    (
        cd "$WORK_DIR"
        printf '%s\n' '386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6  mihomo.gz' \
            '699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968  sing-box.tar.gz' | sha256sum -c -
        gzip -dc mihomo.gz > mihomo
        tar -xzf sing-box.tar.gz --strip-components=1 sing-box-1.14.4-linux-amd64/sing-box
        chmod 755 mihomo sing-box
    )
    VEER_TEST_MIHOMO="$WORK_DIR/mihomo"
    VEER_TEST_SING_BOX="$WORK_DIR/sing-box"
fi
export VEER_TEST_MIHOMO VEER_TEST_SING_BOX
cd "$ROOT_DIR"
go test -c -o "$WORK_DIR/vpn.test" ./internal/app
VEER_RUN_VPN_CORE_TESTS=1 "$WORK_DIR/vpn.test" -test.run='^(TestPluginManagedProcess.*|TestPluginBinary.*|TestVPNCoreLinuxIntegration)$' -test.count=1 -test.v -test.timeout=10m
# A service-owned delegated cgroup lets the strict test verify real quotas,
# rather than silently degrading in the go command's shared runner cgroup.
systemd-run --quiet --wait --pipe --collect --unit="veer-vpn-limits-$$" \
    --property=Delegate=yes --working-directory="$ROOT_DIR" \
    env VEER_RUN_VPN_PROCESS_LIMITS_TEST=1 "$WORK_DIR/vpn.test" \
    -test.run='^TestPluginManagedProcessFullResourceLimits$' -test.v -test.timeout=30s
