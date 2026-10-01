#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} == 0 ]] || { echo 'requires root and systemd' >&2; exit 1; }
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_NAME="veer-platform-$$"
SERVICE_FILE="/run/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="$(mktemp -d /opt/veer-platform.XXXXXX)"
export HOT_RESTART_MARKER="${INSTALL_DIR}/.hot"
export BPF_STATE_DIR="/sys/fs/bpf/${SERVICE_NAME}"
export RUNTIME_STATE_DIR="${INSTALL_DIR}/.state"
export SERVICE_MANAGER=systemd
namespace="${SERVICE_NAME}"
mounted_bpffs=0
cleanup() {
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    journalctl -u "$SERVICE_NAME" --no-pager -n 100 || true
    ip netns del "$namespace" >/dev/null 2>&1 || true
    rm -f -- "$SERVICE_FILE"
    systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl daemon-reload
    rmdir "$BPF_STATE_DIR" 2>/dev/null || true
    if [[ "$mounted_bpffs" == 1 ]]; then
        umount /sys/fs/bpf
    fi
    rm -rf -- "$INSTALL_DIR"
}
trap cleanup EXIT

mkdir -p /run/netns /sys/fs/bpf "$RUNTIME_STATE_DIR"
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
    mounted_bpffs=1
fi
mkdir -p "$BPF_STATE_DIR"
if [[ -n "${VEER_PLATFORM_TEST_BINARY:-}" ]]; then
    install -m 755 "$VEER_PLATFORM_TEST_BINARY" "${INSTALL_DIR}/veer"
else
    (cd "$ROOT_DIR" && CGO_ENABLED=0 go test -c -o "${INSTALL_DIR}/veer" ./internal/app)
fi
python3 "$ROOT_DIR/scripts/verify-platform-behavior.py" --library deploy > "${INSTALL_DIR}/service-functions.sh"
# shellcheck source=/dev/null
source "${INSTALL_DIR}/service-functions.sh"

for phase in create reuse delete; do
    write_service_definition
    sed -i '/^ExecStart=/d; /^Restart=/d' "$SERVICE_FILE"
    cat >> "$SERVICE_FILE" <<EOF

[Service]
Type=oneshot
Restart=no
ExecStart=${INSTALL_DIR}/veer -test.v -test.run=^TestPluginHostMountNamespaceServiceLifecycle$ -test.count=1 -test.timeout=2m
Environment=VEER_RUN_SERVICE_PLATFORM_TEST=1
Environment=VEER_SERVICE_TEST_PHASE=${phase}
Environment=VEER_SERVICE_TEST_NAMESPACE=${namespace}
Environment=VEER_SERVICE_TEST_IDENTITY_FILE=${INSTALL_DIR}/identity.json
EOF
    prepare_selinux_labels
    systemd-analyze verify "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl start "$SERVICE_NAME"
    if [[ "$phase" == delete ]]; then
        [[ ! -e "/run/netns/${namespace}" ]]
    else
        ip netns exec "$namespace" true
    fi
done
echo 'deployment service namespace lifecycle: passed'

write_service_definition
sed -i '/^ExecStart=/d; /^Restart=/d' "$SERVICE_FILE"
cat >> "$SERVICE_FILE" <<EOF

[Service]
Type=oneshot
Restart=no
ExecStart=${INSTALL_DIR}/veer -test.v -test.run=^(TestPluginHostLinuxSandboxIdentityAndCgroup|TestPluginHostLinuxSandboxEnforcementProbe|TestPluginHostLinuxChrootFallbackEnforcementProbe)$ -test.count=1 -test.timeout=2m
EOF
prepare_selinux_labels
systemd-analyze verify "$SERVICE_FILE"
systemctl daemon-reload
systemctl start "$SERVICE_NAME"
journalctl -u "$SERVICE_NAME" --no-pager -o cat > "${INSTALL_DIR}/service.log"
if grep -F -- '--- SKIP:' "${INSTALL_DIR}/service.log"; then
    echo 'deployment service sandbox test was skipped' >&2
    exit 1
fi
for test_name in TestPluginHostLinuxSandboxIdentityAndCgroup TestPluginHostLinuxSandboxEnforcementProbe TestPluginHostLinuxChrootFallbackEnforcementProbe; do
    grep -F -- "--- PASS: ${test_name}" "${INSTALL_DIR}/service.log"
done
echo 'deployment service plugin sandbox: passed'
