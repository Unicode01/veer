#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} == 0 && -d /run/openrc ]] || { echo 'requires root and running OpenRC' >&2; exit 1; }
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_NAME="veer-platform-$$"
SERVICE_FILE="/etc/init.d/${SERVICE_NAME}"
INSTALL_DIR="$(mktemp -d /var/lib/veer-platform.XXXXXX)"
export HOT_RESTART_MARKER="${INSTALL_DIR}/.hot"
export BPF_STATE_DIR="/sys/fs/bpf/${SERVICE_NAME}"
export RUNTIME_STATE_DIR="${INSTALL_DIR}/.state"
export SERVICE_MANAGER=openrc
mkdir -p "$RUNTIME_STATE_DIR" /run/netns
retained_pid=""
retained_group=""
cleanup() {
    if [[ $? != 0 ]]; then
        cat "$SERVICE_FILE" "${INSTALL_DIR}/veer-openrc-launch" 2>/dev/null || true
        ps -eo pid,ppid,args
        find "/sys/fs/cgroup/${SERVICE_NAME}" "/sys/fs/cgroup/openrc.${SERVICE_NAME}" -name cgroup.procs -exec sh -c 'echo "$1"; cat "$1"' sh {} \; 2>/dev/null || true
    fi
    rc-service "$SERVICE_NAME" stop >/dev/null 2>&1 || true
    if [[ -n "$retained_pid" ]]; then
        kill "$retained_pid" 2>/dev/null || true
        wait "$retained_pid" 2>/dev/null || true
    fi
    for group in "/sys/fs/cgroup/${SERVICE_NAME}" "/sys/fs/cgroup/openrc.${SERVICE_NAME}"; do
        if [[ -d "$group" ]]; then
            find "$group" -depth -mindepth 1 -type d -exec rmdir {} \; 2>/dev/null || true
            rmdir "$group" 2>/dev/null || true
        fi
    done
    ip netns del "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -f -- "$SERVICE_FILE" "/var/log/${SERVICE_NAME}.log"
    rm -rf -- "$INSTALL_DIR"
}
trap cleanup EXIT
install -m 755 "${VEER_PLATFORM_TEST_BINARY:?requires a prebuilt test binary}" "${INSTALL_DIR}/veer"
python3 "$ROOT_DIR/scripts/verify-platform-behavior.py" --library deploy > "${INSTALL_DIR}/service-functions.sh"
# shellcheck source=/dev/null
source "${INSTALL_DIR}/service-functions.sh"
cat > "${INSTALL_DIR}/hold-test" <<'EOF'
#!/bin/sh
status=0
printf 'supervisor group: %s\n' "${VEER_OPENRC_CGROUP:-unavailable}" > "$VEER_PLATFORM_TEST_LOG"
cat /proc/self/cgroup >> "$VEER_PLATFORM_TEST_LOG"
if [ -z "${VEER_OPENRC_CGROUP:-}" ]; then
    echo 'the generated service did not delegate its own cgroup' >> "$VEER_PLATFORM_TEST_LOG"
    printf '1\n' > "$VEER_PLATFORM_TEST_RESULT"
    exit 1
fi
"$VEER_PLATFORM_TEST_LAUNCHER" -test.v -test.run="$VEER_PLATFORM_TEST_PATTERN" -test.count=1 -test.timeout=2m >> "$VEER_PLATFORM_TEST_LOG" 2>&1 || status=$?
printf '%s\n' "$status" > "$VEER_PLATFORM_TEST_RESULT"
exec sleep 86400
EOF
chmod 755 "${INSTALL_DIR}/hold-test"

run_phase() {
    local phase="$1" pattern="$2"
    local test_log="${INSTALL_DIR}/${phase}.log" result="${INSTALL_DIR}/${phase}.result"
    write_service_definition
    cat >> "$SERVICE_FILE" <<EOF
command="${INSTALL_DIR}/hold-test"
command_args=""
export VEER_PLATFORM_TEST_LAUNCHER="${INSTALL_DIR}/veer-openrc-launch"
export VEER_PLATFORM_TEST_PATTERN="${pattern}"
export VEER_PLATFORM_TEST_LOG="${test_log}"
export VEER_PLATFORM_TEST_RESULT="${result}"
export VEER_RUN_SERVICE_PLATFORM_TEST=1
export VEER_SERVICE_TEST_PHASE="${phase}"
export VEER_SERVICE_TEST_NAMESPACE="${SERVICE_NAME}"
export VEER_SERVICE_TEST_IDENTITY_FILE="${INSTALL_DIR}/identity.json"
EOF
    rc-service "$SERVICE_NAME" start
    local deadline=$((SECONDS + 150))
    while [[ ! -f "$result" && $SECONDS -lt $deadline ]]; do sleep 1; done
    [[ -f "$result" ]] || { cat "$test_log"; return 1; }
    cat "$test_log"
    [[ $(< "$result") == 0 ]]
    if grep -F -- '--- SKIP:' "$test_log"; then
        echo 'OpenRC deployment service test was skipped' >&2
        return 1
    fi
    grep -F -- '--- PASS:' "$test_log"
    if [[ "$phase" == create ]]; then
        local group
        for group in "/sys/fs/cgroup/${SERVICE_NAME}" "/sys/fs/cgroup/openrc.${SERVICE_NAME}"; do
            [[ -d "$group" ]] || continue
            retained_group="${group}/retained-worker"
            mkdir "$retained_group"
            # Simulate a worker retained by hot restart, with its own process group.
            (printf '%s\n' "$BASHPID" > "${retained_group}/cgroup.procs"; exec sleep 86400) &
            retained_pid=$!
            local deadline=$((SECONDS + 10))
            until grep -qx "$retained_pid" "${retained_group}/cgroup.procs"; do
                [[ $SECONDS -lt $deadline ]] || return 1
                sleep 0.1
            done
            break
        done
        [[ -n "$retained_pid" ]]
    fi
    rc-service "$SERVICE_NAME" stop
    kill -0 "$retained_pid"
    grep -qx "$retained_pid" "${retained_group}/cgroup.procs"
}

for phase in create reuse delete; do
    run_phase "$phase" '^TestPluginHostMountNamespaceServiceLifecycle$'
    if [[ "$phase" == delete ]]; then
        [[ ! -e "/run/netns/${SERVICE_NAME}" ]]
    else
        ip netns exec "$SERVICE_NAME" true
    fi
done
run_phase sandbox '^(TestPluginHostLinuxSandboxIdentityAndCgroup|TestPluginHostLinuxSandboxEnforcementProbe|TestPluginHostLinuxChrootFallbackEnforcementProbe)$'
echo 'OpenRC deployment service namespace lifecycle, retained worker and plugin sandbox: passed'
