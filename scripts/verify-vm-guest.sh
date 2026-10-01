#!/usr/bin/env sh
set -eu

[ "${VEER_VM_TEST_GUEST:-}" = 1 ] || { echo 'requires a disposable VM test guest' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'requires root' >&2; exit 1; }
profile=${1:?requires alpine or rocky profile}
phase=${2:-verify}
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"
. /etc/os-release
uname -a
printf 'guest: %s; phase: %s\n' "$PRETTY_NAME" "$phase"
case "$profile:$ID" in
    alpine:alpine) manager=openrc ;;
    rocky:rocky) manager=systemd; [ "$(getenforce)" = Enforcing ] ;;
    *) echo 'unexpected guest distribution' >&2; exit 1 ;;
esac

ready() {
    attempts=0
    until curl -fsS http://127.0.0.1:8080/readyz; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 30 ] || return 1
        sleep 1
    done
    if [ "$manager" = openrc ]; then
        main_pid=$(pgrep -o -x veer)
        grep -Eq "^0::/(openrc\\.)?veer/veer-app-${main_pid}$" "/proc/$main_pid/cgroup"
    fi
}

if [ "$phase" = reboot ]; then
    ready
    if [ "$manager" = openrc ]; then rc-service veer status; else systemctl is-active veer; fi
    echo 'deployed service starts after guest reboot: passed'
    exit 0
fi

case "$manager" in
    openrc) apk add --no-cache bash curl python3 iproute2 iptables nftables util-linux procps ethtool iputils ;;
    systemd) dnf install -y bash python3 iproute iptables nftables util-linux procps-ng ethtool iputils policycoreutils ;;
esac
# Keep low-memory test guests responsive without changing production configuration.
fallocate -l 256M /var/tmp/veer-vm.swap
chmod 600 /var/tmp/veer-vm.swap
mkswap /var/tmp/veer-vm.swap >/dev/null
swapon /var/tmp/veer-vm.swap
chmod 755 veer-linux-amd64 veer-platform.test
export WEB_BIND=127.0.0.1 WEB_PORT=8080 WEB_TOKEN=veer-vm-test-0123456789abcdef01234567
export VEER_SERVICE_MANAGER="$manager"
bash deploy.sh
ready
if [ "$manager" = systemd ]; then
    pid=$(systemctl show veer --property=MainPID --value)
else
    pid=$(pgrep -o -x veer)
    rc-update show default | grep -w veer
    [ "$(readlink "/proc/$pid/ns/mnt")" = "$(readlink /proc/1/ns/mnt)" ]
fi
awk '$1 == "Max" && $2 == "open" && $3 == "files" { found=1; if ($4+0 < 65535) exit 1 } END { if (!found) exit 1 }' "/proc/$pid/limits"
# Exercise the real installer hot-update path, then supervisor crash recovery.
bash deploy.sh
ready
if [ "$manager" = systemd ]; then pid=$(systemctl show veer --property=MainPID --value); else pid=$(pgrep -o -x veer); fi
kill -KILL "$pid"
sleep 4
ready
if [ "$manager" = systemd ]; then
    [ "$(getenforce)" = Enforcing ]
    systemctl stop veer
    VEER_PLATFORM_TEST_BINARY="$ROOT_DIR/veer-platform.test" bash scripts/verify-service-platform.sh
else
    rc-service veer stop
    VEER_PLATFORM_TEST_BINARY="$ROOT_DIR/veer-platform.test" bash scripts/verify-openrc-platform.sh
fi

mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
export FORWARD_PERF_BINARY="$ROOT_DIR/veer-linux-amd64"
export FORWARD_RUN_KERNEL_LOAD_SMOKE=1 FORWARD_RUN_TC_IPV6_TEST=1
export FORWARD_RUN_XDP_FULLNAT_TEST=1 FORWARD_RUN_XDP_IPV6_TEST=1
export FORWARD_RUN_EGRESS_NAT_TEST=1 FORWARD_RUN_EGRESS_NAT_XDP_TEST=1
pattern='^(TestLoadEmbeddedKernelCollectionsSmoke|TestTCKernelIPv6Integration|TestXDPKernelIPv4FullNATIntegration|TestXDPKernelIPv6Integration|TestEgressNATTCIntegration|TestEgressNATXDPIntegration)$'
status=0
./veer-platform.test -test.v -test.run="$pattern" -test.count=1 -test.timeout=15m > /var/tmp/veer-vm-dataplane.log 2>&1 || status=$?
cat /var/tmp/veer-vm-dataplane.log
[ "$status" = 0 ]
if grep -F -- '--- SKIP:' /var/tmp/veer-vm-dataplane.log; then
    echo 'VM dataplane test was skipped' >&2
    exit 1
fi
for name in TestLoadEmbeddedKernelCollectionsSmoke TestTCKernelIPv6Integration TestXDPKernelIPv4FullNATIntegration TestXDPKernelIPv6Integration TestEgressNATTCIntegration TestEgressNATXDPIntegration; do
    grep -F -- "--- PASS: $name " /var/tmp/veer-vm-dataplane.log
done
if [ "$manager" = systemd ]; then
    [ "$(getenforce)" = Enforcing ]
    systemctl start veer
else
    rc-service veer start
fi
ready
printf '%s VM deployment and native dataplane: passed\n' "$profile"
