#!/usr/bin/env sh
# Runs verify-kfuncs-packets.py in a QEMU guest that boots this host's own
# kernel, through virtme-ng with the host's filesystem shared read-only. The
# guest's console comes out here: a check that hangs the kernel stops the
# guest instead of the host, and the kernel's lockup and stall reports end up
# in the log.
#
# usage: verify-kfuncs-guest.sh LOADER [verify-kfuncs-packets.py arguments...]
# Requires root, KVM, virtme-ng (vng) and qemu-system-x86. VNG overrides the
# vng command, VEER_GUEST_TIMEOUT the time limit in seconds and
# VEER_GUEST_MEMORY the guest's memory.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "the guest check requires root" >&2; exit 1; }
[ $# -ge 1 ] || { echo "usage: $0 LOADER [packet check arguments...]" >&2; exit 2; }
vng=${VNG:-vng}
command -v "$vng" >/dev/null || { echo "virtme-ng ($vng) is not installed" >&2; exit 1; }
release=$(uname -r)
limit=${VEER_GUEST_TIMEOUT:-300}
loader=$(realpath "$1")
shift
echo "kernel $release, $("$vng" --version 2>&1 | head -n 1)"
grep -E '^CONFIG_(VIRTIO_PCI|VIRTIO_MMIO|NET_9P_VIRTIO|9P_FS|VIRTIO_FS|TUN|VETH)=' "/boot/config-$release" 2>/dev/null || true

# The guest's shell runs this; every argument goes in single quotes. The pass
# marker is put together there, so the command echoed at boot cannot match it.
command="cd '$ROOT_DIR' && env PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1 python3 scripts/verify-kfuncs-packets.py --loader '$loader'"
for argument in "$@"; do
    command="$command '$argument'"
done
command="$command && printf '%s_%s\\n' VEER_GUEST PASSED"

log=$(mktemp)
trap 'rm -f "$log" "$log.status"' EXIT
# Soft lockups and stalls are reported sooner than by default, with every
# CPU's backtrace.
append="sysctl.kernel.softlockup_all_cpu_backtrace=1 sysctl.kernel.hung_task_timeout_secs=30 rcupdate.rcu_cpu_stall_timeout=15"
{
    status=0
    timeout --kill-after=15 "$limit" "$vng" --run "/boot/vmlinuz-$release" --cpus 2 --memory "${VEER_GUEST_MEMORY:-2G}" \
        --verbose --append "$append" --exec "$command" < /dev/null 2>&1 || status=$?
    echo "$status" > "$log.status"
} | tee "$log"
status=$(cat "$log.status" 2>/dev/null || echo unknown)
if grep -q 'VEER_GUEST_PASSED' "$log"; then
    echo "==> the checks passed in the guest"
    exit 0
fi
case $status in
124|137) echo "::error::the guest did not finish within ${limit}s; its console is above" ;;
*) echo "::error::the checks did not pass in the guest (vng status $status); its console is above" ;;
esac
exit 1
