#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

fail() {
	printf 'platform script verification failed: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_text() {
	file=$1
	text=$2
	grep -F -- "$text" "$file" >/dev/null 2>&1 || fail "$file is missing contract text: $text"
}

require_command bash
require_command grep

bash -n "$ROOT_DIR/bootstrap.sh"
bash -n "$ROOT_DIR/deploy.sh"
bash -n "$ROOT_DIR/release.sh"

for script in \
	"$ROOT_DIR/scripts/build-all-ebpf.sh" \
	"$ROOT_DIR/scripts/build-ebpf.sh" \
	"$ROOT_DIR/scripts/build-plugin-ebpf.sh" \
	"$ROOT_DIR/scripts/package-plugin-sdk.sh" \
	"$ROOT_DIR/scripts/package-plugins.sh" \
	"$ROOT_DIR/scripts/verify-plugin-manifests.sh" \
	"$ROOT_DIR/scripts/verify-plugin-release.sh" \
	"$ROOT_DIR/plugins/packet_observer/build.sh" \
	"$ROOT_DIR/plugins/pppoe_client/build.sh" \
	"$ROOT_DIR/plugins/pppoe_client/test-blackbox-linux.sh"
do
	sh -n "$script"
done

for distro_contract in \
	'Debian 11+' \
	'Ubuntu 22.04+' \
	'RHEL-compatible 9+' \
	'Fedora 38+' \
	'Alpine 3.19+'
do
	require_text "$ROOT_DIR/bootstrap.sh" "$distro_contract"
done

for package_manager in 'apt-get' 'dnf' 'yum' 'apk'; do
	require_text "$ROOT_DIR/bootstrap.sh" "$package_manager"
done

for dependency in 'iproute2' 'iproute' 'nftables' 'procps' 'procps-ng' 'util-linux' 'openrc'; do
	require_text "$ROOT_DIR/bootstrap.sh" "$dependency"
done

for service_contract in \
	'VEER_SERVICE_MANAGER' \
	'systemd' \
	'openrc' \
	'service_start()' \
	'service_stop()' \
	'service_restart()' \
	'service_enable()' \
	'service_disable()'
do
	require_text "$ROOT_DIR/deploy.sh" "$service_contract"
done

require_text "$ROOT_DIR/deploy.sh" 'Delegate=yes'
require_text "$ROOT_DIR/deploy.sh" 'ReadWritePaths=-/etc/network'
require_text "$ROOT_DIR/deploy.sh" 'ReadWritePaths=/sys/fs/cgroup'
for capability in \
	CAP_NET_BIND_SERVICE \
	CAP_NET_RAW \
	CAP_NET_ADMIN \
	CAP_BPF \
	CAP_PERFMON \
	CAP_SETUID \
	CAP_SETGID \
	CAP_KILL \
	CAP_SYS_CHROOT \
	CAP_SYS_ADMIN
do
	require_text "$ROOT_DIR/deploy.sh" "$capability"
done

require_text "$ROOT_DIR/deploy.sh" '#!/sbin/openrc-run'
require_text "$ROOT_DIR/deploy.sh" 'supervisor="supervise-daemon"'
require_text "$ROOT_DIR/deploy.sh" '/etc/sysctl.d/99-veer.conf'
require_text "$ROOT_DIR/deploy.sh" 'getenforce'
require_text "$ROOT_DIR/deploy.sh" 'systemd-analyze verify'
require_text "$ROOT_DIR/deploy.sh" 'check_host_network_persistence'

printf '%s\n' 'platform script verification passed'
