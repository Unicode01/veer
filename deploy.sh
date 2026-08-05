#!/usr/bin/env bash
#
# Veer - Linux 部署脚本
#
# 用法: 将 veer-linux-<arch> 与本脚本放在同一目录，然后:
#   chmod +x deploy.sh && sudo ./deploy.sh
#   chmod +x deploy.sh && sudo ./deploy.sh --no-inherit-stats
# 如需安装 bundled stable 插件，再放入 veer-plugins.tar.gz 并设置:
#   sudo env VEER_INSTALL_PLUGINS=1 ./deploy.sh
#
# 脚本会自动匹配当前系统架构查找二进制文件:
#   x86_64  => veer-linux-amd64
#   aarch64 => veer-linux-arm64
#
# 可选环境变量:
#   INSTALL_DIR   安装目录       (默认 /opt/veer)
#   READY_TIMEOUT_SECONDS /readyz 等待秒数 (默认 120)
#   WEB_BIND      Web 监听地址   (默认 127.0.0.1)
#   WEB_UI_ENABLED 是否启用 Web UI (默认 true)
#   WEB_PORT      Web 管理端口   (默认 8080)
#   WEB_TOKEN     Bearer Token，对应 config.json 的 web_token (默认随机生成；远程监听至少 24 个字符)
#   PLUGIN_ADMIN_TOKEN 插件高权限 Token，对应 plugin_admin_token (首次安装默认独立随机生成；远程监听至少 24 个字符)
#   VEER_SERVICE_MANAGER 服务管理器，auto/systemd/openrc，默认 auto
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

usage() {
    cat <<'EOF'
用法:
  sudo ./deploy.sh [--no-inherit-stats]

可选参数:
  --no-inherit-stats   热更新时不继承内核 stats_v4 统计表，流量统计从 0 重新累计，
                       但 flow / nat 等其它热更新状态仍尽量继承
  -h, --help           显示帮助

环境变量:
  READY_TIMEOUT_SECONDS  /readyz 就绪检查等待秒数，默认 120
  VEER_BPF_STATE_DIR      bpffs 状态目录，默认 /sys/fs/bpf/forward
  VEER_RUNTIME_STATE_DIR 热重启状态目录，默认 <INSTALL_DIR>/.kernel-state
  VEER_INSTALL_PLUGINS   设为 1 时安装 bundled stable 插件，默认 0
  VEER_PLUGIN_BUNDLE_PATH bundled plugin 包路径，默认与 deploy.sh 同目录的 veer-plugins.tar.gz
  VEER_SERVICE_MANAGER   服务管理器，auto/systemd/openrc，默认 auto

兼容性:
  FORWARD_BPF_STATE_DIR 和 FORWARD_RUNTIME_STATE_DIR 仍可使用；同时设置时 VEER_* 优先。
EOF
}

SKIP_HOT_RESTART_STATS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-inherit-stats)
            SKIP_HOT_RESTART_STATS=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "未知参数: $1（可用: --no-inherit-stats）"
            ;;
    esac
    shift
done

if [[ $EUID -ne 0 ]]; then
    fail "请使用 root 权限运行: sudo $0"
fi

WEB_BIND_EXPLICIT=0
[[ ${WEB_BIND+x} ]] && WEB_BIND_EXPLICIT=1
WEB_UI_ENABLED_EXPLICIT=0
[[ ${WEB_UI_ENABLED+x} ]] && WEB_UI_ENABLED_EXPLICIT=1
WEB_PORT_EXPLICIT=0
[[ ${WEB_PORT+x} ]] && WEB_PORT_EXPLICIT=1
WEB_TOKEN_EXPLICIT=0
[[ ${WEB_TOKEN+x} ]] && WEB_TOKEN_EXPLICIT=1
PLUGIN_ADMIN_TOKEN_EXPLICIT=0
[[ ${PLUGIN_ADMIN_TOKEN+x} ]] && PLUGIN_ADMIN_TOKEN_EXPLICIT=1
INSTALL_DIR_EXPLICIT=0
[[ ${INSTALL_DIR+x} ]] && INSTALL_DIR_EXPLICIT=1

# ---------- 变量 ----------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_INSTALL_DIR="/opt/veer"
LEGACY_INSTALL_DIR="/opt/forward"
INSTALL_DIR="${INSTALL_DIR:-${DEFAULT_INSTALL_DIR}}"
SERVICE_NAME="veer"
LEGACY_SERVICE_NAME="forward"
SERVICE_MANAGER="${VEER_SERVICE_MANAGER:-auto}"
SERVICE_FILE=""
LEGACY_SERVICE_FILE=""
CONFIG_TEMPLATE_PATH="${SCRIPT_DIR}/config.example.json"
READY_TIMEOUT_SECONDS="${READY_TIMEOUT_SECONDS:-120}"
WEB_PORT="${WEB_PORT:-8080}"
WEB_BIND="${WEB_BIND:-127.0.0.1}"
WEB_UI_ENABLED="${WEB_UI_ENABLED:-true}"
WEB_TOKEN="${WEB_TOKEN:-$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)}"
PLUGIN_ADMIN_TOKEN="${PLUGIN_ADMIN_TOKEN:-$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)}"
BPF_STATE_DIR="${VEER_BPF_STATE_DIR:-${FORWARD_BPF_STATE_DIR:-/sys/fs/bpf/forward}}"
RUNTIME_STATE_DIR="${VEER_RUNTIME_STATE_DIR:-${FORWARD_RUNTIME_STATE_DIR:-${INSTALL_DIR}/.kernel-state}}"
HOT_RESTART_MARKER="${INSTALL_DIR}/.hot-restart-kernel"
HOT_RESTART_SKIP_STATS_MARKER="${HOT_RESTART_MARKER}.skip-stats"
CONFIG_BACKUP_PATH="${INSTALL_DIR}/config.json.rollback"
BINARY_BACKUP_PATH="${INSTALL_DIR}/veer.rollback"
SERVICE_BACKUP_PATH=""
LEGACY_SERVICE_BACKUP_PATH=""
PLUGIN_BUNDLE_PATH="${VEER_PLUGIN_BUNDLE_PATH:-${SCRIPT_DIR}/veer-plugins.tar.gz}"
INSTALL_BUNDLED_PLUGINS="${VEER_INSTALL_PLUGINS:-0}"
PLUGIN_STAGING_DIR="${INSTALL_DIR}/.plugins.next.$$"
PLUGIN_BACKUP_DIR="${INSTALL_DIR}/.plugins.rollback"
PLUGIN_INSTALL_DIR=""
API_READY_URL=""
PRESERVE_HOT_RESTART_MARKERS_ON_EXIT=0
HAS_EXISTING_INSTALL=false
PREVIOUS_SERVICE_NAME=""
PREVIOUS_SERVICE_RUNNING=false
ORIGINAL_BINARY_NAME=""
CONFIG_BACKED_UP=false
BINARY_BACKED_UP=false
SERVICE_BACKED_UP=false
PLUGIN_BUNDLE_APPLIED=false
PLUGIN_INSTALL_EXISTED=false

case "${INSTALL_BUNDLED_PLUGINS}" in
    0|1)
        ;;
    *)
        fail "VEER_INSTALL_PLUGINS 仅支持 0 或 1，当前值: ${INSTALL_BUNDLED_PLUGINS}"
        ;;
esac

cleanup_hot_restart_marker() {
    if [[ "${PRESERVE_HOT_RESTART_MARKERS_ON_EXIT}" == "1" ]]; then
        return
    fi
    if [[ -n "${HOT_RESTART_MARKER:-}" ]]; then
        rm -f "${HOT_RESTART_MARKER}"
    fi
    if [[ -n "${HOT_RESTART_SKIP_STATS_MARKER:-}" ]]; then
        rm -f "${HOT_RESTART_SKIP_STATS_MARKER}"
    fi
}

trap cleanup_hot_restart_marker EXIT

normalize_bind_value() {
    local value="${1:-}"
    value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [[ "$value" == \[*\] && ${#value} -gt 2 ]]; then
        value="${value:1:${#value}-2}"
    fi
    if [[ -z "$value" ]]; then
        value="127.0.0.1"
    fi
    printf '%s' "$value"
}

normalize_bool_json() {
    local value="${1:-}"
    value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    case "$value" in
        1|true|yes|on)
            printf 'true'
            ;;
        0|false|no|off)
            printf 'false'
            ;;
        *)
            return 1
            ;;
    esac
}

require_python3() {
    command -v python3 >/dev/null 2>&1 || fail "deploy.sh 需要 python3 来读写 config.json"
}

require_runtime_command() {
    command -v "$1" >/dev/null 2>&1 || fail "部署环境缺少命令: $1"
}

detect_service_manager() {
    local requested="${SERVICE_MANAGER}"
    requested="$(printf '%s' "${requested}" | tr '[:upper:]' '[:lower:]')"
    case "${requested}" in
        auto)
            if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
                SERVICE_MANAGER="systemd"
            elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 && [[ -d /run/openrc ]]; then
                SERVICE_MANAGER="openrc"
            else
                fail "无法检测可用服务管理器；需要正在运行的 systemd 或 OpenRC，可用 VEER_SERVICE_MANAGER 显式指定"
            fi
            ;;
        systemd)
            command -v systemctl >/dev/null 2>&1 || fail "VEER_SERVICE_MANAGER=systemd 但未找到 systemctl"
            [[ -d /run/systemd/system ]] || fail "VEER_SERVICE_MANAGER=systemd 但 systemd 不是当前运行中的服务管理器"
            SERVICE_MANAGER="systemd"
            ;;
        openrc)
            command -v rc-service >/dev/null 2>&1 || fail "VEER_SERVICE_MANAGER=openrc 但未找到 rc-service"
            command -v rc-update >/dev/null 2>&1 || fail "VEER_SERVICE_MANAGER=openrc 但未找到 rc-update"
            [[ -d /run/openrc ]] || fail "VEER_SERVICE_MANAGER=openrc 但 OpenRC 运行时目录不可用"
            SERVICE_MANAGER="openrc"
            ;;
        *)
            fail "VEER_SERVICE_MANAGER 仅支持 auto/systemd/openrc，当前值: ${SERVICE_MANAGER}"
            ;;
    esac

    case "${SERVICE_MANAGER}" in
        systemd)
            SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
            LEGACY_SERVICE_FILE="/etc/systemd/system/${LEGACY_SERVICE_NAME}.service"
            ;;
        openrc)
            SERVICE_FILE="/etc/init.d/${SERVICE_NAME}"
            LEGACY_SERVICE_FILE="/etc/init.d/${LEGACY_SERVICE_NAME}"
            ;;
    esac
    SERVICE_BACKUP_PATH="${SERVICE_FILE}.rollback"
    LEGACY_SERVICE_BACKUP_PATH="${LEGACY_SERVICE_FILE}.rollback"
    ok "服务管理器: ${SERVICE_MANAGER}"
}

service_label() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        printf '%s.service' "$1"
    else
        printf '%s' "$1"
    fi
}

service_is_active() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl is-active --quiet "$1"
    else
        rc-service "$1" status >/dev/null 2>&1
    fi
}

service_is_failed() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl is-failed --quiet "$1"
        return $?
    fi
    return 1
}

service_start() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl start "$1"
    else
        rc-service "$1" start
    fi
}

service_stop() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl stop "$1"
    else
        rc-service "$1" stop
    fi
}

service_restart() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl restart "$1"
    else
        rc-service "$1" restart
    fi
}

service_enable() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl enable "$1"
    else
        rc-update add "$1" default
    fi
}

service_disable() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl disable "$1"
    else
        rc-update del "$1" default
    fi
}

service_reload_manager() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        systemctl daemon-reload
    fi
}

service_log_hint() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        printf 'journalctl -u %s -n 50 --no-pager' "$1"
    else
        printf 'tail -n 50 /var/log/%s.log' "$1"
    fi
}

write_service_definition() {
    case "${SERVICE_MANAGER}" in
        systemd)
            cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Veer Network Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
Environment=VEER_HOT_RESTART_MARKER=${HOT_RESTART_MARKER}
Environment=VEER_BPF_STATE_DIR=${BPF_STATE_DIR}
Environment=VEER_RUNTIME_STATE_DIR=${RUNTIME_STATE_DIR}
Environment=FORWARD_HOT_RESTART_MARKER=${HOT_RESTART_MARKER}
Environment=FORWARD_BPF_STATE_DIR=${BPF_STATE_DIR}
Environment=FORWARD_RUNTIME_STATE_DIR=${RUNTIME_STATE_DIR}
ExecStart=${INSTALL_DIR}/veer --config ${INSTALL_DIR}/config.json
Restart=always
RestartSec=3
KillMode=process
UMask=0077
Delegate=yes

NoNewPrivileges=false
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
ReadWritePaths=${RUNTIME_STATE_DIR}
ReadWritePaths=-/etc/network
ReadWritePaths=/tmp
ReadWritePaths=/sys/fs/bpf
ReadWritePaths=${BPF_STATE_DIR}
ReadWritePaths=/sys/fs/cgroup
PrivateTmp=true

AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_CHROOT CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_CHROOT CAP_SYS_ADMIN

StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

LimitNOFILE=65535
LimitNPROC=4096
LimitMEMLOCK=infinity
TasksMax=4096

[Install]
WantedBy=multi-user.target
EOF
            ;;
        openrc)
            cat > "${SERVICE_FILE}" <<EOF
#!/sbin/openrc-run

description="Veer Network Service"
command="${INSTALL_DIR}/veer"
command_args="--config ${INSTALL_DIR}/config.json"
directory="${INSTALL_DIR}"
supervisor="supervise-daemon"
respawn_delay=3
respawn_max=0
output_log="/var/log/${SERVICE_NAME}.log"
error_log="/var/log/${SERVICE_NAME}.log"
umask=0077

export VEER_HOT_RESTART_MARKER="${HOT_RESTART_MARKER}"
export VEER_BPF_STATE_DIR="${BPF_STATE_DIR}"
export VEER_RUNTIME_STATE_DIR="${RUNTIME_STATE_DIR}"
export FORWARD_HOT_RESTART_MARKER="${HOT_RESTART_MARKER}"
export FORWARD_BPF_STATE_DIR="${BPF_STATE_DIR}"
export FORWARD_RUNTIME_STATE_DIR="${RUNTIME_STATE_DIR}"

depend() {
    need net
    after firewall
}
EOF
            chmod 755 "${SERVICE_FILE}"
            ;;
    esac
}

validate_service_definition() {
    if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
        if command -v systemd-analyze >/dev/null 2>&1; then
            systemd-analyze verify "${SERVICE_FILE}" >/dev/null || fail "systemd unit 校验失败: ${SERVICE_FILE}"
        fi
        return
    fi
    /bin/sh -n "${SERVICE_FILE}" || fail "OpenRC runscript 语法校验失败: ${SERVICE_FILE}"
}

check_cgroup_v2() {
    local controllers=""
    local missing=()
    local controller=""
    if [[ ! -r /sys/fs/cgroup/cgroup.controllers ]]; then
        warn "未检测到 cgroup v2；Veer 核心可运行，但默认 full 插件沙箱会拒绝启动"
        return
    fi
    controllers="$(< /sys/fs/cgroup/cgroup.controllers)"
    for controller in cpu memory pids; do
        if [[ " ${controllers} " != *" ${controller} "* ]]; then
            missing+=("${controller}")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        warn "cgroup v2 缺少插件沙箱 controller: ${missing[*]}"
    else
        ok "cgroup v2 插件 controller 已就绪: cpu memory pids"
    fi
}

check_host_network_persistence() {
    if [[ -f /etc/network/interfaces ]]; then
        ok "检测到 ifupdown 网络配置: /etc/network/interfaces"
        return
    fi
    if command -v nmcli >/dev/null 2>&1; then
        warn "宿主网络由 NetworkManager 管理；Veer 核心与运行时桥可用，但'持久化桥'操作仅支持 /etc/network/interfaces，请使用 nmcli 持久化宿主桥"
        return
    fi
    if command -v networkctl >/dev/null 2>&1; then
        warn "宿主网络可能由 systemd-networkd 管理；Veer 核心与运行时桥可用，但'持久化桥'操作仅支持 /etc/network/interfaces，请使用 networkd 配置持久化宿主桥"
        return
    fi
    warn "未检测到 /etc/network/interfaces；Veer 核心与运行时桥可用，但'持久化桥'操作需要由宿主网络管理器完成"
}

prepare_selinux_labels() {
    local mode=""
    if ! command -v getenforce >/dev/null 2>&1; then
        return
    fi
    mode="$(getenforce 2>/dev/null || true)"
    case "${mode}" in
        Enforcing|Permissive)
            if command -v restorecon >/dev/null 2>&1; then
                restorecon -F "${INSTALL_DIR}/veer" "${SERVICE_FILE}" >/dev/null 2>&1 || \
                    warn "SELinux 标签恢复失败；若服务无法启动请检查 AVC 日志"
            else
                warn "检测到 SELinux ${mode}，但未找到 restorecon"
            fi
            if [[ "${mode}" == "Enforcing" ]]; then
                info "SELinux enforcing 已启用；部署将以 readyz 验证实际策略，失败时不会自动关闭 SELinux"
            fi
            ;;
    esac
}

secure_private_file() {
    local path="$1"
    if [[ -L "${path}" ]]; then
        fail "敏感文件不能是符号链接: ${path}"
    fi
    if [[ ! -e "${path}" ]]; then
        return
    fi
    if [[ ! -f "${path}" ]]; then
        fail "敏感路径不是普通文件: ${path}"
    fi
    chown root:root "${path}"
    chmod 600 "${path}"
}

secure_runtime_secret_files() {
    secure_private_file "${INSTALL_DIR}/config.json"
    secure_private_file "${CONFIG_BACKUP_PATH}"
    secure_private_file "${INSTALL_DIR}/forward.db"
    secure_private_file "${INSTALL_DIR}/forward.db-wal"
    secure_private_file "${INSTALL_DIR}/forward.db-shm"
}

validate_deploy_paths() {
    python3 - "${INSTALL_DIR}" "${BPF_STATE_DIR}" "${RUNTIME_STATE_DIR}" <<'PY'
import os
import re
import sys

safe_path = re.compile(r"^/[A-Za-z0-9._/+:-]+$")
critical = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
    "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys",
    "/tmp", "/usr", "/var", "/var/tmp",
}

for label, value in zip(("INSTALL_DIR", "VEER_BPF_STATE_DIR", "VEER_RUNTIME_STATE_DIR"), sys.argv[1:]):
    if not safe_path.fullmatch(value) or value.startswith("//") or os.path.normpath(value) != value:
        raise SystemExit(f"{label} must be a normalized absolute path without whitespace or control characters: {value!r}")
    if value in critical:
        raise SystemExit(f"refusing system directory for {label}: {value}")
    if os.path.islink(value):
        raise SystemExit(f"{label} cannot be a symbolic link: {value}")
    if os.path.exists(value) and not os.path.isdir(value):
        raise SystemExit(f"{label} is not a directory: {value}")
    resolved = os.path.realpath(value)
    if resolved in critical:
        raise SystemExit(f"refusing {label} resolving to system directory: {value} -> {resolved}")
PY
}

safe_remove_install_path() {
    local path="${1:-}"
    [[ -n "${path}" ]] || return 0
    case "${path}" in
        "${INSTALL_DIR}"/*)
            rm -rf -- "${path}"
            ;;
        *)
            fail "拒绝清理安装目录之外的路径: ${path}"
            ;;
    esac
}

validate_plugin_install_dir() {
    python3 - "${INSTALL_DIR}" "$1" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).absolute()
target = pathlib.Path(sys.argv[2]).absolute()
real_root = pathlib.Path(os.path.realpath(root))
real_target = pathlib.Path(os.path.realpath(target))
try:
    relative = target.relative_to(root)
    real_target.relative_to(real_root)
except ValueError:
    raise SystemExit(f"plugin install directory escapes INSTALL_DIR: {target}")
if not relative.parts:
    raise SystemExit("plugin install directory cannot equal INSTALL_DIR")

current = root
for part in relative.parts:
    current /= part
    if current.is_symlink():
        raise SystemExit(f"plugin install path cannot contain symlinks: {current}")
PY
}

validate_port() {
    local value="${1:-}"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        fail "WEB_PORT 必须是 1-65535 的整数，当前值: ${value:-<empty>}"
    fi
    if (( value < 1 || value > 65535 )); then
        fail "WEB_PORT 必须是 1-65535 的整数，当前值: ${value}"
    fi
}

validate_positive_integer() {
    local name="$1"
    local value="${2:-}"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        fail "${name} 必须是大于 0 的整数，当前值: ${value:-<empty>}"
    fi
    if (( value < 1 )); then
        fail "${name} 必须是大于 0 的整数，当前值: ${value}"
    fi
}

is_loopback_bind() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "${value}" == \[*\] && "${#value}" -gt 2 ]]; then
        value="${value:1:${#value}-2}"
    fi
    case "${value,,}" in
        ""|::1|localhost|localhost.)
            return 0
            ;;
    esac
    if [[ "${value}" =~ ^127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] &&
        (( 10#${BASH_REMATCH[1]} <= 255 && 10#${BASH_REMATCH[2]} <= 255 && 10#${BASH_REMATCH[3]} <= 255 )); then
        return 0
    fi
    return 1
}

probe_host_for_bind() {
    case "${1:-}" in
        ""|0.0.0.0)
            printf '127.0.0.1'
            ;;
        ::)
            printf '::1'
            ;;
        *)
            printf '%s' "$1"
            ;;
    esac
}

format_url_host() {
    local host="${1:-}"
    if [[ "$host" == *:* && "$host" != \[*\] ]]; then
        printf '[%s]' "$host"
        return
    fi
    printf '%s' "$host"
}

compute_ready_url() {
    local probe_host
    probe_host="$(probe_host_for_bind "$1")"
    printf 'http://%s:%s/readyz' "$(format_url_host "$probe_host")" "$2"
}

http_probe_available() {
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1
}

http_probe() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 2 "$url" >/dev/null 2>&1
        return $?
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q -T 2 -O /dev/null "$url"
        return $?
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$url" <<'PY'
import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1], timeout=2) as resp:
    if resp.status < 200 or resp.status >= 300:
        raise SystemExit(1)
PY
        return $?
    fi
    return 127
}

wait_for_service_ready() {
    local ready_url="$1"
    local timeout_seconds="${2:-${READY_TIMEOUT_SECONDS}}"
    local service_name="${3:-${SERVICE_NAME}}"
    local deadline=$((SECONDS + timeout_seconds))

    if ! http_probe_available; then
        warn "未检测到 curl/wget/python3，跳过 /readyz HTTP 检查，仅验证服务状态"
        sleep 2
        service_is_active "$service_name"
        return $?
    fi

    while (( SECONDS < deadline )); do
        if service_is_failed "$service_name"; then
            return 1
        fi
        if http_probe "$ready_url"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

validate_positive_integer "READY_TIMEOUT_SECONDS" "${READY_TIMEOUT_SECONDS}"

prepare_legacy_installation() {
    if [[ "${INSTALL_DIR_EXPLICIT}" == "1" || "${INSTALL_DIR}" != "${DEFAULT_INSTALL_DIR}" ]]; then
        return
    fi

    if [[ -e "${DEFAULT_INSTALL_DIR}" || -L "${DEFAULT_INSTALL_DIR}" ]]; then
        if [[ -d "${LEGACY_INSTALL_DIR}" && ! -L "${LEGACY_INSTALL_DIR}" ]]; then
            fail "同时检测到 ${DEFAULT_INSTALL_DIR} 和旧目录 ${LEGACY_INSTALL_DIR}，拒绝自动合并；请先确认有效安装"
        fi
        return
    fi

    if [[ ! -d "${LEGACY_INSTALL_DIR}" || -L "${LEGACY_INSTALL_DIR}" ]]; then
        return
    fi

    info "检测到旧版安装目录 ${LEGACY_INSTALL_DIR}，迁移到 ${DEFAULT_INSTALL_DIR}..."
    mv "${LEGACY_INSTALL_DIR}" "${DEFAULT_INSTALL_DIR}"
    ln -s "${DEFAULT_INSTALL_DIR}" "${LEGACY_INSTALL_DIR}"
    ok "旧版安装目录已迁移，并保留 ${LEGACY_INSTALL_DIR} 兼容入口"
}

backup_existing_installation() {
    if [[ -f "${INSTALL_DIR}/config.json" ]]; then
        rm -f "${CONFIG_BACKUP_PATH}"
        install -m 600 "${INSTALL_DIR}/config.json" "${CONFIG_BACKUP_PATH}"
        CONFIG_BACKED_UP=true
    fi
    if [[ -f "${INSTALL_DIR}/veer" && ! -L "${INSTALL_DIR}/veer" ]]; then
        cp -f "${INSTALL_DIR}/veer" "${BINARY_BACKUP_PATH}"
        ORIGINAL_BINARY_NAME="veer"
        BINARY_BACKED_UP=true
        ok "已备份当前版本到 ${BINARY_BACKUP_PATH}"
    elif [[ -f "${INSTALL_DIR}/forward" && ! -L "${INSTALL_DIR}/forward" ]]; then
        cp -f "${INSTALL_DIR}/forward" "${BINARY_BACKUP_PATH}"
        ORIGINAL_BINARY_NAME="forward"
        BINARY_BACKED_UP=true
        ok "已备份当前版本到 ${BINARY_BACKUP_PATH}"
    fi
    if [[ -f "${SERVICE_FILE}" ]]; then
        cp -f "${SERVICE_FILE}" "${SERVICE_BACKUP_PATH}"
        SERVICE_BACKED_UP=true
    fi
    if [[ -f "${LEGACY_SERVICE_FILE}" && ! -L "${LEGACY_SERVICE_FILE}" ]]; then
        cp -f "${LEGACY_SERVICE_FILE}" "${LEGACY_SERVICE_BACKUP_PATH}"
    fi
}

configure_plugin_install_dir() {
    local configured="${PLUGINS_DIR:-plugins}"
    case "${configured}" in
        ""|.|/*|..|../*|*/..|*/../*)
            PLUGIN_INSTALL_DIR=""
            warn "plugins_dir=${configured:-<empty>} 不在安装目录内，无法安装 bundled plugins"
            return
            ;;
    esac
    if [[ ! "${configured}" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]]; then
        PLUGIN_INSTALL_DIR=""
        warn "plugins_dir=${configured} 含有不安全字符，无法安装 bundled plugins"
        return
    fi
    PLUGIN_INSTALL_DIR="${INSTALL_DIR}/${configured%/}"
    if ! validate_plugin_install_dir "${PLUGIN_INSTALL_DIR}"; then
        PLUGIN_INSTALL_DIR=""
        warn "plugins_dir=${configured} 未通过安装路径边界检查"
    fi
}

restore_bundled_plugins() {
    if [[ "${PLUGIN_BUNDLE_APPLIED}" != "true" || -z "${PLUGIN_INSTALL_DIR}" ]]; then
        return
    fi
    safe_remove_install_path "${PLUGIN_INSTALL_DIR}"
    if [[ "${PLUGIN_INSTALL_EXISTED}" == "true" && -d "${PLUGIN_BACKUP_DIR}" ]]; then
        mv "${PLUGIN_BACKUP_DIR}" "${PLUGIN_INSTALL_DIR}"
    fi
    PLUGIN_BUNDLE_APPLIED=false
}

install_bundled_plugins() {
    local source=""
    local name=""
    local replacement=""

    if [[ "${INSTALL_BUNDLED_PLUGINS}" != "1" ]]; then
        info "默认不安装 bundled plugins，现有插件目录保持不变"
        return
    fi
    if [[ ! -f "${PLUGIN_BUNDLE_PATH}" ]]; then
        warn "VEER_INSTALL_PLUGINS=1，但未找到插件包: ${PLUGIN_BUNDLE_PATH}"
        return 1
    fi
    if [[ -z "${PLUGIN_INSTALL_DIR}" ]]; then
        return 1
    fi

    safe_remove_install_path "${PLUGIN_STAGING_DIR}"
    mkdir -p "${PLUGIN_STAGING_DIR}"
    if ! python3 - "${PLUGIN_BUNDLE_PATH}" "${PLUGIN_STAGING_DIR}" <<'PY'
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive_path = Path(sys.argv[1])
target = Path(sys.argv[2])

with tarfile.open(archive_path, "r:gz") as archive:
    members = []
    seen = set()
    total_size = 0
    for member in archive:
        members.append(member)
        if len(members) > 4096:
            raise SystemExit("plugin bundle contains too many entries")
        path = PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or path.parts[0] != "plugins" or ".." in path.parts:
            raise SystemExit(f"unsafe plugin bundle path: {member.name}")
        normalized = path.as_posix()
        if normalized in seen:
            raise SystemExit(f"duplicate plugin bundle path: {member.name}")
        seen.add(normalized)
        if member.issym() or member.islnk() or member.isdev():
            raise SystemExit(f"unsupported plugin bundle entry: {member.name}")
        if not member.isdir() and not member.isfile():
            raise SystemExit(f"unsupported plugin bundle entry type: {member.name}")
        if member.isfile():
            if member.size < 0 or member.size > 64 * 1024 * 1024:
                raise SystemExit(f"plugin bundle entry is too large: {member.name}")
            total_size += member.size
            if total_size > 256 * 1024 * 1024:
                raise SystemExit("plugin bundle expands beyond 256 MiB")
        member.mode = 0o755 if member.isdir() else 0o644
        member.uid = member.gid = 0
        member.uname = member.gname = "root"
    archive.extractall(target, members=members)

plugin_root = target / "plugins"
if not plugin_root.is_dir():
    raise SystemExit("plugin bundle does not contain plugins/")

count = 0
for child in plugin_root.iterdir():
    if child.name == "include":
        if not child.is_dir():
            raise SystemExit("plugins/include must be a directory")
        continue
    if not child.is_dir() or not (child / "plugin.json").is_file():
        raise SystemExit(f"invalid bundled plugin entry: {child.name}")
    with (child / "plugin.json").open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("id") != child.name:
        raise SystemExit(f"plugin directory/id mismatch: {child.name}")
    count += 1
if count == 0:
    raise SystemExit("plugin bundle contains no plugins")
PY
    then
        safe_remove_install_path "${PLUGIN_STAGING_DIR}"
        return 1
    fi

    safe_remove_install_path "${PLUGIN_BACKUP_DIR}"
    if [[ -d "${PLUGIN_INSTALL_DIR}" ]]; then
        cp -a "${PLUGIN_INSTALL_DIR}" "${PLUGIN_BACKUP_DIR}" || {
            safe_remove_install_path "${PLUGIN_STAGING_DIR}"
            safe_remove_install_path "${PLUGIN_BACKUP_DIR}"
            return 1
        }
        PLUGIN_INSTALL_EXISTED=true
    else
        PLUGIN_INSTALL_EXISTED=false
    fi

    mkdir -p "${PLUGIN_INSTALL_DIR}"
    PLUGIN_BUNDLE_APPLIED=true
    for source in "${PLUGIN_STAGING_DIR}/plugins"/*; do
        [[ -e "${source}" ]] || continue
        name="$(basename "${source}")"
        replacement="${PLUGIN_INSTALL_DIR}/.${name}.next.$$"
        safe_remove_install_path "${replacement}"
        cp -a "${source}" "${replacement}" || {
            safe_remove_install_path "${PLUGIN_STAGING_DIR}"
            safe_remove_install_path "${replacement}"
            restore_bundled_plugins
            return 1
        }
        safe_remove_install_path "${PLUGIN_INSTALL_DIR:?}/${name}"
        mv "${replacement}" "${PLUGIN_INSTALL_DIR}/${name}" || {
            safe_remove_install_path "${PLUGIN_STAGING_DIR}"
            safe_remove_install_path "${replacement}"
            restore_bundled_plugins
            return 1
        }
    done
    safe_remove_install_path "${PLUGIN_STAGING_DIR}"
    ok "bundled plugins 已更新到 ${PLUGIN_INSTALL_DIR}"
}

sync_config_file() {
    local config_path="$1"
    local missing_bind_default="$2"

    FORWARD_DEPLOY_CONFIG_TEMPLATE_PATH="${CONFIG_TEMPLATE_PATH}" \
    FORWARD_DEPLOY_DEFAULT_WEB_BIND="${missing_bind_default}" \
    FORWARD_DEPLOY_DEFAULT_WEB_UI_ENABLED="true" \
    FORWARD_DEPLOY_DEFAULT_WEB_PORT="${WEB_PORT}" \
    FORWARD_DEPLOY_DEFAULT_WEB_TOKEN="${WEB_TOKEN}" \
    FORWARD_DEPLOY_DEFAULT_PLUGIN_ADMIN_TOKEN="${PLUGIN_ADMIN_TOKEN}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_BIND="${WEB_BIND_EXPLICIT}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_UI_ENABLED="${WEB_UI_ENABLED_EXPLICIT}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_PORT="${WEB_PORT_EXPLICIT}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_TOKEN="${WEB_TOKEN_EXPLICIT}" \
    FORWARD_DEPLOY_EXPLICIT_PLUGIN_ADMIN_TOKEN="${PLUGIN_ADMIN_TOKEN_EXPLICIT}" \
    FORWARD_DEPLOY_WEB_BIND="${WEB_BIND}" \
    FORWARD_DEPLOY_WEB_UI_ENABLED="${WEB_UI_ENABLED}" \
    FORWARD_DEPLOY_WEB_PORT="${WEB_PORT}" \
    FORWARD_DEPLOY_WEB_TOKEN="${WEB_TOKEN}" \
    FORWARD_DEPLOY_PLUGIN_ADMIN_TOKEN="${PLUGIN_ADMIN_TOKEN}" \
    python3 - "$config_path" <<'PY'
from collections import OrderedDict
import ipaddress
import json
import os
import sys
import unicodedata

PLACEHOLDER_WEB_TOKEN = "change-me-to-a-secure-token"
REMOTE_MANAGEMENT_MINIMUM_TOKEN_CHARACTERS = 24

config_path = sys.argv[1]
config_exists = os.path.exists(config_path)


def load_json_object(path: str, label: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f, object_pairs_hook=OrderedDict)
    except FileNotFoundError:
        return OrderedDict()
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label} 不是合法 JSON: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"{label} 顶层必须是 JSON object")
    return OrderedDict(data)


current = load_json_object(config_path, "config.json") if config_exists else OrderedDict()
template_path = os.environ.get("FORWARD_DEPLOY_CONFIG_TEMPLATE_PATH", "")
template_defaults = OrderedDict()
if template_path and os.path.exists(template_path):
    template_defaults = load_json_object(template_path, template_path)


def env_bool(name: str) -> bool:
    value = os.environ[name]
    if value == "true":
        return True
    if value == "false":
        return False
    raise SystemExit(f"{name} 必须是 true 或 false")


def env_int(name: str) -> int:
    return int(os.environ[name])


def get_current_string(key: str):
    if key not in current or current[key] is None:
        return None
    value = current[key]
    if not isinstance(value, str):
        raise SystemExit(f"config.json 中的 {key} 必须是字符串")
    return value


def get_current_bool(key: str):
    if key not in current or current[key] is None:
        return None
    value = current[key]
    if not isinstance(value, bool):
        raise SystemExit(f"config.json 中的 {key} 必须是布尔值")
    return value


def get_current_port(key: str):
    if key not in current or current[key] is None:
        return None
    value = current[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise SystemExit(f"config.json 中的 {key} 必须是整数")
    if value < 1 or value > 65535:
        raise SystemExit(f"config.json 中的 {key} 必须在 1-65535 之间")
    return value


def choose_value(key: str, default_value):
    if explicit_keys.get(key, False):
        return explicit_values[key]
    if key == "web_bind":
        value = get_current_string(key)
    elif key == "web_ui_enabled":
        value = get_current_bool(key)
    elif key == "web_port":
        value = get_current_port(key)
    elif key == "web_token":
        value = get_current_string(key)
        if value is not None and value == "":
            raise SystemExit("config.json 中的 web_token 不能为空")
    elif key == "plugin_admin_token":
        value = get_current_string(key)
    else:
        value = current.get(key)
        if value is None:
            return default_value
    if value is None:
        return default_value
    return value


explicit_keys = {
    "web_bind": os.environ["FORWARD_DEPLOY_EXPLICIT_WEB_BIND"] == "1",
    "web_ui_enabled": os.environ["FORWARD_DEPLOY_EXPLICIT_WEB_UI_ENABLED"] == "1",
    "web_port": os.environ["FORWARD_DEPLOY_EXPLICIT_WEB_PORT"] == "1",
    "web_token": os.environ["FORWARD_DEPLOY_EXPLICIT_WEB_TOKEN"] == "1",
    "plugin_admin_token": os.environ["FORWARD_DEPLOY_EXPLICIT_PLUGIN_ADMIN_TOKEN"] == "1",
}

explicit_values = {
    "web_bind": os.environ["FORWARD_DEPLOY_WEB_BIND"],
    "web_ui_enabled": env_bool("FORWARD_DEPLOY_WEB_UI_ENABLED"),
    "web_port": env_int("FORWARD_DEPLOY_WEB_PORT"),
    "web_token": os.environ["FORWARD_DEPLOY_WEB_TOKEN"],
    "plugin_admin_token": os.environ["FORWARD_DEPLOY_PLUGIN_ADMIN_TOKEN"],
}

hardcoded_defaults = OrderedDict([
    ("web_bind", os.environ["FORWARD_DEPLOY_DEFAULT_WEB_BIND"]),
    ("web_ui_enabled", env_bool("FORWARD_DEPLOY_DEFAULT_WEB_UI_ENABLED")),
    ("web_port", env_int("FORWARD_DEPLOY_DEFAULT_WEB_PORT")),
    ("web_token", os.environ["FORWARD_DEPLOY_DEFAULT_WEB_TOKEN"]),
    ("plugin_admin_token", os.environ["FORWARD_DEPLOY_DEFAULT_PLUGIN_ADMIN_TOKEN"]),
    ("max_workers", 0),
    ("drain_timeout_hours", 24),
    ("managed_network_auto_repair", True),
    ("plugins_enabled", False),
    ("plugins_dataplane_enabled", False),
    ("plugins_isolation", True),
    ("plugins_min_sandbox_level", "full"),
    ("plugins_require_signed_packages", True),
    ("plugins_dir", "plugins"),
    ("default_engine", "auto"),
    ("kernel_engine_order", ["tc"]),
    ("kernel_rules_map_limit", 0),
    ("kernel_flows_map_limit", 0),
    ("kernel_nat_ports_map_limit", 0),
    ("kernel_nat_port_min", 20000),
    ("kernel_nat_port_max", 65535),
    ("experimental_features", OrderedDict([
        ("bridge_xdp", False),
        ("xdp_generic", False),
        ("kernel_traffic_stats", False),
        ("kernel_tc_diag", False),
        ("kernel_tc_diag_verbose", False),
    ])),
    ("tags", []),
])

defaults = OrderedDict(hardcoded_defaults)
for key, value in template_defaults.items():
    defaults[key] = value
defaults["web_bind"] = os.environ["FORWARD_DEPLOY_DEFAULT_WEB_BIND"]
defaults["web_ui_enabled"] = env_bool("FORWARD_DEPLOY_DEFAULT_WEB_UI_ENABLED")
defaults["web_port"] = env_int("FORWARD_DEPLOY_DEFAULT_WEB_PORT")
defaults["web_token"] = os.environ["FORWARD_DEPLOY_DEFAULT_WEB_TOKEN"]
defaults["plugin_admin_token"] = os.environ["FORWARD_DEPLOY_DEFAULT_PLUGIN_ADMIN_TOKEN"]

result = OrderedDict()
for key, default_value in defaults.items():
    result[key] = choose_value(key, default_value)

if result["web_token"] == "":
    raise SystemExit("web_token 不能为空")
if result["web_token"] == PLACEHOLDER_WEB_TOKEN:
    if config_exists and not explicit_keys["web_token"]:
        raise SystemExit(
            "现有 config.json 仍使用示例占位 web_token，请先修改 config.json，"
            "或在部署时通过 WEB_TOKEN=... 覆盖"
        )
    raise SystemExit("web_token 不能使用示例占位值 change-me-to-a-secure-token")
if result.get("plugin_admin_token", "") == result["web_token"]:
    raise SystemExit("plugin_admin_token 必须与 web_token 不同")


def validate_management_token(name: str, value: str):
    if any(character.isspace() or unicodedata.category(character) == "Cc" for character in value):
        raise SystemExit(f"{name} 不能包含空白或控制字符")


def bind_exposes_remote_clients(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value.startswith("[") and value.endswith("]") and len(value) > 2:
        value = value[1:-1]
    if value.lower() in ("localhost", "localhost."):
        return False
    try:
        return not ipaddress.ip_address(value).is_loopback
    except ValueError:
        return True


validate_management_token("web_token", result["web_token"])
if result.get("plugin_admin_token", ""):
    validate_management_token("plugin_admin_token", result["plugin_admin_token"])
if bind_exposes_remote_clients(result["web_bind"]):
    if len(result["web_token"]) < REMOTE_MANAGEMENT_MINIMUM_TOKEN_CHARACTERS:
        raise SystemExit(
            f"web_bind 暴露远程管理面时，web_token 至少需要 {REMOTE_MANAGEMENT_MINIMUM_TOKEN_CHARACTERS} 个字符"
        )
    if result.get("plugin_admin_token", "") and len(result["plugin_admin_token"]) < REMOTE_MANAGEMENT_MINIMUM_TOKEN_CHARACTERS:
        raise SystemExit(
            f"web_bind 暴露远程管理面时，plugin_admin_token 至少需要 {REMOTE_MANAGEMENT_MINIMUM_TOKEN_CHARACTERS} 个字符"
        )

for key, value in current.items():
    if key not in result:
        result[key] = value

with open(config_path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
}

load_config_runtime_values() {
    local config_path="$1"
    python3 - "$config_path" <<'PY'
import json
import shlex
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

values = {
    "WEB_BIND": str(data.get("web_bind", "127.0.0.1")),
    "WEB_UI_ENABLED": "true" if data.get("web_ui_enabled", True) else "false",
    "WEB_PORT": str(data.get("web_port", 8080)),
    "WEB_TOKEN": str(data.get("web_token", "")),
	"PLUGIN_ADMIN_TOKEN": str(data.get("plugin_admin_token", "")),
    "PLUGINS_DIR": str(data.get("plugins_dir", "plugins")),
}

for key, value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
}

log_explicit_config_overrides() {
    local overrides=""
    if [[ "${WEB_BIND_EXPLICIT}" == "1" ]]; then
        overrides="${overrides} web_bind"
    fi
    if [[ "${WEB_UI_ENABLED_EXPLICIT}" == "1" ]]; then
        overrides="${overrides} web_ui_enabled"
    fi
    if [[ "${WEB_PORT_EXPLICIT}" == "1" ]]; then
        overrides="${overrides} web_port"
    fi
    if [[ "${WEB_TOKEN_EXPLICIT}" == "1" ]]; then
        overrides="${overrides} web_token"
    fi
	if [[ "${PLUGIN_ADMIN_TOKEN_EXPLICIT}" == "1" ]]; then
		overrides="${overrides} plugin_admin_token"
	fi
    overrides="$(printf '%s' "$overrides" | sed 's/^[[:space:]]*//')"
    if [[ -n "$overrides" ]]; then
        info "本次部署通过环境变量覆盖配置项: ${overrides}"
    fi
}

rollback_update() {
    local reason="$1"
    local rollback_ready_url="${API_READY_URL}"

    warn "${reason}"
    if [[ "${BINARY_BACKED_UP}" != "true" || ! -f "${BINARY_BACKUP_PATH}" ]]; then
        fail "部署失败，且未找到本次部署生成的旧版本备份；查看日志: $(service_log_hint "${SERVICE_NAME}")"
    fi

    warn "开始回滚到上一版本..."
    service_stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
    if [[ "${PREVIOUS_SERVICE_NAME}" != "${SERVICE_NAME}" ]]; then
        service_disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi

    if [[ "${CONFIG_BACKED_UP}" == "true" && -f "${CONFIG_BACKUP_PATH}" ]]; then
        rm -f "${INSTALL_DIR}/config.json"
        install -m 600 "${CONFIG_BACKUP_PATH}" "${INSTALL_DIR}/config.json"
    fi
    restore_bundled_plugins

    rm -f "${INSTALL_DIR}/veer"
    if [[ "${ORIGINAL_BINARY_NAME}" == "veer" ]]; then
        cp -f "${BINARY_BACKUP_PATH}" "${INSTALL_DIR}/veer"
        chmod 755 "${INSTALL_DIR}/veer"
    elif [[ "${ORIGINAL_BINARY_NAME}" == "forward" && ! -f "${INSTALL_DIR}/forward" ]]; then
        cp -f "${BINARY_BACKUP_PATH}" "${INSTALL_DIR}/forward"
        chmod 755 "${INSTALL_DIR}/forward"
    fi

    if [[ "${SERVICE_BACKED_UP}" == "true" && -f "${SERVICE_BACKUP_PATH}" ]]; then
        cp -f "${SERVICE_BACKUP_PATH}" "${SERVICE_FILE}"
    else
        rm -f "${SERVICE_FILE}"
    fi
    service_reload_manager

    if [[ "${PREVIOUS_SERVICE_RUNNING}" != "true" || -z "${PREVIOUS_SERVICE_NAME}" ]]; then
        fail "新版本部署失败，文件已回滚；部署前服务未运行，因此未自动启动旧版本"
    fi

    if ! service_restart "${PREVIOUS_SERVICE_NAME}"; then
        PRESERVE_HOT_RESTART_MARKERS_ON_EXIT=1
        fail "回滚后的服务重启失败；查看日志: $(service_log_hint "${PREVIOUS_SERVICE_NAME}")"
    fi
    if [[ -f "${INSTALL_DIR}/config.json" ]]; then
        if rollback_env="$(load_config_runtime_values "${INSTALL_DIR}/config.json")"; then
            eval "${rollback_env}"
            rollback_ready_url="$(compute_ready_url "$WEB_BIND" "$WEB_PORT")"
        else
            warn "回滚配置解析失败，继续使用当前 readyz 探针"
        fi
    fi
    info "等待回滚后的服务通过 readyz 检查（超时 ${READY_TIMEOUT_SECONDS}s）..."
    if wait_for_service_ready "${rollback_ready_url}" "${READY_TIMEOUT_SECONDS}" "${PREVIOUS_SERVICE_NAME}"; then
        fail "新版本部署失败，已自动回滚到上一版本"
    fi
    PRESERVE_HOT_RESTART_MARKERS_ON_EXIT=1
    fail "新版本部署失败，且回滚后的服务未能通过 readyz；查看日志: $(service_log_hint "${PREVIOUS_SERVICE_NAME}")"
}

# ---------- 按架构查找二进制 ----------
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *)       fail "不支持的架构: $ARCH" ;;
esac

BINARY_PATH=""
for candidate in \
    "${SCRIPT_DIR}/veer-linux-${GOARCH}" \
    "${SCRIPT_DIR}/veer" \
    "${SCRIPT_DIR}/forward-linux-${GOARCH}" \
    "${SCRIPT_DIR}/forward" \
; do
    if [[ -f "$candidate" ]]; then
        BINARY_PATH="$candidate"
        break
    fi
done

if [[ -z "$BINARY_PATH" ]]; then
    fail "未找到二进制文件，需要以下任一文件与本脚本同目录:\n       veer-linux-${GOARCH}\n       veer\n       forward-linux-${GOARCH}（旧名兼容）\n       forward（旧名兼容）"
fi

FILE_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
ok "找到二进制: $(basename "$BINARY_PATH") (${FILE_SIZE}) [${ARCH}]"

require_python3
for command_name in install mount mountpoint sysctl ip readlink; do
    require_runtime_command "${command_name}"
done
detect_service_manager
if [[ "${SERVICE_MANAGER}" == "openrc" ]]; then
    require_runtime_command supervise-daemon
fi
validate_deploy_paths
check_cgroup_v2
check_host_network_persistence
WEB_BIND="$(normalize_bind_value "$WEB_BIND")"
WEB_UI_ENABLED="$(normalize_bool_json "$WEB_UI_ENABLED")" || fail "WEB_UI_ENABLED 仅支持 true/false/on/off/yes/no/1/0"
validate_port "$WEB_PORT"

# ---------- 识别现有安装 ----------
prepare_legacy_installation

if [[ -f "${INSTALL_DIR}/veer" || -f "${INSTALL_DIR}/forward" || -f "${INSTALL_DIR}/config.json" || -f "${SERVICE_FILE}" || -f "${LEGACY_SERVICE_FILE}" ]]; then
    HAS_EXISTING_INSTALL=true
fi

SERVICE_RUNNING=false
if service_is_active "$SERVICE_NAME" 2>/dev/null; then
    PREVIOUS_SERVICE_NAME="$SERVICE_NAME"
    PREVIOUS_SERVICE_RUNNING=true
    SERVICE_RUNNING=true
elif service_is_active "$LEGACY_SERVICE_NAME" 2>/dev/null; then
    PREVIOUS_SERVICE_NAME="$LEGACY_SERVICE_NAME"
    PREVIOUS_SERVICE_RUNNING=true
    SERVICE_RUNNING=true
fi

if $SERVICE_RUNNING; then
    info "检测到运行中的 $(service_label "${PREVIOUS_SERVICE_NAME}")，将迁移或热更新到 $(service_label "${SERVICE_NAME}")（worker 与 kernel session 尽量不中断）"
elif $HAS_EXISTING_INSTALL; then
    info "检测到已有安装但服务当前未运行，将执行冷启动更新"
fi

# ---------- 部署文件 ----------
info "部署到 ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
secure_runtime_secret_files

if $HAS_EXISTING_INSTALL; then
    backup_existing_installation
fi

if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
    sync_config_file "${INSTALL_DIR}/config.json" "127.0.0.1"
    eval "$(load_config_runtime_values "${INSTALL_DIR}/config.json")"
    log_explicit_config_overrides
    ok "配置文件已生成，并写入完整默认项"
else
    sync_config_file "${INSTALL_DIR}/config.json" "127.0.0.1"
    eval "$(load_config_runtime_values "${INSTALL_DIR}/config.json")"
    log_explicit_config_overrides
    ok "配置文件已保留现有值，并补齐缺失默认项"
fi
secure_runtime_secret_files

if [[ "${INSTALL_BUNDLED_PLUGINS}" == "1" ]]; then
    configure_plugin_install_dir
fi
if ! install_bundled_plugins; then
    if [[ "${CONFIG_BACKED_UP}" == "true" && -f "${CONFIG_BACKUP_PATH}" ]]; then
        rm -f "${INSTALL_DIR}/config.json"
        install -m 600 "${CONFIG_BACKUP_PATH}" "${INSTALL_DIR}/config.json"
    fi
    fail "bundled plugin 安装失败，现有插件与配置已恢复"
fi

install -m 755 "$BINARY_PATH" "${INSTALL_DIR}/veer"

API_READY_URL="$(compute_ready_url "$WEB_BIND" "$WEB_PORT")"
ok "文件部署完成"

# ---------- bpffs / 热更新状态目录 ----------
info "准备 bpffs 热更新状态目录..."
mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
fi
mkdir -p "$BPF_STATE_DIR"
mkdir -p "$RUNTIME_STATE_DIR"
ok "bpffs 状态目录已就绪: ${BPF_STATE_DIR}"

# ---------- 服务管理 ----------
info "配置 ${SERVICE_MANAGER} 服务..."
write_service_definition
validate_service_definition
prepare_selinux_labels
service_reload_manager
service_enable "$SERVICE_NAME"

if $SERVICE_RUNNING; then
    : > "$HOT_RESTART_MARKER"
    if [[ "${SKIP_HOT_RESTART_STATS}" == "1" ]]; then
        : > "$HOT_RESTART_SKIP_STATS_MARKER"
        info "本次热更新将跳过继承内核 stats_v4 统计表，流量统计会重新累计"
    else
        rm -f "$HOT_RESTART_SKIP_STATS_MARKER"
    fi
    if [[ "${PREVIOUS_SERVICE_NAME}" == "${SERVICE_NAME}" ]]; then
        if ! service_restart "$SERVICE_NAME"; then
            rollback_update "热重启命令失败，正在回滚"
        fi
    else
        if ! service_stop "${PREVIOUS_SERVICE_NAME}"; then
            rollback_update "停止旧服务失败，正在回滚"
        fi
        if ! service_start "$SERVICE_NAME"; then
            rollback_update "启动 Veer 服务失败，正在回滚"
        fi
    fi
else
    rm -f "$HOT_RESTART_SKIP_STATS_MARKER"
    if ! service_start "$SERVICE_NAME"; then
        if $HAS_EXISTING_INSTALL; then
            rollback_update "新版本启动命令失败，正在回滚"
        fi
        fail "服务启动失败；查看日志: $(service_log_hint "${SERVICE_NAME}")"
    fi
fi

info "等待服务通过 readyz 检查（超时 ${READY_TIMEOUT_SECONDS}s）..."
if wait_for_service_ready "${API_READY_URL}" "${READY_TIMEOUT_SECONDS}" "${SERVICE_NAME}"; then
    rm -f "$HOT_RESTART_MARKER"
    rm -f "$HOT_RESTART_SKIP_STATS_MARKER"
    if $SERVICE_RUNNING; then
        ok "服务已热更新并通过 readyz 检查"
    elif $HAS_EXISTING_INSTALL; then
        ok "已有安装已更新并通过 readyz 检查"
    else
        ok "服务启动成功并通过 readyz 检查"
    fi
else
    if $HAS_EXISTING_INSTALL; then
        rollback_update "新版本在 ${READY_TIMEOUT_SECONDS} 秒内未通过 readyz 检查，正在回滚"
    fi
    fail "服务在 ${READY_TIMEOUT_SECONDS} 秒内未通过 readyz 检查；查看日志: $(service_log_hint "${SERVICE_NAME}")"
fi

# ---------- 旧名称兼容入口 ----------
info "配置旧版路径与服务名兼容入口..."
if [[ -e "${INSTALL_DIR}/forward" || -L "${INSTALL_DIR}/forward" ]]; then
    rm -f "${INSTALL_DIR}/forward"
fi
ln -s "veer" "${INSTALL_DIR}/forward"

if [[ -f "${LEGACY_SERVICE_FILE}" && ! -L "${LEGACY_SERVICE_FILE}" ]]; then
    service_disable "${LEGACY_SERVICE_NAME}" >/dev/null 2>&1 || true
fi
rm -f "${LEGACY_SERVICE_FILE}"
ln -s "$(basename "${SERVICE_FILE}")" "${LEGACY_SERVICE_FILE}"

if [[ "${INSTALL_DIR}" == "${DEFAULT_INSTALL_DIR}" ]]; then
    if [[ ! -e "${LEGACY_INSTALL_DIR}" && ! -L "${LEGACY_INSTALL_DIR}" ]]; then
        ln -s "${DEFAULT_INSTALL_DIR}" "${LEGACY_INSTALL_DIR}"
    elif [[ -L "${LEGACY_INSTALL_DIR}" && "$(readlink -f "${LEGACY_INSTALL_DIR}")" != "$(readlink -f "${DEFAULT_INSTALL_DIR}")" ]]; then
        warn "${LEGACY_INSTALL_DIR} 已指向其他位置，未覆盖该路径"
    fi
fi
service_reload_manager
ok "兼容入口已就绪: ${INSTALL_DIR}/forward, $(service_label "${LEGACY_SERVICE_NAME}")"

# ---------- 防火墙 ----------
if ! is_loopback_bind "$WEB_BIND"; then
    warn "管理面 web_bind=${WEB_BIND} 使用明文 HTTP；仅应暴露到受信管理网/VPN，公网访问请在前置代理终止 TLS 并限制来源"
fi
if command -v ufw &>/dev/null; then
    info "配置 UFW 防火墙规则..."
    if is_loopback_bind "$WEB_BIND"; then
        info "检测到 web_bind=${WEB_BIND}，跳过放行管理端口 ${WEB_PORT}"
    else
        ufw allow "$WEB_PORT"/tcp comment "forward-web" > /dev/null 2>&1 || true
    fi
    ufw allow 80/tcp comment "forward-http"   > /dev/null 2>&1 || true
    ufw allow 443/tcp comment "forward-https" > /dev/null 2>&1 || true
    ok "UFW 规则已添加"
elif command -v nft &>/dev/null || command -v iptables &>/dev/null; then
    if is_loopback_bind "$WEB_BIND"; then
        info "管理端口仅监听本地地址 ${WEB_BIND}，无需额外放行 ${WEB_PORT}"
    else
        info "检测到 nftables/iptables，请手动放行端口: ${WEB_PORT}, 80, 443"
    fi
fi

# ---------- 内核转发 ----------
SYSCTL_FILE="/etc/sysctl.d/99-veer.conf"
mkdir -p "$(dirname "${SYSCTL_FILE}")"
printf '%s\n' '# Managed by Veer deploy.sh' 'net.ipv4.ip_forward=1' > "${SYSCTL_FILE}"
chmod 644 "${SYSCTL_FILE}"
if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]]; then
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    ok "IPv4 转发已开启 (已持久化)"
else
    ok "IPv4 转发已开启 (已持久化)"
fi

# ---------- 完成 ----------
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}       Veer 部署完成${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "  安装目录:  ${CYAN}${INSTALL_DIR}${NC}"
echo -e "  配置文件:  ${CYAN}${INSTALL_DIR}/config.json${NC}"
echo -e "  数据库:    ${CYAN}${INSTALL_DIR}/forward.db${NC}"
echo ""
if [[ "${WEB_UI_ENABLED}" == "true" ]]; then
    if is_loopback_bind "$WEB_BIND"; then
        echo -e "  管理面板:  ${CYAN}http://$(format_url_host "${WEB_BIND}"):${WEB_PORT}${NC}"
    elif [[ "${WEB_BIND}" == "0.0.0.0" || "${WEB_BIND}" == "::" ]]; then
        echo -e "  管理面板:  ${CYAN}http://<服务器IP>:${WEB_PORT}${NC}"
    else
        echo -e "  管理面板:  ${CYAN}http://$(format_url_host "${WEB_BIND}"):${WEB_PORT}${NC}"
    fi
else
    echo -e "  Web UI:    ${YELLOW}disabled${NC}"
    if [[ "${WEB_BIND}" == "0.0.0.0" || "${WEB_BIND}" == "::" ]]; then
        echo -e "  API Base:  ${CYAN}http://<服务器IP>:${WEB_PORT}/api${NC}"
    else
        echo -e "  API Base:  ${CYAN}http://$(format_url_host "${WEB_BIND}"):${WEB_PORT}/api${NC}"
    fi
fi
echo -e "  就绪探针:  ${CYAN}${API_READY_URL}${NC}"
echo -e "  就绪超时:  ${CYAN}${READY_TIMEOUT_SECONDS}s${NC}"
if [[ "${CONFIG_BACKED_UP}" != "true" && -t 1 ]]; then
    echo -e "  Bearer Token (web_token): ${YELLOW}${WEB_TOKEN}${NC}"
    if [[ -n "${PLUGIN_ADMIN_TOKEN}" ]]; then
	    echo -e "  Plugin Admin Token:       ${YELLOW}${PLUGIN_ADMIN_TOKEN}${NC}"
    else
	    echo -e "  Plugin Admin API:         ${YELLOW}disabled${NC}"
    fi
else
    echo -e "  Bearer Token (web_token): ${YELLOW}[hidden; stored in config.json]${NC}"
    if [[ -n "${PLUGIN_ADMIN_TOKEN}" ]]; then
        echo -e "  Plugin Admin Token:       ${YELLOW}[hidden; stored in config.json]${NC}"
    else
	    echo -e "  Plugin Admin API:         ${YELLOW}disabled${NC}"
    fi
fi
echo ""
echo -e "  服务管理:"
if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
    echo -e "    查看状态:  ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "    查看日志:  ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "    重启服务:  ${CYAN}systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "    停止服务:  ${CYAN}systemctl stop ${SERVICE_NAME}${NC}"
else
    echo -e "    查看状态:  ${CYAN}rc-service ${SERVICE_NAME} status${NC}"
    echo -e "    查看日志:  ${CYAN}tail -f /var/log/${SERVICE_NAME}.log${NC}"
    echo -e "    重启服务:  ${CYAN}rc-service ${SERVICE_NAME} restart${NC}"
    echo -e "    停止服务:  ${CYAN}rc-service ${SERVICE_NAME} stop${NC}"
fi
echo ""
echo -e "  卸载:"
if [[ "${SERVICE_MANAGER}" == "systemd" ]]; then
    echo -e "    ${CYAN}systemctl stop ${SERVICE_NAME} && systemctl disable ${SERVICE_NAME}${NC}"
    echo -e "    ${CYAN}rm -f ${SERVICE_FILE} ${LEGACY_SERVICE_FILE} ${SERVICE_BACKUP_PATH} ${LEGACY_SERVICE_BACKUP_PATH} && systemctl daemon-reload${NC}"
else
    echo -e "    ${CYAN}rc-service ${SERVICE_NAME} stop && rc-update del ${SERVICE_NAME} default${NC}"
    echo -e "    ${CYAN}rm -f ${SERVICE_FILE} ${LEGACY_SERVICE_FILE} ${SERVICE_BACKUP_PATH} ${LEGACY_SERVICE_BACKUP_PATH}${NC}"
fi
echo -e "    ${CYAN}rm -f ${SYSCTL_FILE}${NC}"
echo -e "    ${CYAN}rm -rf ${BPF_STATE_DIR} ${RUNTIME_STATE_DIR}${NC}"
echo -e "    ${CYAN}rm -rf ${INSTALL_DIR}${NC}"
if [[ "${INSTALL_DIR}" == "${DEFAULT_INSTALL_DIR}" ]]; then
    echo -e "    ${CYAN}rm -f ${LEGACY_INSTALL_DIR}${NC}"
fi
echo ""
