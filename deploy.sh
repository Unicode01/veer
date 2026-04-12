#!/usr/bin/env bash
#
# NAT Forward - Debian 部署脚本
#
# 用法: 将 forward-linux-<arch> 与本脚本放在同一目录，然后:
#   chmod +x deploy.sh && sudo ./deploy.sh
#   chmod +x deploy.sh && sudo ./deploy.sh --no-inherit-stats
#
# 脚本会自动匹配当前系统架构查找二进制文件:
#   x86_64  => forward-linux-amd64
#   aarch64 => forward-linux-arm64
#
# 可选环境变量:
#   INSTALL_DIR   安装目录       (默认 /opt/forward)
#   WEB_BIND      Web 监听地址   (默认 127.0.0.1)
#   WEB_UI_ENABLED 是否启用 Web UI (默认 true)
#   WEB_PORT      Web 管理端口   (默认 8080)
#   WEB_TOKEN     API 认证令牌   (默认随机生成)
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

# ---------- 变量 ----------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/forward}"
SERVICE_NAME="forward"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_TEMPLATE_PATH="${SCRIPT_DIR}/config.example.json"
WEB_PORT="${WEB_PORT:-8080}"
WEB_BIND="${WEB_BIND:-127.0.0.1}"
WEB_UI_ENABLED="${WEB_UI_ENABLED:-true}"
WEB_TOKEN="${WEB_TOKEN:-$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)}"
BPF_STATE_DIR="${FORWARD_BPF_STATE_DIR:-/sys/fs/bpf/forward}"
RUNTIME_STATE_DIR="${FORWARD_RUNTIME_STATE_DIR:-${INSTALL_DIR}/.kernel-state}"
HOT_RESTART_MARKER="${INSTALL_DIR}/.hot-restart-kernel"
HOT_RESTART_SKIP_STATS_MARKER="${HOT_RESTART_MARKER}.skip-stats"
CONFIG_BACKUP_PATH="${INSTALL_DIR}/config.json.rollback"
BINARY_BACKUP_PATH="${INSTALL_DIR}/forward.rollback"
SERVICE_BACKUP_PATH="${SERVICE_FILE}.rollback"
API_READY_URL=""
PRESERVE_HOT_RESTART_MARKERS_ON_EXIT=0

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

validate_port() {
    local value="${1:-}"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        fail "WEB_PORT 必须是 1-65535 的整数，当前值: ${value:-<empty>}"
    fi
    if (( value < 1 || value > 65535 )); then
        fail "WEB_PORT 必须是 1-65535 的整数，当前值: ${value}"
    fi
}

is_loopback_bind() {
    case "${1:-}" in
        127.0.0.1|::1|localhost)
            return 0
            ;;
    esac
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
    local timeout_seconds="${2:-30}"
    local deadline=$((SECONDS + timeout_seconds))

    if ! http_probe_available; then
        warn "未检测到 curl/wget/python3，跳过 /readyz HTTP 检查，仅验证 systemd 状态"
        sleep 2
        systemctl is-active --quiet "$SERVICE_NAME"
        return $?
    fi

    while (( SECONDS < deadline )); do
        if systemctl is-failed --quiet "$SERVICE_NAME"; then
            return 1
        fi
        if http_probe "$ready_url"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

backup_existing_installation() {
    if [[ -f "${INSTALL_DIR}/config.json" ]]; then
        cp -f "${INSTALL_DIR}/config.json" "${CONFIG_BACKUP_PATH}"
    fi
    if [[ -f "${INSTALL_DIR}/forward" ]]; then
        cp -f "${INSTALL_DIR}/forward" "${BINARY_BACKUP_PATH}"
        ok "已备份当前版本到 ${BINARY_BACKUP_PATH}"
    fi
    if [[ -f "${SERVICE_FILE}" ]]; then
        cp -f "${SERVICE_FILE}" "${SERVICE_BACKUP_PATH}"
    fi
}

sync_config_file() {
    local config_path="$1"
    local missing_bind_default="$2"

    FORWARD_DEPLOY_CONFIG_TEMPLATE_PATH="${CONFIG_TEMPLATE_PATH}" \
    FORWARD_DEPLOY_DEFAULT_WEB_BIND="${missing_bind_default}" \
    FORWARD_DEPLOY_DEFAULT_WEB_UI_ENABLED="true" \
    FORWARD_DEPLOY_DEFAULT_WEB_PORT="${WEB_PORT}" \
    FORWARD_DEPLOY_DEFAULT_WEB_TOKEN="${WEB_TOKEN}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_BIND="${WEB_BIND_EXPLICIT}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_UI_ENABLED="${WEB_UI_ENABLED_EXPLICIT}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_PORT="${WEB_PORT_EXPLICIT}" \
    FORWARD_DEPLOY_EXPLICIT_WEB_TOKEN="${WEB_TOKEN_EXPLICIT}" \
    FORWARD_DEPLOY_WEB_BIND="${WEB_BIND}" \
    FORWARD_DEPLOY_WEB_UI_ENABLED="${WEB_UI_ENABLED}" \
    FORWARD_DEPLOY_WEB_PORT="${WEB_PORT}" \
    FORWARD_DEPLOY_WEB_TOKEN="${WEB_TOKEN}" \
    python3 - "$config_path" <<'PY'
from collections import OrderedDict
import json
import os
import sys

PLACEHOLDER_WEB_TOKEN = "change-me-to-a-secure-token"

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
}

explicit_values = {
    "web_bind": os.environ["FORWARD_DEPLOY_WEB_BIND"],
    "web_ui_enabled": env_bool("FORWARD_DEPLOY_WEB_UI_ENABLED"),
    "web_port": env_int("FORWARD_DEPLOY_WEB_PORT"),
    "web_token": os.environ["FORWARD_DEPLOY_WEB_TOKEN"],
}

hardcoded_defaults = OrderedDict([
    ("web_bind", os.environ["FORWARD_DEPLOY_DEFAULT_WEB_BIND"]),
    ("web_ui_enabled", env_bool("FORWARD_DEPLOY_DEFAULT_WEB_UI_ENABLED")),
    ("web_port", env_int("FORWARD_DEPLOY_DEFAULT_WEB_PORT")),
    ("web_token", os.environ["FORWARD_DEPLOY_DEFAULT_WEB_TOKEN"]),
    ("max_workers", 0),
    ("drain_timeout_hours", 24),
    ("managed_network_auto_repair", True),
    ("default_engine", "auto"),
    ("kernel_engine_order", ["tc", "xdp"]),
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
    overrides="$(printf '%s' "$overrides" | sed 's/^[[:space:]]*//')"
    if [[ -n "$overrides" ]]; then
        info "本次部署通过环境变量覆盖配置项: ${overrides}"
    fi
}

rollback_update() {
    local reason="$1"

    warn "${reason}"
    if [[ ! -f "${BINARY_BACKUP_PATH}" ]]; then
        fail "部署失败，且未找到旧版本备份；查看日志: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    fi

    warn "开始回滚到上一版本..."
    if [[ -f "${CONFIG_BACKUP_PATH}" ]]; then
        cp -f "${CONFIG_BACKUP_PATH}" "${INSTALL_DIR}/config.json"
    fi
    cp -f "${BINARY_BACKUP_PATH}" "${INSTALL_DIR}/forward"
    chmod 755 "${INSTALL_DIR}/forward"
    if [[ -f "${SERVICE_BACKUP_PATH}" ]]; then
        cp -f "${SERVICE_BACKUP_PATH}" "${SERVICE_FILE}"
    fi
    systemctl daemon-reload
    if ! systemctl restart "$SERVICE_NAME"; then
        PRESERVE_HOT_RESTART_MARKERS_ON_EXIT=1
        fail "回滚后的服务重启失败；查看日志: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    fi
    if wait_for_service_ready "${API_READY_URL}" 30; then
        fail "新版本部署失败，已自动回滚到上一版本"
    fi
    PRESERVE_HOT_RESTART_MARKERS_ON_EXIT=1
    fail "新版本部署失败，且回滚后的服务未能通过 readyz；查看日志: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
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
    "${SCRIPT_DIR}/forward-linux-${GOARCH}" \
    "${SCRIPT_DIR}/forward" \
; do
    if [[ -f "$candidate" ]]; then
        BINARY_PATH="$candidate"
        break
    fi
done

if [[ -z "$BINARY_PATH" ]]; then
    fail "未找到二进制文件，需要以下任一文件与本脚本同目录:\n       forward-linux-${GOARCH}\n       forward"
fi

FILE_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
ok "找到二进制: $(basename "$BINARY_PATH") (${FILE_SIZE}) [${ARCH}]"

require_python3
WEB_BIND="$(normalize_bind_value "$WEB_BIND")"
WEB_UI_ENABLED="$(normalize_bool_json "$WEB_UI_ENABLED")" || fail "WEB_UI_ENABLED 仅支持 true/false/on/off/yes/no/1/0"
validate_port "$WEB_PORT"

# ---------- 识别现有安装 ----------
HAS_EXISTING_INSTALL=false
if [[ -f "${INSTALL_DIR}/forward" || -f "${INSTALL_DIR}/config.json" || -f "${SERVICE_FILE}" ]]; then
    HAS_EXISTING_INSTALL=true
fi

SERVICE_RUNNING=false
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    SERVICE_RUNNING=true
fi

if $SERVICE_RUNNING; then
    info "检测到运行中的现有服务，将执行热更新（worker 与 kernel session 尽量不中断）"
elif $HAS_EXISTING_INSTALL; then
    info "检测到已有安装但服务当前未运行，将执行冷启动更新"
fi

# ---------- 部署文件 ----------
info "部署到 ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

if $HAS_EXISTING_INSTALL; then
    backup_existing_installation
fi

if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
    sync_config_file "${INSTALL_DIR}/config.json" "127.0.0.1"
    eval "$(load_config_runtime_values "${INSTALL_DIR}/config.json")"
    log_explicit_config_overrides
    ok "配置文件已生成，并写入完整默认项"
else
    sync_config_file "${INSTALL_DIR}/config.json" "0.0.0.0"
    eval "$(load_config_runtime_values "${INSTALL_DIR}/config.json")"
    log_explicit_config_overrides
    ok "配置文件已保留现有值，并补齐缺失默认项"
fi

install -m 755 "$BINARY_PATH" "${INSTALL_DIR}/forward"

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

# ---------- systemd 服务 ----------
info "配置 systemd 服务..."

cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=NAT Forward Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
Environment=FORWARD_HOT_RESTART_MARKER=${HOT_RESTART_MARKER}
Environment=FORWARD_BPF_STATE_DIR=${BPF_STATE_DIR}
Environment=FORWARD_RUNTIME_STATE_DIR=${RUNTIME_STATE_DIR}
ExecStart=${INSTALL_DIR}/forward --config ${INSTALL_DIR}/config.json
Restart=always
RestartSec=3
KillMode=process

NoNewPrivileges=false
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
ReadWritePaths=${RUNTIME_STATE_DIR}
ReadWritePaths=/etc/network
ReadWritePaths=/tmp
ReadWritePaths=/sys/fs/bpf
ReadWritePaths=${BPF_STATE_DIR}
PrivateTmp=true

AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_PERFMON

StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

LimitNOFILE=65535
LimitNPROC=4096
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

if $SERVICE_RUNNING; then
    : > "$HOT_RESTART_MARKER"
    if [[ "${SKIP_HOT_RESTART_STATS}" == "1" ]]; then
        : > "$HOT_RESTART_SKIP_STATS_MARKER"
        info "本次热更新将跳过继承内核 stats_v4 统计表，流量统计会重新累计"
    else
        rm -f "$HOT_RESTART_SKIP_STATS_MARKER"
    fi
    if ! systemctl restart "$SERVICE_NAME"; then
        rollback_update "热重启命令失败，正在回滚"
    fi
else
    rm -f "$HOT_RESTART_SKIP_STATS_MARKER"
    if ! systemctl start "$SERVICE_NAME"; then
        if $HAS_EXISTING_INSTALL; then
            rollback_update "新版本启动命令失败，正在回滚"
        fi
        fail "服务启动失败；查看日志: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    fi
fi

if wait_for_service_ready "${API_READY_URL}" 30; then
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
        rollback_update "新版本在 30 秒内未通过 readyz 检查，正在回滚"
    fi
    fail "服务在 30 秒内未通过 readyz 检查；查看日志: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
fi

# ---------- 防火墙 ----------
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
if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]]; then
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    ok "IPv4 转发已开启 (已持久化)"
else
    ok "IPv4 转发已开启"
fi

# ---------- 完成 ----------
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}       NAT Forward 部署完成${NC}"
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
echo -e "  API Token: ${YELLOW}${WEB_TOKEN}${NC}"
echo ""
echo -e "  服务管理:"
echo -e "    查看状态:  ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
echo -e "    查看日志:  ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "    重启服务:  ${CYAN}systemctl restart ${SERVICE_NAME}${NC}"
echo -e "    停止服务:  ${CYAN}systemctl stop ${SERVICE_NAME}${NC}"
echo ""
echo -e "  卸载:"
echo -e "    ${CYAN}systemctl stop ${SERVICE_NAME} && systemctl disable ${SERVICE_NAME}${NC}"
echo -e "    ${CYAN}rm -f ${SERVICE_FILE} ${SERVICE_BACKUP_PATH} && systemctl daemon-reload${NC}"
echo -e "    ${CYAN}rm -rf ${BPF_STATE_DIR} ${RUNTIME_STATE_DIR}${NC}"
echo -e "    ${CYAN}rm -rf ${INSTALL_DIR}${NC}"
echo ""
