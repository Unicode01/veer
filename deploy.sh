#!/usr/bin/env bash
#
# NAT Forward - Debian 部署脚本
#
# 用法: 将 forward-linux-<arch> 与本脚本放在同一目录，然后:
#   chmod +x deploy.sh && sudo ./deploy.sh
#
# 脚本会自动匹配当前系统架构查找二进制文件:
#   x86_64  => forward-linux-amd64
#   aarch64 => forward-linux-arm64
#
# 可选环境变量:
#   INSTALL_DIR   安装目录       (默认 /opt/forward)
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

if [[ $EUID -ne 0 ]]; then
    fail "请使用 root 权限运行: sudo $0"
fi

# ---------- 变量 ----------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/forward}"
SERVICE_NAME="forward"
WEB_PORT="${WEB_PORT:-8080}"
WEB_TOKEN="${WEB_TOKEN:-$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)}"
BPF_STATE_DIR="${FORWARD_BPF_STATE_DIR:-/sys/fs/bpf/forward}"
RUNTIME_STATE_DIR="${FORWARD_RUNTIME_STATE_DIR:-${INSTALL_DIR}/.kernel-state}"
HOT_RESTART_MARKER="${INSTALL_DIR}/.hot-restart-kernel"

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

# ---------- 停止旧服务(首次安装时) ----------
IS_UPDATE=false
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    IS_UPDATE=true
    info "检测到正在运行的服务，将热更新二进制文件（worker 与 kernel session 尽量不中断）"
fi

# ---------- 部署文件 ----------
info "部署到 ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

cp -f "$BINARY_PATH" "${INSTALL_DIR}/forward"
chmod 755 "${INSTALL_DIR}/forward"

if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
    cat > "${INSTALL_DIR}/config.json" <<CONF
{
  "web_port": ${WEB_PORT},
  "web_token": "${WEB_TOKEN}"
}
CONF
    ok "配置文件已生成 (token: ${WEB_TOKEN})"
else
    ok "配置文件已存在，保留原有配置"
    WEB_PORT=$(grep -oP '"web_port"\s*:\s*\K[0-9]+' "${INSTALL_DIR}/config.json" 2>/dev/null || echo "$WEB_PORT")
    WEB_TOKEN=$(grep -oP '"web_token"\s*:\s*"\K[^"]+' "${INSTALL_DIR}/config.json" 2>/dev/null || echo "$WEB_TOKEN")
fi

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

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
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
ReadWritePaths=${INSTALL_DIR} /tmp /sys/fs/bpf
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

if $IS_UPDATE; then
    : > "$HOT_RESTART_MARKER"
    if systemctl restart "$SERVICE_NAME"; then
        rm -f "$HOT_RESTART_MARKER"
        ok "服务已热重启（worker 自动重连，kernel flow/NAT 表尝试跨进程接力）"
    else
        warn "热重启失败，已保留标记文件与 bpffs 状态，修复后可再次执行部署"
        exit 1
    fi
else
    systemctl start "$SERVICE_NAME"
fi

sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "服务启动成功"
else
    warn "服务可能启动失败，查看日志: journalctl -u ${SERVICE_NAME} -n 20"
fi

# ---------- 防火墙 ----------
if command -v ufw &>/dev/null; then
    info "配置 UFW 防火墙规则..."
    ufw allow "$WEB_PORT"/tcp comment "forward-web" > /dev/null 2>&1 || true
    ufw allow 80/tcp comment "forward-http"   > /dev/null 2>&1 || true
    ufw allow 443/tcp comment "forward-https" > /dev/null 2>&1 || true
    ok "UFW 规则已添加"
elif command -v nft &>/dev/null || command -v iptables &>/dev/null; then
    info "检测到 nftables/iptables，请手动放行端口: ${WEB_PORT}, 80, 443"
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
echo -e "  管理面板:  ${CYAN}http://<服务器IP>:${WEB_PORT}${NC}"
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
echo -e "    ${CYAN}rm /etc/systemd/system/${SERVICE_NAME}.service && systemctl daemon-reload${NC}"
echo -e "    ${CYAN}rm -rf ${INSTALL_DIR}${NC}"
echo ""
