#!/usr/bin/env bash
#
# NAT Forward - 交叉编译构建脚本
#
# 用法:
#   ./release.sh              # 编译所有架构 (amd64 + arm64)
#   ./release.sh amd64        # 仅编译 amd64
#   ./release.sh arm64        # 仅编译 arm64
#
# 产物直接输出到项目根目录:
#   forward-linux-amd64
#   forward-linux-arm64
#
# 部署: 将 forward-linux-<arch> + deploy.sh 一起传到服务器执行即可
#
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v go &>/dev/null; then
    fail "未找到 go 命令，请先安装 Go >= 1.21"
fi
ok "Go: $(go version)"

# ---------- 目标架构 ----------
TARGETS=()
if [[ $# -gt 0 ]]; then
    for arg in "$@"; do
        case "$arg" in
            amd64|arm64) TARGETS+=("$arg") ;;
            *) fail "不支持的架构: $arg (可选: amd64, arm64)" ;;
        esac
    done
else
    TARGETS=("amd64" "arm64")
fi

cd "$PROJECT_DIR"
[[ -f "go.mod" ]] || fail "go.mod 未找到，请在项目根目录运行"

info "下载依赖..."
go mod download

# ---------- 编译 ----------
for ARCH in "${TARGETS[@]}"; do
    OUT="${PROJECT_DIR}/forward-linux-${ARCH}"
    info "编译 linux/${ARCH}..."

    NONCE=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        go build -ldflags="-s -w -X main.buildNonce=${NONCE}" -trimpath -o "$OUT" .

    SIZE=$(du -h "$OUT" | cut -f1)
    ok "linux/${ARCH} => forward-linux-${ARCH} (${SIZE})"
done

echo ""
echo -e "${GREEN}构建完成。部署方法:${NC}"
echo ""
echo "  scp forward-linux-amd64 deploy.sh root@server:/tmp/"
echo "  ssh root@server 'cd /tmp && chmod +x deploy.sh && ./deploy.sh'"
echo ""
