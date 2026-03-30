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
# 注意: eBPF tc 对象会先在本地编译并 embed 进 Go 二进制，部署时无需额外携带 .o 文件
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
EBPF_DIR="${PROJECT_DIR}/ebpf"
EBPF_SRC="${EBPF_DIR}/forward-tc-bpf.c"
EBPF_OBJ="${EBPF_DIR}/forward-tc-bpf.o"
EBPF_INC="${EBPF_DIR}/include"
BPF_CLANG="${BPF_CLANG:-clang}"
BPF_EXTRA_CFLAGS="${BPF_EXTRA_CFLAGS:-}"
BPF_OLEVEL="${BPF_OLEVEL:-1}"

if ! command -v go &>/dev/null; then
    fail "未找到 go 命令，请先安装 Go >= 1.21"
fi
ok "Go: $(go version)"

if ! command -v "${BPF_CLANG}" &>/dev/null; then
    fail "未找到 clang，无法编译 ebpf/forward-tc-bpf.o"
fi
ok "Clang: $("${BPF_CLANG}" --version | head -n 1)"

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

[[ -f "${EBPF_SRC}" ]] || fail "eBPF 源文件未找到: ${EBPF_SRC}"

find_multiarch_include() {
    local candidate=""

    if command -v dpkg-architecture &>/dev/null; then
        candidate="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
        if [[ -n "${candidate}" && -d "/usr/include/${candidate}" ]]; then
            echo "/usr/include/${candidate}"
            return 0
        fi
    fi

    if command -v gcc &>/dev/null; then
        candidate="$(gcc -print-multiarch 2>/dev/null || true)"
        if [[ -n "${candidate}" && -d "/usr/include/${candidate}" ]]; then
            echo "/usr/include/${candidate}"
            return 0
        fi
    fi

    if [[ -d "/usr/include/$(uname -m)-linux-gnu" ]]; then
        echo "/usr/include/$(uname -m)-linux-gnu"
        return 0
    fi

    return 1
}

BPF_CFLAGS=(
    "-O${BPF_OLEVEL}"
    -g
    -target bpf
    -I"${EBPF_INC}"
)

if MULTIARCH_INC="$(find_multiarch_include)"; then
    BPF_CFLAGS+=(-I"${MULTIARCH_INC}")
    info "检测到多架构头文件目录: ${MULTIARCH_INC}"
else
    info "未检测到多架构头文件目录，若编译报 asm/*.h 缺失，请安装 linux-libc-dev 或设置 BPF_EXTRA_CFLAGS"
fi

if [[ -n "${BPF_EXTRA_CFLAGS}" ]]; then
    # shellcheck disable=SC2206
    EXTRA_FLAGS=( ${BPF_EXTRA_CFLAGS} )
    BPF_CFLAGS+=("${EXTRA_FLAGS[@]}")
fi

info "eBPF clang 优化级别: -O${BPF_OLEVEL}"
info "编译 tc eBPF 对象..."
if ! "${BPF_CLANG}" "${BPF_CFLAGS[@]}" -c "${EBPF_SRC}" -o "${EBPF_OBJ}"; then
    fail "eBPF 编译失败；Debian/Ubuntu 通常需要 linux-libc-dev，必要时可通过 BPF_EXTRA_CFLAGS 追加头文件路径"
fi

if command -v llvm-strip &>/dev/null; then
    llvm-strip -g "${EBPF_OBJ}" || true
fi
ok "eBPF => ${EBPF_OBJ}"

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
