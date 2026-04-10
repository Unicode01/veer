#!/usr/bin/env bash
#
# forward - Debian / Ubuntu 一键引导部署脚本
#
# 设计目标:
#   1. 安装构建与部署依赖
#   2. 拉取指定 Git ref 的源码
#   3. 调用 release.sh 本机构建
#   4. 调用 deploy.sh 完成安装 / 热更新
#
# 典型用法:
#   bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
#   FORWARD_REF=main WEB_PORT=8080 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh) -- --no-inherit-stats
#
# 说明:
#   - 该脚本适合直接通过 GitHub Raw 分发
#   - 目前仅支持 Debian 11+ 与 Ubuntu 22.04+
#   - 最终仍以实际内核版本为准
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOOTSTRAP_HINT_URL="https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh"

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

usage() {
    cat <<EOF
用法:
  bash <(curl -fsSL ${BOOTSTRAP_HINT_URL}) [-- deploy.sh 参数]

常用环境变量:
  FORWARD_REPO_URL     Git 仓库地址，默认 https://github.com/Unicode01/forward.git
  FORWARD_REF          拉取的 Git ref，默认 main
  FORWARD_GO_VERSION   安装的 Go 版本，默认 1.25.1
  FORWARD_WORKDIR      临时工作目录，默认 /tmp/forward-bootstrap
  FORWARD_SKIP_APT     设为 1 时跳过 apt 依赖安装
  FORWARD_SKIP_GO      设为 1 时跳过 Go 安装检查

部署阶段透传给 deploy.sh 的常用环境变量:
  INSTALL_DIR WEB_PORT WEB_TOKEN FORWARD_BPF_STATE_DIR FORWARD_RUNTIME_STATE_DIR

示例:
  bash <(curl -fsSL ${BOOTSTRAP_HINT_URL})
  FORWARD_REF=v1.2.3 bash <(curl -fsSL ${BOOTSTRAP_HINT_URL})
  bash <(curl -fsSL ${BOOTSTRAP_HINT_URL}) -- --no-inherit-stats
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    fail "请使用 root 运行。建议先执行 sudo -i，再运行 bash <(curl -fsSL ${BOOTSTRAP_HINT_URL})"
fi

FORWARD_REPO_URL="${FORWARD_REPO_URL:-https://github.com/Unicode01/forward.git}"
FORWARD_REF="${FORWARD_REF:-main}"
FORWARD_GO_VERSION="${FORWARD_GO_VERSION:-1.25.1}"
FORWARD_WORKDIR="${FORWARD_WORKDIR:-/tmp/forward-bootstrap}"
FORWARD_SKIP_APT="${FORWARD_SKIP_APT:-0}"
FORWARD_SKIP_GO="${FORWARD_SKIP_GO:-0}"

DEPLOY_ARGS=("$@")

cleanup() {
    if [[ -n "${FORWARD_WORKDIR:-}" && -d "${FORWARD_WORKDIR}" ]]; then
        rm -rf "${FORWARD_WORKDIR}"
    fi
}
trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "缺少命令: $1"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)
            GOARCH="amd64"
            GO_TARBALL_ARCH="amd64"
            ;;
        aarch64|arm64)
            GOARCH="arm64"
            GO_TARBALL_ARCH="arm64"
            ;;
        *)
            fail "不支持的架构: $(uname -m)"
            ;;
    esac
}

require_supported_distro() {
    [[ -f /etc/os-release ]] || fail "未找到 /etc/os-release，无法识别发行版"
    # shellcheck disable=SC1091
    . /etc/os-release

    case "${ID:-}" in
        debian)
            if ! dpkg --compare-versions "${VERSION_ID:-0}" ge "11"; then
                fail "仅支持 Debian 11+，当前为 Debian ${VERSION_ID:-unknown}"
            fi
            ;;
        ubuntu)
            if ! dpkg --compare-versions "${VERSION_ID:-0}" ge "22.04"; then
                fail "仅支持 Ubuntu 22.04+，当前为 Ubuntu ${VERSION_ID:-unknown}"
            fi
            ;;
        *)
            fail "当前仅支持 Debian 11+ 与 Ubuntu 22.04+，检测到: ${ID:-unknown} ${VERSION_ID:-unknown}"
            ;;
    esac

    ok "发行版检测通过: ${PRETTY_NAME:-${ID:-unknown}}"
}

install_apt_deps() {
    if [[ "${FORWARD_SKIP_APT}" == "1" ]]; then
        warn "已跳过 apt 依赖安装"
        return
    fi

    info "安装系统依赖..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        clang \
        llvm \
        linux-libc-dev \
        xz-utils
    ok "系统依赖安装完成"
}

current_go_version() {
    if ! command -v go >/dev/null 2>&1; then
        return 1
    fi
    go version | awk '{print $3}' | sed 's/^go//'
}

install_go_if_needed() {
    local current=""
    local url=""
    local tarball=""

    if [[ "${FORWARD_SKIP_GO}" == "1" ]]; then
        warn "已跳过 Go 安装检查"
        return
    fi

    current="$(current_go_version || true)"
    if [[ -n "${current}" ]] && dpkg --compare-versions "${current}" ge "${FORWARD_GO_VERSION}"; then
        ok "Go 已满足要求: ${current}"
        return
    fi

    info "安装 Go ${FORWARD_GO_VERSION}..."
    url="https://go.dev/dl/go${FORWARD_GO_VERSION}.linux-${GO_TARBALL_ARCH}.tar.gz"
    tarball="/tmp/go${FORWARD_GO_VERSION}.linux-${GO_TARBALL_ARCH}.tar.gz"

    rm -f "${tarball}"
    curl -fsSL "${url}" -o "${tarball}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${tarball}"
    rm -f "${tarball}"

    export PATH="/usr/local/go/bin:${PATH}"
    current="$(current_go_version || true)"
    if [[ -z "${current}" ]] || ! dpkg --compare-versions "${current}" ge "${FORWARD_GO_VERSION}"; then
        fail "Go 安装失败，当前版本: ${current:-unknown}"
    fi
    ok "Go 已安装: ${current}"
}

clone_repo() {
    local repo_dir="${FORWARD_WORKDIR}/repo"

    info "拉取源码: ${FORWARD_REPO_URL} @ ${FORWARD_REF}"
    rm -rf "${FORWARD_WORKDIR}"
    mkdir -p "${repo_dir}"

    git init -q "${repo_dir}"
    git -C "${repo_dir}" remote add origin "${FORWARD_REPO_URL}"
    git -C "${repo_dir}" fetch --depth 1 origin "${FORWARD_REF}"
    git -C "${repo_dir}" checkout -q FETCH_HEAD

    FORWARD_REPO_DIR="${repo_dir}"
    ok "源码已就绪: $(git -C "${repo_dir}" rev-parse --short HEAD)"
}

build_release() {
    info "开始构建 linux/${GOARCH}..."
    export PATH="/usr/local/go/bin:${PATH}"
    cd "${FORWARD_REPO_DIR}"
    ./release.sh "${GOARCH}"
    ok "构建完成"
}

run_deploy() {
    info "开始部署..."
    cd "${FORWARD_REPO_DIR}"
    ./deploy.sh "${DEPLOY_ARGS[@]}"
}

main() {
    require_command dpkg
    require_command apt-get
    require_command curl
    require_command tar

    detect_arch
    require_supported_distro
    install_apt_deps
    require_command git
    install_go_if_needed
    clone_repo
    build_release
    run_deploy
}

main
