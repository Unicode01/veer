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
set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOOTSTRAP_HINT_URL="https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh"
CURRENT_STEP="初始化"
BOOTSTRAP_FAILED=0
BOOTSTRAP_ERROR_REPORTED=0

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { BOOTSTRAP_FAILED=1; BOOTSTRAP_ERROR_REPORTED=1; echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

usage() {
    cat <<EOF
用法:
  bash <(curl -fsSL ${BOOTSTRAP_HINT_URL}) [-- deploy.sh 参数]

常用环境变量:
  FORWARD_REPO_URL     Git 仓库地址，默认 https://github.com/Unicode01/forward.git
  FORWARD_REPO_URL_CN  CN 模式优先尝试的 Git 源，默认空
  FORWARD_REPO_ARCHIVE_URL
                      显式覆盖源码归档地址，git 拉取失败时作为回退
  FORWARD_REPO_ARCHIVE_URL_CN
                      CN 模式优先尝试的源码归档地址，默认空
  FORWARD_REF          拉取的 Git ref，默认 main
  FORWARD_GO_VERSION   安装的 Go 版本，默认 1.25.1
  FORWARD_GO_REGION    Go 下载区域策略: auto/cn/global，默认 auto
  FORWARD_GO_BASE_URL  显式覆盖 Go 下载源前缀，例如 https://mirror.example.com/golang
  FORWARD_GO_CN_BASE_URL
                      CN 模式优先使用的 Go 镜像前缀，默认 https://mirrors.aliyun.com/golang
  FORWARD_GOPROXY      显式覆盖 Go 模块代理，例如 https://goproxy.cn|direct
  FORWARD_GOPROXY_CN   CN 模式默认模块代理，默认 https://goproxy.cn|direct
  FORWARD_GOPROXY_GLOBAL
                      global 模式默认模块代理，默认 https://proxy.golang.org|direct
  FORWARD_GOSUMDB      显式覆盖 Go 校验源，例如 sum.golang.google.cn
  FORWARD_GOSUMDB_CN   CN 模式默认校验源，默认 sum.golang.google.cn
  FORWARD_GOSUMDB_GLOBAL
                      global 模式默认校验源，默认 sum.golang.org
  FORWARD_WORKDIR      临时工作目录，默认 /tmp/forward-bootstrap
  FORWARD_KEEP_WORKDIR_ON_ERROR
                        失败时保留临时目录，默认 1
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
FORWARD_REPO_URL_CN="${FORWARD_REPO_URL_CN:-}"
FORWARD_REPO_ARCHIVE_URL="${FORWARD_REPO_ARCHIVE_URL:-}"
FORWARD_REPO_ARCHIVE_URL_CN="${FORWARD_REPO_ARCHIVE_URL_CN:-}"
FORWARD_REF="${FORWARD_REF:-main}"
FORWARD_GO_VERSION="${FORWARD_GO_VERSION:-1.25.1}"
FORWARD_GO_REGION="${FORWARD_GO_REGION:-auto}"
FORWARD_GO_BASE_URL="${FORWARD_GO_BASE_URL:-}"
FORWARD_GO_CN_BASE_URL="${FORWARD_GO_CN_BASE_URL:-https://mirrors.aliyun.com/golang}"
FORWARD_GOPROXY="${FORWARD_GOPROXY:-}"
FORWARD_GOPROXY_CN="${FORWARD_GOPROXY_CN:-https://goproxy.cn|direct}"
FORWARD_GOPROXY_GLOBAL="${FORWARD_GOPROXY_GLOBAL:-https://proxy.golang.org|direct}"
FORWARD_GOSUMDB="${FORWARD_GOSUMDB:-}"
FORWARD_GOSUMDB_CN="${FORWARD_GOSUMDB_CN:-sum.golang.google.cn}"
FORWARD_GOSUMDB_GLOBAL="${FORWARD_GOSUMDB_GLOBAL:-sum.golang.org}"
FORWARD_GO_EFFECTIVE_REGION=""
FORWARD_WORKDIR="${FORWARD_WORKDIR:-/tmp/forward-bootstrap}"
FORWARD_KEEP_WORKDIR_ON_ERROR="${FORWARD_KEEP_WORKDIR_ON_ERROR:-1}"
FORWARD_SKIP_APT="${FORWARD_SKIP_APT:-0}"
FORWARD_SKIP_GO="${FORWARD_SKIP_GO:-0}"
FORWARD_REPO_DIR="${FORWARD_WORKDIR}/repo"
FORWARD_GO_ROOT="${FORWARD_WORKDIR}/go"
FORWARD_GO_TARBALL="${FORWARD_WORKDIR}/go${FORWARD_GO_VERSION}.linux-${GO_TARBALL_ARCH:-amd64}.tar.gz"

DEPLOY_ARGS=("$@")

set_step() {
    CURRENT_STEP="$1"
    info "${CURRENT_STEP}..."
}

run_with_retry() {
    local attempts="$1"
    local delay_seconds="$2"
    local description="$3"
    shift 3

    local try=1
    while true; do
        if "$@"; then
            return 0
        fi

        local exit_code=$?
        if (( try >= attempts )); then
            fail "${description} 失败，已重试 ${attempts} 次 (exit=${exit_code})"
        fi

        warn "${description} 失败 (exit=${exit_code})，${delay_seconds}s 后重试 (${try}/${attempts})"
        sleep "${delay_seconds}"
        try=$((try + 1))
    done
}

try_with_retry() {
    local attempts="$1"
    local delay_seconds="$2"
    local description="$3"
    shift 3

    local try=1
    local exit_code=0
    while true; do
        if "$@"; then
            return 0
        fi

        exit_code=$?
        if (( try >= attempts )); then
            warn "${description} 失败，已重试 ${attempts} 次 (exit=${exit_code})"
            return "${exit_code}"
        fi

        warn "${description} 失败 (exit=${exit_code})，${delay_seconds}s 后重试 (${try}/${attempts})"
        sleep "${delay_seconds}"
        try=$((try + 1))
    done
}

on_error() {
    local exit_code="$1"
    local line="$2"
    local command="$3"

    if [[ "${BOOTSTRAP_ERROR_REPORTED}" == "1" ]]; then
        return
    fi

    BOOTSTRAP_FAILED=1
    BOOTSTRAP_ERROR_REPORTED=1
    echo -e "${RED}[FAIL]${NC}  bootstrap 执行失败"
    echo -e "        step: ${CURRENT_STEP}"
    echo -e "        line: ${line}"
    echo -e "        exit: ${exit_code}"
    echo -e "     command: ${command}"
    if [[ -n "${FORWARD_WORKDIR:-}" ]]; then
        echo -e "        work: ${FORWARD_WORKDIR}"
    fi
}

cleanup() {
    if [[ -n "${FORWARD_WORKDIR:-}" && -d "${FORWARD_WORKDIR}" ]]; then
        if [[ "${BOOTSTRAP_FAILED}" == "1" && "${FORWARD_KEEP_WORKDIR_ON_ERROR}" == "1" ]]; then
            warn "bootstrap 失败，已保留临时目录: ${FORWARD_WORKDIR}"
            return
        fi
        rm -rf "${FORWARD_WORKDIR}"
    fi
}
trap cleanup EXIT
trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

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

detect_memory_limit_kib() {
    local value=""

    if [[ -r /sys/fs/cgroup/memory.max ]]; then
        value="$(< /sys/fs/cgroup/memory.max)"
        if [[ "${value}" =~ ^[0-9]+$ ]] && (( value > 0 )); then
            echo $(( value / 1024 ))
            return 0
        fi
    fi

    if [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
        value="$(< /sys/fs/cgroup/memory/memory.limit_in_bytes)"
        if [[ "${value}" =~ ^[0-9]+$ ]] && (( value > 0 && value < 9223372036854771712 )); then
            echo $(( value / 1024 ))
            return 0
        fi
    fi

    return 1
}

warn_low_memory() {
    local total_kib=""
    local limit_kib=""
    local effective_kib=""
    local effective_mib=0

    total_kib="$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || true)"
    if [[ "${total_kib}" =~ ^[0-9]+$ ]]; then
        effective_kib="${total_kib}"
    fi

    limit_kib="$(detect_memory_limit_kib || true)"
    if [[ "${limit_kib}" =~ ^[0-9]+$ ]]; then
        if [[ -z "${effective_kib}" ]] || (( limit_kib < effective_kib )); then
            effective_kib="${limit_kib}"
        fi
    fi

    if ! [[ "${effective_kib}" =~ ^[0-9]+$ ]]; then
        warn "无法检测可用内存，继续执行"
        return
    fi

    if (( effective_kib < 1024 * 1024 )); then
        effective_mib=$(( effective_kib / 1024 ))
        warn "检测到可用内存约 ${effective_mib} MiB，小于 1 GiB；编译与首次部署可能因内存不足失败，建议先增加内存或临时启用 swap"
    fi
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

    export DEBIAN_FRONTEND=noninteractive
    run_with_retry 3 3 "apt-get update" apt-get update
    run_with_retry 3 3 "安装系统依赖" apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        clang \
        llvm \
        linux-libc-dev \
        python3 \
        xz-utils
    ok "系统依赖安装完成"
}

current_go_version() {
    if ! command -v go >/dev/null 2>&1; then
        return 1
    fi
    go version | awk '{print $3}' | sed 's/^go//'
}

normalize_go_region() {
    local value="${1:-}"
    value="$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    case "${value}" in
        ""|auto)
            printf 'auto'
            ;;
        cn)
            printf 'cn'
            ;;
        global)
            printf 'global'
            ;;
        *)
            fail "FORWARD_GO_REGION 仅支持 auto/cn/global，当前值: ${1:-<empty>}"
            ;;
    esac
}

detect_timezone_name() {
    local tz=""

    if command -v timedatectl >/dev/null 2>&1; then
        tz="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
    fi

    if [[ -z "${tz}" && -r /etc/timezone ]]; then
        tz="$(tr -d '[:space:]' < /etc/timezone 2>/dev/null || true)"
    fi

    if [[ -z "${tz}" && -L /etc/localtime ]]; then
        tz="$(readlink /etc/localtime 2>/dev/null || true)"
        tz="${tz#*/zoneinfo/}"
    fi

    printf '%s' "${tz}"
}

timezone_indicates_cn() {
    case "${1:-}" in
        Asia/Shanghai|Asia/Chongqing|Asia/Harbin|Asia/Urumqi)
            return 0
            ;;
    esac
    return 1
}

fetch_country_code() {
    local url="$1"
    local format="${2:-plain}"
    local output=""
    local code=""

    output="$(curl -fsS --max-time 3 "${url}" 2>/dev/null || true)"
    if [[ -z "${output}" ]]; then
        return 1
    fi

    case "${format}" in
        trace)
            code="$(printf '%s\n' "${output}" | awk -F= '/^loc=/{print $2; exit}')"
            ;;
        plain)
            code="$(printf '%s' "${output}" | tr -d '[:space:]')"
            ;;
        *)
            return 1
            ;;
    esac

    code="$(printf '%s' "${code}" | tr '[:lower:]' '[:upper:]')"
    if [[ -z "${code}" ]]; then
        return 1
    fi

    printf '%s' "${code}"
}

detect_go_download_region() {
    local requested=""
    local timezone_name=""
    local country_code=""

    [[ -n "${FORWARD_GO_EFFECTIVE_REGION}" ]] && return 0

    requested="$(normalize_go_region "${FORWARD_GO_REGION}")"
    case "${requested}" in
        cn)
            FORWARD_GO_EFFECTIVE_REGION="cn"
            info "Go 下载区域已强制设为中国大陆镜像"
            return 0
            ;;
        global)
            FORWARD_GO_EFFECTIVE_REGION="global"
            info "Go 下载区域已强制设为默认源"
            return 0
            ;;
    esac

    timezone_name="$(detect_timezone_name)"
    if [[ -n "${timezone_name}" ]] && timezone_indicates_cn "${timezone_name}"; then
        FORWARD_GO_EFFECTIVE_REGION="cn"
        info "检测到中国大陆时区 (${timezone_name})，Go 下载将优先使用国内镜像"
        return 0
    fi

    country_code="$(fetch_country_code "https://www.cloudflare.com/cdn-cgi/trace" trace || true)"
    if [[ -z "${country_code}" ]]; then
        country_code="$(fetch_country_code "https://ifconfig.co/country-iso" plain || true)"
    fi
    if [[ -z "${country_code}" ]]; then
        country_code="$(fetch_country_code "https://ipinfo.io/country" plain || true)"
    fi

    if [[ "${country_code}" == "CN" ]]; then
        FORWARD_GO_EFFECTIVE_REGION="cn"
        info "检测到中国大陆网络 (${country_code})，Go 下载将优先使用国内镜像"
    else
        FORWARD_GO_EFFECTIVE_REGION="global"
        if [[ -n "${country_code}" ]]; then
            info "Go 下载区域检测结果: ${country_code}，使用默认源"
        else
            warn "无法确定 Go 下载区域，默认使用 go.dev"
        fi
    fi
}

array_contains() {
    local needle="$1"
    shift

    local item=""
    for item in "$@"; do
        if [[ "${item}" == "${needle}" ]]; then
            return 0
        fi
    done
    return 1
}

configure_go_module_env() {
    local region=""
    local effective_proxy=""
    local effective_sumdb=""

    if [[ -z "${FORWARD_GO_EFFECTIVE_REGION}" ]]; then
        detect_go_download_region
    fi
    region="${FORWARD_GO_EFFECTIVE_REGION:-global}"

    if [[ -n "${FORWARD_GOPROXY}" ]]; then
        effective_proxy="${FORWARD_GOPROXY}"
    elif [[ ${GOPROXY+x} ]]; then
        effective_proxy="${GOPROXY}"
    elif [[ "${region}" == "cn" ]]; then
        effective_proxy="${FORWARD_GOPROXY_CN}"
    else
        effective_proxy="${FORWARD_GOPROXY_GLOBAL}"
    fi

    if [[ -n "${FORWARD_GOSUMDB}" ]]; then
        effective_sumdb="${FORWARD_GOSUMDB}"
    elif [[ ${GOSUMDB+x} ]]; then
        effective_sumdb="${GOSUMDB}"
    elif [[ "${region}" == "cn" ]]; then
        effective_sumdb="${FORWARD_GOSUMDB_CN}"
    else
        effective_sumdb="${FORWARD_GOSUMDB_GLOBAL}"
    fi

    export GOPROXY="${effective_proxy}"
    export GOSUMDB="${effective_sumdb}"

    if [[ -n "${GOPROXY}" ]]; then
        info "Go 模块代理: ${GOPROXY}"
    else
        warn "Go 模块代理为空，将使用 Go 默认行为"
    fi

    if [[ -n "${GOSUMDB}" ]]; then
        info "Go 校验源: ${GOSUMDB}"
    else
        warn "Go 校验源为空，模块校验将按当前环境默认行为处理"
    fi
}

join_url_path() {
    local base="${1%/}"
    local path="${2#/}"
    printf '%s/%s' "${base}" "${path}"
}

github_repo_slug_from_url() {
    local url="$1"
    local path=""

    case "${url}" in
        https://github.com/*)
            path="${url#https://github.com/}"
            ;;
        http://github.com/*)
            path="${url#http://github.com/}"
            ;;
        https://www.github.com/*)
            path="${url#https://www.github.com/}"
            ;;
        http://www.github.com/*)
            path="${url#http://www.github.com/}"
            ;;
        ssh://git@github.com/*)
            path="${url#ssh://git@github.com/}"
            ;;
        git@github.com:*)
            path="${url#git@github.com:}"
            ;;
        *)
            return 1
            ;;
    esac

    path="${path%.git}"
    if [[ "${path}" != */* ]]; then
        return 1
    fi
    printf '%s' "${path}"
}

resolve_repo_fetch_urls() {
    local region=""
    local urls=()

    if [[ -z "${FORWARD_GO_EFFECTIVE_REGION}" ]]; then
        detect_go_download_region
    fi
    region="${FORWARD_GO_EFFECTIVE_REGION:-global}"

    if [[ "${region}" == "cn" && -n "${FORWARD_REPO_URL_CN}" ]] && ! array_contains "${FORWARD_REPO_URL_CN}" "${urls[@]}"; then
        urls+=("${FORWARD_REPO_URL_CN}")
    fi
    if [[ -n "${FORWARD_REPO_URL}" ]] && ! array_contains "${FORWARD_REPO_URL}" "${urls[@]}"; then
        urls+=("${FORWARD_REPO_URL}")
    fi
    if (( ${#urls[@]} == 0 )); then
        return 0
    fi
    printf '%s\n' "${urls[@]}"
}

resolve_repo_archive_urls() {
    local region=""
    local slug=""
    local urls=()
    local url=""

    if [[ -z "${FORWARD_GO_EFFECTIVE_REGION}" ]]; then
        detect_go_download_region
    fi
    region="${FORWARD_GO_EFFECTIVE_REGION:-global}"

    if [[ "${region}" == "cn" && -n "${FORWARD_REPO_ARCHIVE_URL_CN}" ]] && ! array_contains "${FORWARD_REPO_ARCHIVE_URL_CN}" "${urls[@]}"; then
        urls+=("${FORWARD_REPO_ARCHIVE_URL_CN}")
    fi
    if [[ -n "${FORWARD_REPO_ARCHIVE_URL}" ]] && ! array_contains "${FORWARD_REPO_ARCHIVE_URL}" "${urls[@]}"; then
        urls+=("${FORWARD_REPO_ARCHIVE_URL}")
    fi

    slug="$(github_repo_slug_from_url "${FORWARD_REPO_URL}" || true)"
    if [[ -n "${slug}" ]]; then
        for url in \
            "https://codeload.github.com/${slug}/tar.gz/refs/heads/${FORWARD_REF}" \
            "https://codeload.github.com/${slug}/tar.gz/refs/tags/${FORWARD_REF}" \
            "https://codeload.github.com/${slug}/tar.gz/${FORWARD_REF}"
        do
            if ! array_contains "${url}" "${urls[@]}"; then
                urls+=("${url}")
            fi
        done
    fi

    if (( ${#urls[@]} == 0 )); then
        return 0
    fi
    printf '%s\n' "${urls[@]}"
}

resolve_go_download_urls() {
    local filename="$1"
    local region=""

    if [[ -n "${FORWARD_GO_BASE_URL}" ]]; then
        printf '%s\n' "$(join_url_path "${FORWARD_GO_BASE_URL}" "${filename}")"
        return 0
    fi

    if [[ -z "${FORWARD_GO_EFFECTIVE_REGION}" ]]; then
        detect_go_download_region >/dev/null
    fi
    region="${FORWARD_GO_EFFECTIVE_REGION:-global}"
    if [[ "${region}" == "cn" ]]; then
        printf '%s\n' "$(join_url_path "${FORWARD_GO_CN_BASE_URL}" "${filename}")"
        printf '%s\n' "https://golang.google.cn/dl/${filename}"
        printf '%s\n' "https://go.dev/dl/${filename}"
        return 0
    fi
    printf '%s\n' "https://go.dev/dl/${filename}"
    printf '%s\n' "https://golang.google.cn/dl/${filename}"
}

fetch_repo_via_git() {
    local repo_url="$1"

    rm -rf "${FORWARD_REPO_DIR}"
    mkdir -p "${FORWARD_REPO_DIR}"
    git init -q "${FORWARD_REPO_DIR}"
    git -C "${FORWARD_REPO_DIR}" remote add origin "${repo_url}"
    if ! try_with_retry 3 3 "拉取源码 ${repo_url}@${FORWARD_REF}" git -C "${FORWARD_REPO_DIR}" fetch --depth 1 origin "${FORWARD_REF}"; then
        return 1
    fi
    git -C "${FORWARD_REPO_DIR}" checkout -q FETCH_HEAD
}

fetch_repo_via_archive() {
    local archive_url="$1"
    local archive_path="${FORWARD_WORKDIR}/repo-src.tar.gz"

    rm -f "${archive_path}"
    if ! try_with_retry 3 3 "下载源码归档 ${archive_url}" curl -fL --connect-timeout 15 --retry 3 --retry-all-errors --retry-delay 1 -o "${archive_path}" "${archive_url}"; then
        rm -f "${archive_path}"
        return 1
    fi

    rm -rf "${FORWARD_REPO_DIR}"
    mkdir -p "${FORWARD_REPO_DIR}"
    if ! tar -C "${FORWARD_REPO_DIR}" --strip-components=1 -xzf "${archive_path}"; then
        rm -f "${archive_path}"
        rm -rf "${FORWARD_REPO_DIR}"
        return 1
    fi
    rm -f "${archive_path}"
}

download_go_tarball() {
    local filename="$1"
    local url=""
    local attempt_index=0
    local total_urls=0
    local urls=()

    mapfile -t urls < <(resolve_go_download_urls "${filename}")
    total_urls="${#urls[@]}"

    if (( total_urls == 0 )); then
        fail "未生成任何 Go 下载地址"
    fi

    for url in "${urls[@]}"; do
        attempt_index=$((attempt_index + 1))
        info "尝试下载 Go ${FORWARD_GO_VERSION} (${attempt_index}/${total_urls}): ${url}"
        if curl -fL --connect-timeout 15 --retry 3 --retry-all-errors --retry-delay 1 -o "${FORWARD_GO_TARBALL}" "${url}"; then
            ok "Go 下载完成: ${url}"
            return 0
        fi
        warn "Go 下载失败，尝试下一个源: ${url}"
        rm -f "${FORWARD_GO_TARBALL}"
    done

    fail "下载 Go ${FORWARD_GO_VERSION} 失败，已尝试 ${total_urls} 个源"
}

install_go_if_needed() {
    local current=""
    local filename=""

    if [[ "${FORWARD_SKIP_GO}" == "1" ]]; then
        warn "已跳过 Go 安装检查"
        return
    fi

    current="$(current_go_version || true)"
    if [[ -n "${current}" ]] && dpkg --compare-versions "${current}" ge "${FORWARD_GO_VERSION}"; then
        ok "Go 已满足要求: ${current}"
        return
    fi

    filename="go${FORWARD_GO_VERSION}.linux-${GO_TARBALL_ARCH}.tar.gz"
    FORWARD_GO_TARBALL="${FORWARD_WORKDIR}/${filename}"

    mkdir -p "${FORWARD_WORKDIR}"
    rm -f "${FORWARD_GO_TARBALL}"
    rm -rf "${FORWARD_GO_ROOT}"
    detect_go_download_region
    download_go_tarball "${filename}"
    tar -C "${FORWARD_WORKDIR}" -xzf "${FORWARD_GO_TARBALL}"
    rm -f "${FORWARD_GO_TARBALL}"

    export GOROOT="${FORWARD_GO_ROOT}"
    export PATH="${FORWARD_GO_ROOT}/bin:${PATH}"
    current="$(current_go_version || true)"
    if [[ -z "${current}" ]] || ! dpkg --compare-versions "${current}" ge "${FORWARD_GO_VERSION}"; then
        fail "Go 安装失败，当前版本: ${current:-unknown}"
    fi
    ok "临时 Go 已安装: ${current} (${FORWARD_GO_ROOT})"
}

clone_repo() {
    local fetch_urls=()
    local archive_urls=()
    local url=""
    local index=0
    local total=0

    mapfile -t fetch_urls < <(resolve_repo_fetch_urls)
    total="${#fetch_urls[@]}"
    for url in "${fetch_urls[@]}"; do
        [[ -n "${url}" ]] || continue
        index=$((index + 1))
        info "尝试拉取源码 (${index}/${total}): ${url}"
        if fetch_repo_via_git "${url}"; then
            ok "源码已就绪: $(git -C "${FORWARD_REPO_DIR}" rev-parse --short HEAD)"
            return 0
        fi
        warn "源码拉取失败，尝试下一个源: ${url}"
    done

    mapfile -t archive_urls < <(resolve_repo_archive_urls)
    total="${#archive_urls[@]}"
    index=0
    for url in "${archive_urls[@]}"; do
        [[ -n "${url}" ]] || continue
        index=$((index + 1))
        info "尝试源码归档回退 (${index}/${total}): ${url}"
        if fetch_repo_via_archive "${url}"; then
            [[ -f "${FORWARD_REPO_DIR}/release.sh" ]] || fail "源码归档缺少 release.sh，无法继续构建"
            ok "源码已通过归档回退方式就绪: ${FORWARD_REF}"
            return 0
        fi
        warn "源码归档回退失败，尝试下一个源: ${url}"
    done

    fail "拉取源码失败，Git 拉取与归档回退均不可用"
}

build_release() {
    cd "${FORWARD_REPO_DIR}"
    bash ./release.sh "${GOARCH}"
    ok "构建完成"
}

run_deploy() {
    cd "${FORWARD_REPO_DIR}"
    bash ./deploy.sh "${DEPLOY_ARGS[@]}"
}

main() {
    require_command dpkg
    require_command apt-get
    require_command curl
    require_command tar

    set_step "检测架构"
    detect_arch
    FORWARD_GO_TARBALL="${FORWARD_WORKDIR}/go${FORWARD_GO_VERSION}.linux-${GO_TARBALL_ARCH}.tar.gz"
    set_step "检查内存"
    warn_low_memory
    set_step "检查发行版"
    require_supported_distro
    set_step "安装系统依赖"
    install_apt_deps
    set_step "检查 Git"
    require_command git
    set_step "安装 Go"
    install_go_if_needed
    set_step "配置 Go 模块代理"
    configure_go_module_env
    set_step "拉取源码"
    clone_repo
    set_step "构建 release"
    build_release
    set_step "执行部署"
    run_deploy
}

main
