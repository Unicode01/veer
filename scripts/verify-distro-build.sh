#!/usr/bin/env sh
set -eu

# Run only inside disposable CI containers; use the real bootstrap package lists.
[ "${VEER_PLATFORM_TEST_CONTAINER:-}" = 1 ] || { echo 'requires a disposable platform test container' >&2; exit 1; }
. /etc/os-release
case "$ID" in
    debian|ubuntu)
        apt-get update
        apt-get install -y --no-install-recommends bash python3
        ;;
    alpine) apk add --no-cache bash python3 ;;
    *) dnf install -y bash python3 ;;
esac

mkdir -p /work/veer
cp -R /src/. /work/veer/
cd /work/veer
python3 scripts/verify-platform-behavior.py --library bootstrap > /work/bootstrap-functions.sh
bash -c '. /work/bootstrap-functions.sh; FORWARD_SKIP_DEPS=0; require_supported_distro; install_system_deps; require_runtime_tools'
python3 scripts/verify-platform-behavior.py
export PATH="/opt/veer-go/bin:$PATH"
export CGO_ENABLED=0
export GOMAXPROCS=2
VEER_BUILD_PLUGIN_SDK=0 bash release.sh amd64
go test ./internal/app ./internal/kernelcap ./internal/tproxysetup -run 'TestPluginHostMountNamespaceOperation|TestEnsureRouting|TestCheckPluginCompatibility' -count=1
