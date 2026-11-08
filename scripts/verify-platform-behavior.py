#!/usr/bin/env python3

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BASH = os.environ.get("VEER_TEST_BASH", "bash")
BOOTSTRAP_FUNCTIONS = (
    "version_ge", "os_major_version", "os_id_like_contains", "require_supported_distro",
    "detect_package_manager", "run_with_retry", "rpm_dependency_package", "install_system_deps", "require_runtime_tools",
    "require_build_tools", "file_sha256", "github_repo_slug_from_url", "resolve_install_mode", "resolve_release_tag",
    "resolve_release_base_urls", "release_asset_checksum", "download_release",
)
BUILD_PACKAGES = ("clang", "git", "llvm")
LOGGING = """
info() { printf '%s\\n' "$*"; }
ok() { printf '%s\\n' "$*"; }
warn() { printf '%s\\n' "$*" >&2; }
fail() { printf '%s\\n' "$*" >&2; exit 1; }
"""


def shell_function(filename: str, name: str) -> str:
    source = (ROOT / filename).read_text(encoding="utf-8")
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n", source, re.M)
    if match is None:
        raise AssertionError(f"missing shell function: {filename}:{name}")
    lines = []
    delimiter = None
    for line in source[match.start():].splitlines(keepends=True):
        lines.append(line)
        if delimiter is not None:
            if line.rstrip("\n") == delimiter:
                delimiter = None
            continue
        heredoc = re.search(r"<<['\"]?([A-Za-z_][A-Za-z_0-9]*)['\"]?", line)
        if heredoc:
            delimiter = heredoc[1]
        elif line == "}\n":
            return "".join(lines)
    raise AssertionError(f"unterminated shell function: {filename}:{name}")


def library(kind: str) -> str:
    filename, names = (
        ("bootstrap.sh", BOOTSTRAP_FUNCTIONS) if kind == "bootstrap"
        else ("deploy.sh", ("write_service_definition", "prepare_selinux_labels", "collect_kernel_helper_modules"))
    )
    return "set -eu\n" + LOGGING + "\n".join(shell_function(filename, name) for name in names)


def run_shell(source: str, **variables: str) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment.update(variables)
    return subprocess.run([BASH, "-c", source], env=environment, text=True, encoding="utf-8",
                          capture_output=True, check=False, timeout=30)


class PlatformBehaviorTests(unittest.TestCase):
    def test_installer_dependencies(self):
        cases = [(manager, "0", scope) for manager in ("apt", "dnf", "yum", "apk") for scope in ("runtime", "build")]
        cases += [(manager, "1", "runtime") for manager in ("dnf", "yum")]
        for manager, minimal, scope in cases:
            with self.subTest(manager=manager, minimal=minimal, scope=scope):
                source = library("bootstrap") + """
ok() { :; }
detect_package_manager() { printf '%s' "$TEST_MANAGER"; }
rpm() { test "$TEST_RPM_MINIMAL" = 1; }
run_with_retry() { shift 3; printf '%s\\n' "$@"; }
install_system_deps "$TEST_SCOPE"
"""
                result = run_shell(source, FORWARD_SKIP_DEPS="0", TEST_MANAGER=manager, TEST_RPM_MINIMAL=minimal,
                                   TEST_SCOPE=scope)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = result.stdout.splitlines()
                for package in ("iptables", "nftables", "util-linux", "ethtool", "python3", "tar"):
                    self.assertIn(package, arguments)
                self.assertIn("curl-minimal" if minimal == "1" else "curl", arguments)
                self.assertIn("coreutils-single" if minimal == "1" else "coreutils", arguments)
                self.assertNotIn("--allowerasing", arguments)
                if manager == "apk":
                    self.assertIn("openrc", arguments)
                # Release installs need no toolchain; only source builds pull it in.
                for package in BUILD_PACKAGES:
                    if scope == "build":
                        self.assertIn(package, arguments)
                    else:
                        self.assertNotIn(package, arguments)

    def test_install_mode(self):
        source = library("bootstrap") + "\nresolve_install_mode\n"
        for mode, explicit, expected in (
            ("auto", "0", "auto"), ("auto", "1", "source"),
            ("release", "1", "release"), ("source", "0", "source"),
        ):
            with self.subTest(mode=mode, explicit_ref=explicit):
                result = run_shell(source, FORWARD_INSTALL_MODE=mode, FORWARD_REF_EXPLICIT=explicit)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_release_tag_resolution(self):
        source = library("bootstrap") + """
curl() { printf '%s' "$TEST_EFFECTIVE_URL"; }
resolve_release_tag Unicode01/veer
"""
        latest = "https://github.com/Unicode01/veer/releases"
        for version, effective, expected in (
            ("latest", latest + "/tag/v1.2.3", "v1.2.3"),
            ("v1.0.0-rc.1", "", "v1.0.0-rc.1"),
            # Without any release GitHub redirects to the release list.
            ("latest", latest, None),
            ("latest", latest + "/tag/v1.2.3;rm", None),
            ("latest", "https://github.com/other/veer/releases/tag/v9.9.9", None),
        ):
            with self.subTest(version=version, effective=effective):
                result = run_shell(source, FORWARD_VERSION=version, TEST_EFFECTIVE_URL=effective)
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, expected)

    def test_release_checksum_lookup(self):
        digest = "ab" * 32
        sums = f"{digest.upper()}  veer-linux-amd64.tar.gz\n{'cd' * 32} *veer-linux-arm64.tar.gz\nnot-a-digest  veer-plugin-sdk.tar.gz\n"
        source = library("bootstrap") + '\nrelease_asset_checksum "$TEST_SUMS" "$TEST_ASSET"\n'
        with tempfile.TemporaryDirectory(prefix="veer-sums-") as temp:
            path = Path(temp) / "sha256sums.txt"
            path.write_text(sums, encoding="utf-8")
            for asset, expected in (
                ("veer-linux-amd64.tar.gz", digest), ("veer-linux-arm64.tar.gz", "cd" * 32),
                ("veer-plugin-sdk.tar.gz", None), ("veer-linux-riscv64.tar.gz", None),
            ):
                with self.subTest(asset=asset):
                    result = run_shell(source, TEST_SUMS=path.as_posix(), TEST_ASSET=asset)
                    if expected is None:
                        self.assertNotEqual(result.returncode, 0)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, expected)

    def test_release_download(self):
        source = library("bootstrap") + """
safe_remove_bootstrap_path() { rm -rf -- "$1"; }
FORWARD_DEPLOY_DIR=""
if download_release; then
    printf 'deploy=%s\\n' "$FORWARD_DEPLOY_DIR"
    cat "$FORWARD_DEPLOY_DIR/VERSION"
else
    echo unavailable
fi
"""
        for case in ("valid", "tampered", "unlisted", "missing"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="veer-release-") as temp:
                root = Path(temp)
                mirror, work, stage = root / "mirror", root / "work", root / "stage" / "veer-linux-amd64"
                for directory in (mirror, work, stage):
                    directory.mkdir(parents=True)
                for name, body in (("veer-linux-amd64", "binary"), ("deploy.sh", "deploy"),
                                   ("config.example.json", "{}"), ("VERSION", "v1.2.3\n")):
                    (stage / name).write_text(body, encoding="utf-8")
                archive = mirror / "veer-linux-amd64.tar.gz"
                subprocess.run(["tar", "-C", stage.parent.as_posix(), "-czf", archive.as_posix(), "veer-linux-amd64"],
                               check=True)
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                listed = "veer-linux-arm64.tar.gz" if case == "unlisted" else "veer-linux-amd64.tar.gz"
                (mirror / "sha256sums.txt").write_text(f"{digest}  {listed}\n", encoding="utf-8")
                if case == "tampered":
                    archive.write_bytes(archive.read_bytes() + b"\0")
                if case == "missing":
                    archive.unlink()
                result = run_shell(
                    source, GOARCH="amd64", FORWARD_WORKDIR=work.as_posix(),
                    FORWARD_RELEASE_DIR=(work / "release").as_posix(),
                    FORWARD_RELEASE_BASE_URL=mirror.as_uri(), FORWARD_REPO_URL="https://example.invalid/veer.git",
                    FORWARD_VERSION="latest",
                )
                if case == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"deploy={(work / 'release' / 'veer-linux-amd64').as_posix()}\nv1.2.3\n", result.stdout)
                elif case == "missing":
                    # Nothing served is not fatal: auto mode falls back to a source build.
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("unavailable", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("SHA-256", result.stderr)
                    self.assertFalse((work / "release").exists(), "an unverified archive must not be unpacked")

    def test_missing_iptables_fails_preflight(self):
        source = library("bootstrap") + """
command() { test "$2" != "$TEST_MISSING_TOOL"; }
require_runtime_tools
"""
        for missing, expected in (("iptables", 1), ("", 0)):
            with self.subTest(missing=missing):
                result = run_shell(source, TEST_MISSING_TOOL=missing)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected:
                    self.assertIn("iptables", result.stderr)

    def test_kernel_helper_module_collection(self):
        # bootstrap deploys from the repo, where the build leaves kernel/veer_kfuncs/veer_kfuncs.ko.
        source = library("deploy") + """
modinfo() { sed -n 's/^vermagic=//p' "$3"; }
KERNEL_MODULE_RELEASES=()
collect_kernel_helper_modules "$TEST_DIR"
printf '%s\\n' "${KERNEL_MODULE_RELEASES[@]}"
"""
        built = "6.12.74+deb12-cloud-amd64"
        cases = (
            ({"veer_kfuncs": built, built: built, "5.14.0-427.el9.x86_64": "5.14.0-427.el9.x86_64"},
             0, "5.14.0-427.el9.x86_64\n" + built + "\n"),
            ({"6.1.0-31-amd64": built}, 1, "vermagic"),
            ({"latest": built}, 1, "目录名不是内核版本"),
        )
        for directories, expected, output in cases:
            with self.subTest(directories=sorted(directories)), tempfile.TemporaryDirectory(prefix="veer-kmod-") as temp:
                for directory, vermagic in directories.items():
                    module = Path(temp) / "kernel" / directory / "veer_kfuncs.ko"
                    module.parent.mkdir(parents=True)
                    module.write_text(f"vermagic={vermagic} SMP preempt mod_unload\n", encoding="utf-8")
                result = run_shell(source, TEST_DIR=Path(temp).as_posix())
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertIn(output, result.stdout if expected == 0 else result.stderr)

    def test_generated_services(self):
        for manager in ("systemd", "openrc"):
            with self.subTest(manager=manager), tempfile.TemporaryDirectory(prefix="veer-unit-") as temp:
                unit = Path(temp) / "service"
                result = run_shell(library("deploy") + "\nwrite_service_definition\n",
                                   SERVICE_MANAGER=manager, SERVICE_FILE=unit.as_posix(),
                                   INSTALL_DIR=Path(temp).as_posix(), HOT_RESTART_MARKER="/opt/veer-test/.hot",
                                   BPF_STATE_DIR="/sys/fs/bpf/veer-test", RUNTIME_STATE_DIR="/opt/veer-test/.state",
                                   SERVICE_NAME="veer-test")
                self.assertEqual(result.returncode, 0, result.stderr)
                definition = unit.read_text(encoding="utf-8")
                if manager == "systemd":
                    entries = [line.split("=", 1) for line in definition.splitlines() if "=" in line]
                    self.assertIn(["ProtectSystem", "strict"], entries)
                    self.assertIn(["PrivateTmp", "true"], entries)
                    self.assertIn(["ReadWritePaths", "/run/netns"], entries)
                    self.assertIn(["LimitNOFILE", "65535"], entries)
                    self.assertIn(["Environment", "VEER_HOST_MOUNT_NAMESPACE=/proc/1/ns/mnt"], entries)
                    for key in ("AmbientCapabilities", "CapabilityBoundingSet"):
                        value = next(value for name, value in entries if name == key)
                        self.assertIn("CAP_SYS_PTRACE", value.split())
                else:
                    result = run_shell('source "$TEST_SERVICE_FILE"\nprintf "%s\\n" "$rc_ulimit" "$supervisor"',
                                       TEST_SERVICE_FILE=unit.as_posix())
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), ["-n 65535", "supervise-daemon"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", choices=("bootstrap", "deploy"))
    options = parser.parse_args()
    if options.library:
        print(library(options.library))
    else:
        unittest.main(argv=[__file__], verbosity=2)
