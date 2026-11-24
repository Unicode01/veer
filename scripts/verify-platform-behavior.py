#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import pty
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BASH = os.environ.get("VEER_TEST_BASH", "bash")
BOOTSTRAP_FUNCTIONS = (
    "version_ge", "os_major_version", "os_id_like_contains", "require_supported_distro",
    "detect_package_manager", "run_with_retry", "rpm_dependency_package", "install_system_deps", "require_runtime_tools",
    "require_build_tools", "file_sha256", "github_repo_slug_from_url", "resolve_install_mode", "resolve_release_tag",
    "resolve_release_base_urls", "release_asset_checksum", "download_release", "count_installed_plugins",
    "rust_targets_for_arch", "zig_available", "missing_rust_tools", "describe_rust_tools", "bootstrap_workdir_space",
    "ask_rust_install", "check_source_build_plugins", "pinned_zig_sha256", "resolve_zig_download_urls", "install_zig",
)
DEPLOY_FUNCTIONS = (
    "write_service_definition", "prepare_selinux_labels", "collect_kernel_helper_modules", "safe_remove_install_path",
    "restore_bundled_plugins", "install_bundled_plugins", "check_installed_plugins",
)
BUILD_PACKAGES = ("clang", "gcc", "git", "llvm")
LOGGING = """
YELLOW=''
NC=''
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
        else ("deploy.sh", DEPLOY_FUNCTIONS)
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

    def test_installed_plugin_check(self):
        # Plugins ship with the release: every installed plugin the bundle
        # provides is replaced by the bundle's version unless the installed
        # one is newer; another plugin the new version cannot run stops the
        # deploy before anything changes.
        source = library("deploy") + """
check_installed_plugins "$TEST_PHASE"
printf 'upgrade=%s keep=%s\\n' "$PLUGIN_UPGRADE_IDS" "$PLUGIN_KEEP_IDS"
install_bundled_plugins
"""
        cases = {
            "old plugin in the bundle is replaced": dict(
                plugins=[("wan_core", "blocked", "control_script"), ("vpn_core", "ok", "")],
                rc=0, upgrade="wan_core", replaced=True, says="[替换] wan_core 1.7.0"),
            "an older plugin that runs is updated too": dict(
                plugins=[("wan_core", "ok", ""), ("vpn_core", "ok", "")],
                rc=0, upgrade="wan_core", replaced=True, says="[更新] wan_core 1.7.0 -> 1.8.0"),
            "the same version with other files is refreshed from the bundle": dict(
                plugins=[("wan_core", "ok", "")], installed="1.8.0", rc=0, upgrade="wan_core", replaced=True,
                says="[重装] wan_core 1.8.0"),
            "the same version with the bundle's files is left alone": dict(
                plugins=[("wan_core", "ok", "")], installed="1.8.0", identical=True, rc=0, upgrade="",
                keep="wan_core", says="[相同] wan_core 1.8.0"),
            "a newer installed plugin is kept": dict(
                plugins=[("wan_core", "ok", "")], installed="1.10.0", rc=0, upgrade="", keep="wan_core",
                says="[保留] wan_core 1.10.0"),
            "plugins that do not run yet are updated as well": dict(
                plugins=[], rc=0, upgrade="wan_core", replaced=True),
            "stop on plugin outside the bundle": dict(
                plugins=[("vpn_core", "blocked", "control_script")], rc=1, says="1 个已安装插件无法在新版本运行"),
            "allow incompatible plugins": dict(
                plugins=[("vpn_core", "blocked", "control_script")], allow="1", rc=0, upgrade="wan_core", replaced=True,
                says="这些插件将停止工作"),
            "a missing worker is not fixed by the bundle": dict(
                plugins=[("wan_core", "blocked", "no_worker")], rc=1, says="没有插件 worker"),
            "warnings do not stop": dict(
                plugins=[("wan_core", "warning", "catalog_error")], rc=0, upgrade="wan_core", replaced=True,
                says="[注意] wan_core"),
            "without a bundle installed plugins stay": dict(
                plugins=[("wan_core", "ok", "")], bundle=False, rc=0, upgrade="", says="已安装插件保持现有版本"),
            "after the bundle a blocked plugin fails": dict(
                plugins=[("wan_core", "blocked", "control_script")], phase="after", rc=1),
            "check that fails stops": dict(raw="boom", status="2", rc=1, says="插件兼容性检查未完成"),
            "no config means a fresh install": dict(raw="unused", config=False, rc=0, upgrade="", called=False),
        }
        for name, case in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="veer-plugin-check-") as temp:
                root = Path(temp)
                install, bundle_root = root / "install", root / "bundle"
                plugins = install / "plugins"
                installed = {"wan_core": case.get("installed", "1.7.0"), "vpn_core": "0.12.0"}
                for plugin, version in installed.items():
                    (plugins / plugin).mkdir(parents=True)
                    (plugins / plugin / "plugin.json").write_text(json.dumps({"id": plugin, "version": version}),
                                                                   encoding="utf-8")
                    (plugins / plugin / "control.js").write_text("old", encoding="utf-8")
                for plugin, version in (("wan_core", "1.8.0"), ("lan_core", "1.5.0")):
                    (bundle_root / "plugins" / plugin / "lib").mkdir(parents=True)
                    (bundle_root / "plugins" / plugin / "plugin.json").write_text(
                        json.dumps({"id": plugin, "version": version}), encoding="utf-8")
                    (bundle_root / "plugins" / plugin / "lib" / f"lib{plugin}.so").write_text("new", encoding="utf-8")
                if case.get("identical"):
                    # Installed from this bundle before: the same files.
                    shutil.rmtree(plugins / "wan_core")
                    shutil.copytree(bundle_root / "plugins" / "wan_core", plugins / "wan_core")
                    installed_mtime = (plugins / "wan_core" / "lib" / "libwan_core.so").stat().st_mtime_ns
                bundle = root / "veer-plugins.tar.gz"
                if case.get("bundle", True):
                    subprocess.run(["tar", "-C", bundle_root.as_posix(), "-czf", bundle.as_posix(), "plugins"], check=True)
                if case.get("config", True):
                    (install / "config.json").write_text('{"plugins_enabled": true}', encoding="utf-8")
                report = case.get("raw") or json.dumps({
                    "verdict": "ok", "plugins_enabled": True, "plugins_dir": plugins.as_posix(), "worker": True,
                    "plugins": [{"id": plugin, "version": installed.get(plugin, ""), "dir": plugin, "status": status,
                                 "problem": problem, "reason": f"{problem} reason"}
                                for plugin, status, problem in case["plugins"]],
                })
                (root / "report.json").write_text(report, encoding="utf-8")
                binary = root / "veer-linux-amd64"
                binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_ARGS"\ncat "$TEST_REPORT"\nexit "$TEST_STATUS"\n',
                                  encoding="utf-8")
                binary.chmod(0o755)
                result = run_shell(
                    source, TEST_PHASE=case.get("phase", "before"), TEST_REPORT=(root / "report.json").as_posix(),
                    TEST_STATUS=case.get("status", "0"), TEST_ARGS=(root / "args").as_posix(),
                    INSTALL_DIR=install.as_posix(), BINARY_PATH=binary.as_posix(), PLUGIN_BUNDLE_PATH=bundle.as_posix(),
                    INSTALL_BUNDLED_PLUGINS="0", ALLOW_INCOMPATIBLE_PLUGINS=case.get("allow", "0"), PLUGIN_UPGRADE_IDS="",
                    PLUGIN_KEEP_IDS="", PLUGIN_INSTALL_DIR=plugins.as_posix(),
                    PLUGIN_STAGING_DIR=(install / ".plugins.next").as_posix(),
                    PLUGIN_BACKUP_DIR=(install / ".plugins.rollback").as_posix(),
                    PLUGIN_BUNDLE_APPLIED="false", PLUGIN_INSTALL_EXISTED="false",
                )
                self.assertEqual(result.returncode, case["rc"], result.stdout + result.stderr)
                if "says" in case:
                    self.assertIn(case["says"], result.stdout + result.stderr)
                if "upgrade" in case:
                    self.assertIn(f"upgrade={case['upgrade']} keep={case.get('keep', '')}\n", result.stdout)
                # Python 3.12+ warns when tar extraction names no filter.
                self.assertNotIn("DeprecationWarning", result.stderr)
                if case.get("identical"):
                    self.assertIn("没有需要安装或更新的插件", result.stdout)
                    self.assertEqual((plugins / "wan_core" / "lib" / "libwan_core.so").stat().st_mtime_ns,
                                     installed_mtime, "an identical plugin is not copied again")
                else:
                    replaced = case.get("replaced", False)
                    self.assertEqual((plugins / "wan_core" / "lib" / "libwan_core.so").exists(), replaced)
                    self.assertEqual((plugins / "wan_core" / "control.js").exists(), not replaced)
                self.assertTrue((plugins / "vpn_core" / "control.js").exists(), "plugins outside the bundle stay")
                # Plugins that were not installed stay out.
                self.assertFalse((plugins / "lan_core").exists())
                # The check runs a copy of the new binary from the install directory.
                self.assertEqual(list(install.glob(".veer-plugin-check.*")), [])
                if case.get("called", True):
                    args = (root / "args").read_text(encoding="utf-8").splitlines()
                    self.assertEqual(args, ["plugin", "preflight", "--json", "--install-dir", install.as_posix(),
                                            "--config", (install / "config.json").as_posix()])
                else:
                    self.assertFalse((root / "args").exists())

    def test_source_build_rust_decision(self):
        # A source build without the Rust tools makes a veer that runs no
        # plugin: bootstrap installs them on request, and stops without them
        # when this host runs plugins or the plugin bundle is wanted.
        source = library("bootstrap") + """
missing_rust_tools() { printf '%s' "$TEST_MISSING"; }
ask_rust_install() { echo asked; return "$TEST_ANSWER"; }
check_source_build_plugins
printf 'install=%s bundle=%s\\n' "$FORWARD_RUST_INSTALL" "$FORWARD_BUILD_PLUGIN_BUNDLE"
"""
        script = {"id": "old", "control": {"main": "control.js"}}
        native = {"id": "new", "control": {"library": {"x86_64-linux-gnu": {"path": "lib/libnew.so"}}}}
        # name: (plugins enabled, manifests, bundle wanted, missing, VEER_INSTALL_RUST, answer, rc, output)
        cases = {
            "asked and accepted": (True, [script, native], "0", "rust zig", "ask", 0, 0, "install=1 bundle=1"),
            "declined with plugins": (True, [native], "0", "rust", "ask", 1, 1, "本机已安装并启用 1 个插件"),
            "no terminal with plugins": (True, [native], "0", "zig", "ask", 2, 1, "VEER_INSTALL_RUST=1"),
            "VEER_INSTALL_RUST=1 does not ask": (True, [native], "0", "rust", "1", 9, 0, "install=1 bundle=1"),
            "VEER_INSTALL_RUST=0 with plugins": (True, [native], "0", "rust", "0", 0, 1, "Rust 1.88.0+"),
            "bundle wanted": (None, [], "1", "cargo-zigbuild", "ask", 1, 1, "VEER_INSTALL_PLUGINS=1"),
            "no plugins, no terminal": (False, [script], "0", "rust", "ask", 2, 0, "install=0 bundle=0"),
            "no plugins, declined": (None, [], "0", "rust", "ask", 1, 0, "不能运行插件"),
            "tools present": (True, [script], "0", "", "ask", 9, 0, "install=0 bundle=1"),
        }
        for name, (enabled, manifests, bundle, missing, mode, answer, expected, output) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="veer-source-plugins-") as temp:
                root = Path(temp)
                if enabled is not None:
                    (root / "config.json").write_text(json.dumps({"plugins_enabled": enabled}), encoding="utf-8")
                for manifest in manifests:
                    path = root / "plugins" / manifest["id"] / "plugin.json"
                    path.parent.mkdir(parents=True)
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                result = run_shell(source, INSTALL_DIR=root.as_posix(), FORWARD_BUILD_PLUGIN_BUNDLE=bundle,
                                   TEST_MISSING=missing, FORWARD_INSTALL_RUST=mode, TEST_ANSWER=str(answer),
                                   FORWARD_RUST_MIN_VERSION="1.88.0", FORWARD_RUST_ROOT=(root / "rust").as_posix())
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertIn(output, result.stdout + result.stderr)
                self.assertEqual("asked" in result.stdout, mode == "ask" and missing != "", result.stdout)

    def test_missing_rust_tools(self):
        source = library("bootstrap") + """
command() {
    if [ "$1" = -v ]; then
        case " $TEST_PRESENT " in *" $2 "*) return 0 ;; esac
        return 1
    fi
    builtin command "$@"
}
rustc() { if [ "$1" = --version ]; then echo "rustc $TEST_RUSTC (abc 2026-01-01)"; else echo "$TEST_SYSROOT"; fi; }
python3() { return 1; }
missing_rust_tools
"""
        everything = "cargo rustc cargo-zigbuild zig"
        both = ("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl")
        cases = (
            ("complete", everything, "1.100.0", both, ""),
            ("old rustc", everything, "1.80.1", both, "rust"),
            ("no cargo", "rustc cargo-zigbuild zig", "1.100.0", both, "rust"),
            ("musl target missing", everything, "1.100.0", both[:1], "target:x86_64-unknown-linux-musl"),
            ("no zigbuild or zig", "cargo rustc", "1.100.0", both, "cargo-zigbuild zig"),
        )
        for name, present, version, targets, expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="veer-rust-tools-") as temp:
                for target in targets:
                    (Path(temp) / "lib" / "rustlib" / target).mkdir(parents=True)
                result = run_shell(source, GOARCH="amd64", TEST_PRESENT=present, TEST_RUSTC=version,
                                   TEST_SYSROOT=temp, FORWARD_RUST_MIN_VERSION="1.88.0", ZIG="")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_rust_install_prompt(self):
        # The question goes to the controlling terminal, so it also works
        # under curl | bash; without one there is no answer to wait for.
        source = library("bootstrap") + """
FORWARD_RUST_MISSING="rust zig"
status=0
ask_rust_install "本机已安装并启用 1 个插件" "$TEST_REQUIRED" || status=$?
echo "status=$status"
"""
        environment = dict(os.environ, FORWARD_RUST_MIN_VERSION="1.88.0", FORWARD_RUST_ROOT="/tmp/veer-test/rust",
                           FORWARD_WORKDIR=tempfile.gettempdir())
        for required, answer, expected in (("1", "", 0), ("1", "n", 1), ("0", "", 1), ("0", "Y", 0)):
            with self.subTest(required=required, answer=answer):
                pid, fd = pty.fork()
                if pid == 0:
                    os.execvpe(BASH, [BASH, "-c", source], dict(environment, TEST_REQUIRED=required))
                output = b""
                answered = False
                while True:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                    if not answered and (b"[Y/n]" in output or b"[y/N]" in output):
                        os.write(fd, answer.encode() + b"\n")
                        answered = True
                os.waitpid(pid, 0)
                text = output.decode("utf-8", "replace")
                self.assertIn("缺少: Rust 1.88.0+ (cargo 与 rustc)、zig", text)
                self.assertIn("[Y/n]" if required == "1" else "[y/N]", text)
                self.assertIn(f"status={expected}", text)
        result = subprocess.run([BASH, "-c", source], env=dict(environment, TEST_REQUIRED="1"), text=True,
                                encoding="utf-8", capture_output=True, timeout=30, start_new_session=True)
        self.assertIn("status=2", result.stdout, result.stderr)

    def test_zig_install(self):
        source = library("bootstrap") + """
install_zig
command -v zig
zig
"""
        for case in ("valid", "tampered"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="veer-zig-") as temp:
                root = Path(temp)
                stage = root / "stage" / "zig-x86_64-linux-0.99.0"
                stage.mkdir(parents=True)
                (stage / "zig").write_text("#!/bin/sh\necho zig-ok\n", encoding="utf-8")
                (stage / "zig").chmod(0o755)
                mirror = root / "mirror" / "0.99.0"
                mirror.mkdir(parents=True)
                archive = mirror / "zig-x86_64-linux-0.99.0.tar.xz"
                subprocess.run(["tar", "-C", stage.parent.as_posix(), "-cJf", archive.as_posix(), stage.name], check=True)
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                if case == "tampered":
                    digest = "0" * 64
                (root / "rust").mkdir()
                result = run_shell(source, GOARCH="amd64", FORWARD_RUST_ROOT=(root / "rust").as_posix(),
                                   FORWARD_ZIG_VERSION="0.99.0", FORWARD_ZIG_SHA256=digest,
                                   FORWARD_ZIG_BASE_URL=(root / "mirror").as_uri())
                if case == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"{(root / 'rust' / stage.name / 'zig').as_posix()}\nzig-ok\n", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("SHA-256 不匹配", result.stderr)
                    self.assertFalse((root / "rust" / stage.name).exists(), "an unverified archive must not be unpacked")
        # An unknown version has no pinned checksum.
        result = run_shell(source, GOARCH="arm64", FORWARD_RUST_ROOT=tempfile.gettempdir(), FORWARD_ZIG_VERSION="0.1.0",
                           FORWARD_ZIG_SHA256="", FORWARD_ZIG_BASE_URL="file:///nonexistent")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VEER_ZIG_SHA256", result.stderr)

    def test_zig_download_sources(self):
        # ziglang.org is slow from mainland China: the domestic mirror goes
        # first there; VEER_ZIG_BASE_URL replaces the list.
        source = library("bootstrap") + '\nresolve_zig_download_urls zig-x86_64-linux-0.15.2.tar.xz\n'
        file = "zig-x86_64-linux-0.15.2.tar.xz"
        official = f"https://ziglang.org/download/0.15.2/{file}"
        domestic = f"https://fs.liujiacai.net/zigbuilds/{file}"
        mirror = f"https://zig.linus.dev/zig/{file}"
        for region, base, expected in (
            ("cn", "", [domestic, official, mirror]),
            ("global", "", [official, mirror, domestic]),
            ("cn", "https://zig.example.invalid/dl/", [f"https://zig.example.invalid/dl/0.15.2/{file}"]),
        ):
            with self.subTest(region=region, base=base):
                result = run_shell(source, FORWARD_ZIG_VERSION="0.15.2", FORWARD_ZIG_BASE_URL=base,
                                   FORWARD_GO_EFFECTIVE_REGION=region)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), expected)

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
