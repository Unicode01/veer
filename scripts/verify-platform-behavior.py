#!/usr/bin/env python3

import argparse
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
)
LOGGING = """
info() { printf '%s\\n' "$*"; }
ok() { printf '%s\\n' "$*"; }
warn() { printf '%s\\n' "$*" >&2; }
fail() { printf '%s\\n' "$*" >&2; exit 1; }
"""


def shell_function(filename: str, name: str) -> str:
    source = (ROOT / filename).read_text(encoding="utf-8")
    # Top-level closing braces are followed by a blank line, unlike heredoc bodies.
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n(?=\n|\Z)", source, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing shell function: {filename}:{name}")
    return match.group()


def library(kind: str) -> str:
    filename, names = (
        ("bootstrap.sh", BOOTSTRAP_FUNCTIONS) if kind == "bootstrap"
        else ("deploy.sh", ("write_service_definition",))
    )
    return "set -eu\n" + LOGGING + "\n".join(shell_function(filename, name) for name in names)


def run_shell(source: str, **variables: str) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment.update(variables)
    return subprocess.run([BASH, "-c", source], env=environment, text=True, encoding="utf-8",
                          capture_output=True, check=False, timeout=30)


class PlatformBehaviorTests(unittest.TestCase):
    def test_installer_dependencies(self):
        cases = [(manager, "0") for manager in ("apt", "dnf", "yum", "apk")]
        cases += [(manager, "1") for manager in ("dnf", "yum")]
        for manager, minimal in cases:
            with self.subTest(manager=manager, minimal=minimal):
                source = library("bootstrap") + """
ok() { :; }
detect_package_manager() { printf '%s' "$TEST_MANAGER"; }
rpm() { test "$TEST_RPM_MINIMAL" = 1; }
run_with_retry() { shift 3; printf '%s\\n' "$@"; }
install_system_deps
"""
                result = run_shell(source, FORWARD_SKIP_DEPS="0", TEST_MANAGER=manager, TEST_RPM_MINIMAL=minimal)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = result.stdout.splitlines()
                for package in ("iptables", "nftables", "util-linux", "ethtool", "python3"):
                    self.assertIn(package, arguments)
                self.assertIn("curl-minimal" if minimal == "1" else "curl", arguments)
                self.assertIn("coreutils-single" if minimal == "1" else "coreutils", arguments)
                self.assertNotIn("--allowerasing", arguments)
                if manager == "apk":
                    self.assertIn("openrc", arguments)

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

    def test_generated_services(self):
        for manager in ("systemd", "openrc"):
            with self.subTest(manager=manager), tempfile.TemporaryDirectory(prefix="veer-unit-") as temp:
                unit = Path(temp) / "service"
                result = run_shell(library("deploy") + "\nwrite_service_definition\n",
                                   SERVICE_MANAGER=manager, SERVICE_FILE=unit.as_posix(),
                                   INSTALL_DIR="/opt/veer-test", HOT_RESTART_MARKER="/opt/veer-test/.hot",
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
