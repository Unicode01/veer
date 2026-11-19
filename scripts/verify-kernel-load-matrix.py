#!/usr/bin/env python3
"""Load veer's embedded eBPF collections on pinned distribution kernels.

Each kernel boots in a disposable QEMU guest whose initramfs holds busybox,
the cross-built `internal/app` test binary, the repository's eBPF sources and
objects, and the bundled plugins' objects listed in PLUGIN_OBJECTS. The guest
runs TestLoadEmbeddedKernelCollectionsSmoke, which loads the TC, TC-stats, XDP
and XDP-stats collections and the XDP plugin dispatcher the way the runtime
does, and TestLoadBundledPluginObjectsSmoke, which loads each plugin object
behind that dispatcher the way the XDP plugin runtime does. A verifier that
rejects any program, or a skipped test, fails the check. With --host the same
tests also run on the kernel this script runs on, such as a CI runner's.

Older verifiers are the ones that break: on Ubuntu 22.04's first kernel
(5.15.0-25) a single BPF-to-BPF call in the TC object once pushed
forward_ingress_v4_egress_nat past the 1M-instruction limit, while newer
kernels loaded it without trouble.
"""

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
UBUNTU_POOL = "http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/"
# Launchpad's librarian keeps every Ubuntu upload, after the archive drops it.
LAUNCHPAD = "https://launchpad.net/ubuntu/+archive/primary/+files/"
DEBIAN_SIGNED = "/pool/main/l/linux-signed-amd64/"
# Kernel image packages: (package file, SHA256, sources tried in order). The
# last source of each is an archive that keeps the file for good.
KERNELS = {
    "debian-11": (
        "linux-image-5.10.0-32-cloud-amd64_5.10.223-1_amd64.deb",
        "fb4a1229952d892138532c1d9f40a7fd0bd408e4dcf969c12e4524b6a89fdcb8",
        ("http://archive.debian.org/debian" + DEBIAN_SIGNED,
         "https://snapshot.debian.org/archive/debian/20240815T030336Z" + DEBIAN_SIGNED),
    ),
    "ubuntu-22.04-ga": (
        "linux-image-5.15.0-25-generic_5.15.0-25.25_amd64.deb",
        "ad56f8c442a54d4f5ff2dff010d00321d53e32b543f3a92f3ba4e042d20a71da",
        (UBUNTU_POOL, LAUNCHPAD),
    ),
    "ubuntu-22.04-updates": (
        "linux-image-5.15.0-203-generic_5.15.0-203.213_amd64.deb",
        "6c589fa40523261185450e437d39456c8c3e2debf036c31b157f9fae5a803ed1",
        (UBUNTU_POOL, LAUNCHPAD),
    ),
    "debian-12": (
        "linux-image-6.1.0-50-cloud-amd64_6.1.176-1_amd64.deb",
        "efe19f605b6f54a8352e68d85a629abb2d30b72a085faef603a9152590baa791",
        ("https://deb.debian.org/debian" + DEBIAN_SIGNED,
         "https://snapshot.debian.org/archive/debian/20260704T211317Z" + DEBIAN_SIGNED),
    ),
}
TESTS = ("TestLoadEmbeddedKernelCollectionsSmoke", "TestLoadBundledPluginObjectsSmoke")
TEST_PATTERN = "^(" + "|".join(TESTS) + ")$"
# Bundled plugin objects TestLoadBundledPluginObjectsSmoke loads, relative to
# the repository root (scripts/build-plugin-ebpf.sh builds them).
PLUGIN_OBJECTS = ("plugins/firewall/firewall.o",)
INIT = f"""#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmp /tmp
echo "GUEST_KERNEL $(uname -r)"
cd /repo/internal/app
FORWARD_RUN_KERNEL_LOAD_SMOKE=1 ./veer.test -test.run '{TEST_PATTERN}' -test.count=1 -test.v > /tmp/out.txt 2>&1
echo "GUEST_RC $?"
cat /tmp/out.txt
echo "GUEST_END"
poweroff -f
"""
APPLETS = ("sh", "mount", "poweroff", "cat", "echo", "uname")


def fetch_kernel(name, cache):
    """Downloads and checks the kernel package, then extracts its vmlinuz."""
    filename, expected, sources = KERNELS[name]
    package = cache / filename
    if not package.is_file() or sha256(package) != expected:
        for source in sources:
            print(f"download pinned {name} kernel package from {source}", flush=True)
            result = subprocess.run(["curl", "-fsSL", "--retry", "3", "--retry-all-errors",
                                     "--connect-timeout", "30", "--max-time", "600",
                                     "--output", str(package), source + filename], check=False)
            if result.returncode == 0 and sha256(package) == expected:
                break
            print(f"{name}: curl exited with {result.returncode} or the checksum did not match", flush=True)
            package.unlink(missing_ok=True)
        else:
            raise RuntimeError(f"{name} kernel package is unavailable from every source")
    kernel = cache / (package.stem + ".vmlinuz")
    if kernel.is_file():
        return kernel
    # dpkg-deb copes with every data.tar compression the archives use.
    with subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(package)], stdout=subprocess.PIPE) as unpack:
        with tarfile.open(fileobj=unpack.stdout, mode="r|") as archive:
            for member in archive:
                if member.isfile() and re.fullmatch(r"vmlinuz(-.+)?", member.name.rsplit("/", 1)[-1]):
                    kernel.write_bytes(archive.extractfile(member).read())
                    break
        # Let dpkg-deb finish instead of dying on a closed pipe.
        for _ in iter(lambda: unpack.stdout.read(1024 * 1024), b""):
            pass
    if unpack.returncode != 0 or not kernel.is_file():
        kernel.unlink(missing_ok=True)
        raise RuntimeError(f"{name} kernel package holds no vmlinuz")
    return kernel


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class NewcArchive:
    """Writes the initramfs as a newc cpio archive, keeping modification times."""

    def __init__(self, stream):
        self.stream = stream
        self.inode = 1

    def _entry(self, name, mode, data=b"", mtime=0):
        name_bytes = name.encode() + b"\0"
        header = "070701" + "".join(f"{value:08x}" for value in (
            self.inode, mode, 0, 0, 1, int(mtime), len(data), 0, 0, 0, 0, len(name_bytes), 0))
        self.inode += 1
        self.stream.write(header.encode() + name_bytes)
        self.stream.write(b"\0" * (-(110 + len(name_bytes)) % 4))
        self.stream.write(data)
        self.stream.write(b"\0" * (-len(data) % 4))

    def directory(self, name):
        self._entry(name, stat.S_IFDIR | 0o755)

    def file(self, name, source, mode=None):
        info = source.stat()
        self._entry(name, stat.S_IFREG | (mode if mode is not None else stat.S_IMODE(info.st_mode)),
                    source.read_bytes(), info.st_mtime)

    def text(self, name, text, mode):
        self._entry(name, stat.S_IFREG | mode, text.encode(), time.time())

    def symlink(self, name, target):
        self._entry(name, stat.S_IFLNK | 0o777, target.encode())

    def close(self):
        self._entry("TRAILER!!!", 0)


def busybox_libraries(busybox):
    """Lists the shared libraries a dynamically linked busybox needs."""
    result = subprocess.run(["ldd", str(busybox)], capture_output=True, text=True, check=False)
    libraries = []
    for line in result.stdout.splitlines():
        match = re.search(r"(/\S+)\s+\(0x", line)
        if match:
            libraries.append(Path(match.group(1)))
    return libraries


def build_initramfs(path, busybox, test_binary):
    with gzip.open(path, "wb", compresslevel=1) as compressed:
        archive = NewcArchive(compressed)
        for directory in ("bin", "proc", "sys", "dev", "tmp", "repo", "repo/internal", "repo/internal/app"):
            archive.directory(directory)
        archive.file("bin/busybox", busybox, 0o755)
        for applet in APPLETS:
            archive.symlink(f"bin/{applet}", "busybox")
        made = set()
        for library in busybox_libraries(busybox):
            parts = library.parent.parts[1:]
            for depth in range(1, len(parts) + 1):
                directory = "/".join(parts[:depth])
                if directory not in made:
                    archive.directory(directory)
                    made.add(directory)
            archive.file(str(library)[1:], library.resolve(), 0o755)
        archive.text("init", INIT, 0o755)
        # The smoke test finds the repository by go.mod and checks that the
        # objects are newer than their sources.
        archive.file("repo/go.mod", ROOT / "go.mod")
        ebpf = ROOT / "internal/app/ebpf"
        archive.directory("repo/internal/app/ebpf")
        # Sorted paths list every directory before what it holds.
        for source in sorted(ebpf.rglob("*")):
            name = "repo/internal/app/ebpf/" + source.relative_to(ebpf).as_posix()
            if source.is_dir():
                archive.directory(name)
            elif source.is_file():
                archive.file(name, source)
        for relative in PLUGIN_OBJECTS:
            parts = relative.split("/")
            for depth in range(1, len(parts)):
                directory = "repo/" + "/".join(parts[:depth])
                if directory not in made:
                    archive.directory(directory)
                    made.add(directory)
            archive.file("repo/" + relative, ROOT / relative)
        archive.file("repo/internal/app/veer.test", test_binary, 0o755)
        archive.close()


def boot(name, kernel, initramfs, memory, output):
    accelerator = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    console = output / f"{name}-console.log"
    print(f"boot {name}: accelerator={accelerator}, memory={memory} MiB", flush=True)
    started = time.monotonic()
    try:
        # The guest powers off when the test is done; a panic ends QEMU too.
        result = subprocess.run(
            ["qemu-system-x86_64", "-accel", accelerator, "-m", str(memory), "-smp", "2",
             "-cpu", "host" if accelerator == "kvm" else "max",
             "-display", "none", "-monitor", "none", "-serial", f"file:{console}",
             "-no-reboot", "-nic", "none", "-kernel", str(kernel), "-initrd", str(initramfs),
             "-append", "console=ttyS0 rdinit=/init panic=-1 quiet"],
            timeout=900 if accelerator == "kvm" else 3600, check=False)
        if result.returncode != 0:
            print(f"{name}: QEMU exited with {result.returncode}", flush=True)
    except subprocess.TimeoutExpired:
        print(f"{name}: guest timed out", flush=True)
    text = console.read_text(encoding="utf-8", errors="replace").replace("\r", "") if console.exists() else ""
    start, end = text.find("GUEST_KERNEL"), text.find("GUEST_END")
    report = text[start:end] if start >= 0 and end > start else text[-6000:]
    return summarize(name, report, started)


def run_host(test_binary, output):
    """Runs the tests on this machine's kernel, as root, from the checkout."""
    started = time.monotonic()
    print(f"run on the host kernel {os.uname().release}", flush=True)
    env = dict(os.environ, FORWARD_RUN_KERNEL_LOAD_SMOKE="1")
    try:
        result = subprocess.run([str(test_binary), "-test.run", TEST_PATTERN, "-test.count=1", "-test.v"],
                                cwd=ROOT / "internal/app", env=env, capture_output=True, text=True,
                                errors="replace", timeout=900, check=False)
        text, code = result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired as expired:
        partial = expired.stdout or b""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        text, code = partial + "\nhost run timed out\n", "timeout"
    (output / "host-console.log").write_text(text, encoding="utf-8")
    report = f"GUEST_KERNEL {os.uname().release}\nGUEST_RC {code}\n{text}"
    return summarize("host", report, started)


def summarize(name, report, started):
    passed = ("GUEST_RC 0\n" in report and all(f"--- PASS: {test} " in report for test in TESTS)
              and "--- SKIP" not in report and "--- FAIL" not in report)
    if passed:
        lines = [line for line in report.splitlines() if line.startswith(("GUEST_", "=== RUN", "--- "))]
    else:
        lines = report.splitlines()[-80:]
    print("\n".join(line[:300] for line in lines), flush=True)
    print(f"{name}: {'passed' if passed else 'FAILED'} in {time.monotonic() - started:.0f}s", flush=True)
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--test-binary", required=True, type=Path,
                        help="static test binary: CGO_ENABLED=0 go test -c ./internal/app")
    parser.add_argument("--kernels", default=",".join(KERNELS),
                        help="comma-separated subset of: " + ", ".join(KERNELS))
    parser.add_argument("--memory", type=int, default=1024)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/kernel-load")
    parser.add_argument("--cache", type=Path, help="keep downloaded kernel packages here")
    parser.add_argument("--host", action="store_true",
                        help="also run the tests on the kernel this script runs on (needs root)")
    args = parser.parse_args()
    names = [name.strip() for name in args.kernels.split(",") if name.strip()]
    unknown = [name for name in names if name not in KERNELS]
    if unknown:
        parser.error(f"unknown kernels: {', '.join(unknown)}")
    if not names and not args.host:
        parser.error("nothing to check: no --kernels and no --host")
    if args.memory < 512:
        parser.error("the guest needs at least 512 MiB")
    busybox = None
    if names:
        for command in ("qemu-system-x86_64", "dpkg-deb", "curl", "ldd"):
            if shutil.which(command) is None:
                parser.error(f"required command is unavailable: {command}")
        busybox = shutil.which("busybox")
        if busybox is None:
            parser.error("busybox is unavailable (install busybox-static)")
    if args.host and os.geteuid() != 0:
        parser.error("--host loads eBPF programs and needs root")
    if not args.test_binary.is_file():
        parser.error(f"missing test binary: {args.test_binary}")
    for name in ("forward-tc-bpf.o", "forward-xdp-bpf.o"):
        if not (ROOT / "internal/app/ebpf" / name).is_file():
            parser.error(f"missing eBPF object {name}; run sh scripts/build-ebpf.sh first")
    for relative in PLUGIN_OBJECTS:
        if not (ROOT / relative).is_file():
            parser.error(f"missing plugin object {relative}; run sh scripts/build-plugin-ebpf.sh first")
    args.output.mkdir(parents=True, exist_ok=True)
    failed = []
    with tempfile.TemporaryDirectory(prefix="veer-kernel-load-") as temporary:
        directory = Path(temporary)
        cache = args.cache.resolve() if args.cache else directory
        cache.mkdir(parents=True, exist_ok=True)
        initramfs = directory / "initramfs.gz"
        if names:
            build_initramfs(initramfs, Path(busybox).resolve(), args.test_binary.resolve())
        for name in names:
            if not boot(name, fetch_kernel(name, cache), initramfs, args.memory, args.output.resolve()):
                failed.append(name)
    if args.host:
        names.append("host")
        if not run_host(args.test_binary.resolve(), args.output.resolve()):
            failed.append("host")
    if failed:
        raise SystemExit(f"embedded eBPF collections or plugin objects failed to load on: {', '.join(failed)}")
    print(f"embedded eBPF collections and plugin objects loaded on: {', '.join(names)}", flush=True)


if __name__ == "__main__":
    main()
