#!/usr/bin/env python3
"""Boot stock distro kernels and test real deployment in disposable QEMU guests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
IMAGES = {
    "alpine": (
        "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/cloud/"
        "nocloud_alpine-3.19.8-x86_64-bios-cloudinit-r0.qcow2",
        "sha512",
        "1b883abca5266857d6ab601ec5898da031a2f365da99781eea86a1e3e0d87b662"
        "a04ec220634fe46d672b89a06e7a1269df005572079eba63ac7200ab800fe88",
    ),
    "rocky": (
        "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/"
        "Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2",
        "sha256",
        "92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8",
    ),
}


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def image_for(profile, directory):
    url, algorithm, expected = IMAGES[profile]
    image = directory / "base.qcow2"
    print(f"download pinned {profile} cloud image", flush=True)
    run(["curl", "-fL", "--retry", "3", "--connect-timeout", "30",
         "--max-time", "600", "--output", str(image), url])
    digest = hashlib.new(algorithm)
    with image.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise RuntimeError(f"{profile} image checksum mismatch")
    print(f"{profile} image {algorithm}: {expected}", flush=True)
    return image


def payload_for(directory, binary, test_binary):
    payload = directory / "payload.tar.gz"
    with tarfile.open(payload, "w:gz") as archive:
        for entry in ("bootstrap.sh", "deploy.sh", "config.example.json", "go.mod",
                      "internal/app/ebpf", "plugins", "sdk", "scripts"):
            archive.add(ROOT / entry, arcname=entry)
        archive.add(binary, arcname="veer-linux-amd64")
        archive.add(test_binary, arcname="veer-platform.test")
    return payload


def wait_for_ssh(ssh, process, serial, timeout=300):
    deadline = time.monotonic() + timeout
    next_report = time.monotonic()
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited with {process.returncode}; see {serial}")
        result = subprocess.run(ssh + ["true"], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=15, check=False)
        if result.returncode == 0:
            return
        if time.monotonic() >= next_report:
            print("waiting for guest SSH initialization", flush=True)
            next_report = time.monotonic() + 20
        time.sleep(3)
    raise RuntimeError(f"guest SSH did not become ready; see {serial}")


def verify(profile, binary, test_binary, memory, output):
    # All disks, seed credentials and keys are scoped to this temporary directory.
    with tempfile.TemporaryDirectory(prefix=f"veer-qemu-{profile}-") as temporary:
        directory = Path(temporary)
        image = image_for(profile, directory)
        overlay = directory / "guest.qcow2"
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
             str(image), str(overlay)])
        info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", str(overlay)]))
        if info["virtual-size"] < 8 * 1024**3:
            run(["qemu-img", "resize", str(overlay), "8G"])
        key = directory / "key"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
        public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        # OpenSSH without PAM rejects locked accounts even for key authentication.
        # Keep password authentication disabled and unlock only this disposable root account.
        password_hash = subprocess.check_output(["openssl", "passwd", "-6", "-stdin"],
                                                input=secrets.token_hex(32), text=True).strip()
        (directory / "meta-data").write_text(json.dumps({
            "instance-id": f"veer-{profile}-{time.time_ns()}",
            "local-hostname": f"veer-{profile}",
        }), encoding="utf-8")
        (directory / "user-data").write_text("#cloud-config\n" + json.dumps({
            "disable_root": False,
            "ssh_pwauth": False,
            "users": [{"name": "root", "lock_passwd": False,
                       "hashed_passwd": password_hash, "ssh_authorized_keys": [public_key]}],
        }), encoding="utf-8")
        seed = directory / "seed.iso"
        run(["genisoimage", "-quiet", "-output", str(seed), "-volid", "cidata",
             "-joliet", "-rock", str(directory / "user-data"), str(directory / "meta-data")])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        serial = output / f"{profile}-serial.log"
        accelerator = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        print(f"boot {profile}: accelerator={accelerator}, memory={memory} MiB", flush=True)
        common = ["-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                  "-o", f"UserKnownHostsFile={directory / 'known_hosts'}",
                  "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=15"]
        ssh = ["ssh", "-p", str(port)] + common + ["root@127.0.0.1"]
        process = subprocess.Popen([
            "qemu-system-x86_64", "-accel", accelerator, "-m", str(memory), "-smp", "2",
            "-cpu", "host" if accelerator == "kvm" else "max",
            "-display", "none", "-monitor", "none", "-serial", f"file:{serial}",
            "-drive", f"file={overlay},format=qcow2,if=virtio",
            "-drive", f"file={seed},format=raw,media=cdrom,readonly=on",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device", "virtio-net-pci,netdev=net0",
        ])
        try:
            wait_for_ssh(ssh, process, serial)
            run(ssh + ["cloud-init status --wait"], timeout=300)
            payload = payload_for(directory, binary, test_binary)
            run(["scp", "-O", "-P", str(port)] + common +
                [str(payload), "root@127.0.0.1:/root/veer-platform.tar.gz"], timeout=180)
            command = ("mkdir -p /root/veer-platform && "
                       "tar -xzf /root/veer-platform.tar.gz -C /root/veer-platform && "
                       "cd /root/veer-platform && "
                       f"VEER_VM_TEST_GUEST=1 sh scripts/verify-vm-guest.sh {profile}")
            with (output / f"{profile}-verification.log").open("w", encoding="utf-8") as log:
                child = subprocess.Popen(ssh + [command], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, encoding="utf-8")
                assert child.stdout is not None
                for line in child.stdout:
                    print(line, end="", flush=True)
                    log.write(line)
                    log.flush()
                if child.wait() != 0:
                    raise RuntimeError(f"{profile} guest verification failed")
            # Prove the generated service really returns after a guest reboot.
            old_boot = subprocess.check_output(ssh + ["cat /proc/sys/kernel/random/boot_id"], text=True).strip()
            subprocess.run(ssh + ["reboot"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False, timeout=15)
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                time.sleep(3)
                result = subprocess.run(ssh + ["cat /proc/sys/kernel/random/boot_id"],
                                        capture_output=True, text=True, timeout=15, check=False)
                if result.returncode == 0 and result.stdout.strip() != old_boot:
                    break
            else:
                raise RuntimeError(f"{profile} guest did not reboot")
            run(ssh + ["cd /root/veer-platform && VEER_VM_TEST_GUEST=1 "
                       f"sh scripts/verify-vm-guest.sh {profile} reboot"], timeout=120)
            print(f"{profile}: stock-kernel deployment, sandbox, dataplane and reboot passed", flush=True)
        except BaseException:
            subprocess.run(ssh + ["journalctl -u veer --no-pager -n 80 2>/dev/null; "
                                  "journalctl -k --no-pager -n 80 2>/dev/null; "
                                  "tail -80 /var/log/veer.log 2>/dev/null"],
                           check=False, timeout=30)
            print(serial.read_text(encoding="utf-8", errors="replace")[-12000:], flush=True)
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=IMAGES)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--test-binary", required=True, type=Path)
    parser.add_argument("--memory", type=int, default=2048)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/platform-vm")
    args = parser.parse_args()
    if args.memory < 512:
        parser.error("the VM requires at least 512 MiB")
    for command in ("qemu-system-x86_64", "qemu-img", "genisoimage", "ssh", "scp", "ssh-keygen", "curl", "openssl"):
        if shutil.which(command) is None:
            parser.error(f"required command is unavailable: {command}")
    for binary in (args.binary, args.test_binary):
        if not binary.is_file():
            parser.error(f"missing prebuilt binary: {binary}")
    args.output.mkdir(parents=True, exist_ok=True)
    verify(args.profile, args.binary.resolve(), args.test_binary.resolve(), args.memory, args.output.resolve())


if __name__ == "__main__":
    main()
