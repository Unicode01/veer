"""PPPoE base/enhanced wire correctness and optional same-host throughput."""

import argparse
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(
    description="Isolated PPPoE kfunc correctness and optional throughput checks"
)
parser.add_argument(
    "--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent
)
parser.add_argument("--loader", type=pathlib.Path, required=True)
parser.add_argument("--output", type=pathlib.Path)
parser.add_argument("--performance", action="store_true")
parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()
ROOT = args.root.resolve()
LOADER = args.loader.resolve()
if not args.child:
    sys.exit(
        subprocess.run(
            [
                "unshare",
                "--net",
                "--",
                sys.executable,
                __file__,
                *sys.argv[1:],
                "--child",
            ],
            timeout=300,
        ).returncode
    )
work = tempfile.TemporaryDirectory(prefix="veer-kfuncs-packets-")
BASE = pathlib.Path(work.name)


def run(a, check=True, data=None, timeout=20):
    r = subprocess.run(a, input=data, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(str(a) + ": " + r.stdout[-1500:] + r.stderr[-1500:])
    return r.stdout.strip()


def ip(*a):
    return run(["ip", *a])


remote = "vkmod-" + str(os.getpid())
procs = []
logs = []
results = []


def proc(a, label):
    f = open(BASE / (label + ".log"), "w")
    logs.append(f)
    p = subprocess.Popen(a, stdout=f, stderr=f)
    procs.append(p)
    return p


def idx(name, ns=None):
    return json.loads(
        run((["ip", "-n", ns] if ns else ["ip"]) + ["-j", "link", "show", name])
    )[0]


def cfg(ns, side):
    l, p, w = [idx(n, ns) for n in ["local" + side, "pipe" + side, "wan" + side]]
    other = idx("wan" + ("0" if side == "1" else "1"), None if side == "1" else remote)
    mac = lambda a: bytes.fromhex(a["address"].replace(":", ""))
    return (
        struct.pack(
            "<IIIIHHHH",
            1,
            l["ifindex"],
            p["ifindex"],
            w["ifindex"],
            1234,
            2,
            1452,
            1432,
        )
        + mac(p)
        + mac(l)
        + mac(w)
        + mac(other)
        + b"\0" * 4
    )


def malformed_frames(mode):
    # Inject actual PPPoE wire frames. A valid control probe must reach UDP,
    # whereas malformed/session/peer mismatches must not reach that same socket.
    echo_code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.90.0.2',39991));\nwhile True:\n d,a=s.recvfrom(65536);s.sendto(d,a)"
    echo = proc(
        ["ip", "netns", "exec", remote, "python3", "-u", "-c", echo_code],
        mode + "-raw-echo",
    )
    time.sleep(0.2)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("10.90.0.1", 39992))
    client.settimeout(0.3)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw.bind(("wan0", 0))
    payload = b"veer-raw-frame-check"
    udp = struct.pack("!HHHH", 39992, 39991, 8 + len(payload), 0) + payload
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton("10.90.0.1"),
        socket.inet_aton("10.90.0.2"),
    )
    words = struct.unpack("!10H", header)
    total = sum(words)
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    header = header[:10] + struct.pack("!H", (~total) & 65535) + header[12:]
    ip_packet = header + udp
    mac = lambda n, ns=None: bytes.fromhex(idx(n, ns)["address"].replace(":", ""))
    eth = mac("wan1", remote) + mac("wan0") + b"\x88\x64"
    ppp = struct.pack("!BBHHH", 0x11, 0, 1234, len(ip_packet) + 2, 0x21)
    frame = eth + ppp + ip_packet
    for good in [frame, frame + b"\0" * 20]:
        raw.send(good)
        assert client.recv(65536) == payload
    bad = [
        frame[:20],
        eth + ppp + ip_packet[:-3],
        eth + struct.pack("!BBHHH", 0x11, 0, 1234, 1, 0x21) + ip_packet,
        eth + struct.pack("!BBHHH", 0x11, 0, 1234, 1495, 0x21) + ip_packet,
        eth
        + struct.pack("!BBHHH", 0x11, 0, 1235, len(ip_packet) + 2, 0x21)
        + ip_packet,
        eth
        + struct.pack("!BBHHH", 0x11, 0, 1234, len(ip_packet) + 2, 0xFFFF)
        + ip_packet,
        eth[:6] + bytes([eth[6] ^ 2]) + eth[7:] + ppp + ip_packet,
    ]
    for frame in bad:
        raw.send(frame)
        try:
            client.recv(65536)
        except socket.timeout:
            continue
        raise RuntimeError("malformed PPPoE frame reached the backend")
    raw.close()
    client.close()
    echo.terminate()
    echo.wait(timeout=4)
    procs.remove(echo)
    print(
        mode,
        "PPPoE padding, truncated lengths, wrong session/protocol/peer checks passed",
        flush=True,
    )


try:
    ip("link", "set", "lo", "up")
    ip("netns", "add", remote)
    ip("-n", remote, "link", "set", "lo", "up")
    ip("link", "add", "wan0", "type", "veth", "peer", "name", "wan1")
    ip("link", "set", "wan1", "netns", remote)
    for side, ns in [("0", None), ("1", remote)]:
        prefix = ["ip"] + (["-n", ns] if ns else [])
        run(
            prefix
            + [
                "link",
                "add",
                "local" + side,
                "type",
                "veth",
                "peer",
                "name",
                "pipe" + side,
            ]
        )
        for name in ["local" + side, "pipe" + side]:
            run(prefix + ["link", "set", name, "mtu", "1492", "up"])
        run(prefix + ["link", "set", "wan" + side, "up"])
        run(
            (["ip", "netns", "exec", ns] if ns else [])
            + ["ethtool", "-K", "wan" + side, "tx", "off"]
        )
        run(
            prefix
            + [
                "addr",
                "add",
                "10.90.0." + ("1" if side == "0" else "2") + "/24",
                "dev",
                "local" + side,
            ]
        )
        run(
            prefix
            + [
                "-6",
                "addr",
                "add",
                "fd90::" + ("1" if side == "0" else "2") + "/64",
                "dev",
                "local" + side,
                "nodad",
            ]
        )
    # fixed neighbours are the virtual point-to-point PPP boundary
    for side, ns in [("0", None), ("1", remote)]:
        prefix = ["ip"] + (["-n", ns] if ns else [])
        run(
            prefix
            + [
                "neigh",
                "replace",
                "10.90.0." + ("2" if side == "0" else "1"),
                "lladdr",
                idx("pipe" + side, ns)["address"],
                "nud",
                "permanent",
                "dev",
                "local" + side,
            ]
        )
        run(
            prefix
            + [
                "-6",
                "neigh",
                "replace",
                "fd90::" + ("2" if side == "0" else "1"),
                "lladdr",
                idx("pipe" + side, ns)["address"],
                "nud",
                "permanent",
                "dev",
                "local" + side,
            ]
        )
    server = proc(["ip", "netns", "exec", remote, "iperf3", "-s"], "server")
    for mode in ["bpf", "kfuncs"]:
        loaders = []
        for side, ns in [("0", None), ("1", remote)]:
            pre = ["ip", "netns", "exec", ns] if ns else []
            run(
                pre
                + [
                    "ethtool",
                    "-K",
                    "local" + side,
                    "sg",
                    "on" if mode == "kfuncs" else "off",
                    "tso",
                    "on" if mode == "kfuncs" else "off",
                    "gso",
                    "on" if mode == "kfuncs" else "off",
                ]
            )
            run(
                pre
                + [
                    "ethtool",
                    "-K",
                    "pipe" + side,
                    "gro",
                    "on" if mode == "kfuncs" else "off",
                    "lro",
                    "off",
                ]
            )
            run(
                (["ip", "-n", ns] if ns else ["ip"])
                + [
                    "link",
                    "set",
                    "local" + side,
                    "gso_max_size",
                    "65536" if mode == "kfuncs" else "1492",
                    "gso_max_segs",
                    "65535" if mode == "kfuncs" else "1",
                ]
            )
            config = {
                "Object": str(
                    ROOT
                    / "plugins/pppoe_client"
                    / ("pppoe_tunnel" + ("-kfuncs" if mode == "kfuncs" else "") + ".o")
                ),
                "Program": "tc_tunnel",
                "Map": "pppoe_tunnel_config",
                "Interfaces": ["pipe" + side, "wan" + side],
                "Entries": [{"Key": "00000000", "Value": cfg(ns, side).hex()}],
            }
            file = BASE / (mode + side + ".json")
            file.write_text(json.dumps(config))
            p = proc(pre + [str(LOADER), str(file)], mode + side)
            loaders.append(p)
        time.sleep(0.7)
        for p in loaders:
            if p.poll() is not None:
                raise RuntimeError("loader exited")
        print(mode, run(["ping", "-n", "-c", "3", "-W", "2", "10.90.0.2"]), flush=True)
        print(
            mode, run(["ping", "-6", "-n", "-c", "2", "-W", "2", "fd90::2"]), flush=True
        )
        if mode == "kfuncs":
            r = subprocess.run(["rmmod", "veer_kfuncs"], capture_output=True, text=True)
            if r.returncode == 0:
                raise RuntimeError("unloaded module while BPF programs referenced it")
        for destination in ["10.90.0.2", "fd90::2"]:
            # UDP echo verifies exact boundaries/checksums, including UDP segmentation.
            echo_code = (
                "import socket; s=socket.socket(socket.AF_INET6 if ':' in '"
                + destination
                + "' else socket.AF_INET,socket.SOCK_DGRAM);s.bind(('"
                + destination
                + "',39990));\nwhile True:\n d,a=s.recvfrom(65536);s.sendto(d,a)"
            )
            echo = proc(
                ["ip", "netns", "exec", remote, "python3", "-u", "-c", echo_code],
                mode + "-udp" + destination.replace(":", ""),
            )
            time.sleep(0.2)
            client = socket.socket(
                socket.AF_INET6 if ":" in destination else socket.AF_INET,
                socket.SOCK_DGRAM,
            )
            client.settimeout(2)
            for length in [1, 64, 1444 if ":" in destination else 1464]:
                payload = os.urandom(length)
                client.sendto(payload, (destination, 39990))
                assert client.recv(65536) == payload
            # Eight UDP datagrams carried in one GSO skb at the sending socket.
            payload = os.urandom(128)
            client.setsockopt(17, 103, 128)
            client.sendto(payload * 8, (destination, 39990))
            for _ in range(8):
                assert client.recv(65536) == payload
            client.close()
            echo.terminate()
            echo.wait(timeout=4)
            procs.remove(echo)
            transfer = json.loads(
                run(["iperf3", "-c", destination, "-t", "1", "-J"], timeout=8)
            )
            if "error" in transfer or transfer["end"]["sum_received"]["bytes"] <= 0:
                raise RuntimeError("TCP transfer failed")
        malformed_frames(mode)
        print(
            mode,
            "IPv4/IPv6 TCP, UDP, UDP GSO and live-reference checks passed",
            flush=True,
        )
        for reverse in [False, True]:
            for round in range(3 if args.performance else 1):
                stat = lambda: list(
                    map(
                        int,
                        pathlib.Path("/proc/stat")
                        .read_text()
                        .splitlines()[0]
                        .split()[1:],
                    )
                )
                a = stat()
                start = time.monotonic()
                d = json.loads(
                    run(
                        [
                            "iperf3",
                            "-c",
                            "10.90.0.2",
                            "-t",
                            "4" if args.performance else "1",
                            "-O",
                            "1",
                            "-J",
                        ]
                        + (["-R"] if reverse else []),
                        timeout=12,
                    )
                )
                b = stat()
                elapsed = time.monotonic() - start
                if "error" in d:
                    raise RuntimeError(d["error"])
                busy = (
                    sum(b[i] - a[i] for i in [0, 1, 2, 5, 6])
                    / os.sysconf("SC_CLK_TCK")
                    / elapsed
                )
                r = {
                    "mode": mode,
                    "direction": "rx" if reverse else "tx",
                    "round": round + 1,
                    "mbps": d["end"]["sum_received"]["bits_per_second"] / 1e6,
                    "busy_cores": busy,
                    "retransmits": d["end"]["sum_sent"].get("retransmits"),
                }
                results.append(r)
                print(json.dumps(r), flush=True)
        for p in loaders:
            p.terminate()
            p.wait(timeout=5)
            procs.remove(p)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2))
except BaseException:
    for f in logs:
        f.flush()
        print(
            pathlib.Path(f.name).name,
            pathlib.Path(f.name).read_text()[-8000:],
            flush=True,
        )
    raise
finally:
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    for f in logs:
        f.close()
    run(["ip", "netns", "del", remote], check=False)

    work.cleanup()
