"""Opt-in WG + real Veer TC NAT throughput benchmark in disposable namespaces.

The runtime directory must contain veer and plugins/{wan_core,vpn_core}.
Use a native root test host; run the same script with base/enhanced binaries.
"""

import argparse
import json
import os
import pathlib
import re
import signal
import statistics
import subprocess
import sys
import threading
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runtime", type=pathlib.Path, required=True)
parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()
BASE = args.runtime.resolve()
if not args.child:
    r = subprocess.run(
        ["unshare", "--net", "--", sys.executable, __file__, *sys.argv[1:], "--child"],
        timeout=360,
    )
    sys.exit(r.returncode)


def run(args, data=None, check=True, timeout=15):
    r = subprocess.run(
        args, input=data, text=True, capture_output=True, timeout=timeout
    )
    if check and r.returncode:
        raise RuntimeError(str(args[:6]) + ": " + r.stdout[-1500:] + r.stderr[-1500:])
    return r.stdout.strip()


def ip(*args):
    return run(["ip", *args])


def ns(name, *args):
    return run(["ip", "netns", "exec", name, *args])


def cpu_snapshot():
    vals = list(
        map(int, pathlib.Path("/proc/stat").read_text().splitlines()[0].split()[1:])
    )
    return sum(vals[i] for i in (0, 1, 2, 5, 6)), vals[7]


def process_stats(parent):
    procs = {}
    for d in pathlib.Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            stat = (d / "stat").read_text().rsplit(")", 1)[1].split()
            procs[int(d.name)] = (
                int(stat[1]),
                int(stat[11]) + int(stat[12]),
                int(stat[21]) * os.sysconf("SC_PAGE_SIZE"),
            )
        except (OSError, ValueError, IndexError):
            pass
    family = {parent}
    for _ in range(5):
        family.update(p for p, v in procs.items() if v[0] in family)
    return sum(procs[p][1] for p in family if p in procs), sum(
        procs[p][2] for p in family if p in procs
    )


def api(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:39888" + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + TOKEN,
            "X-Veer-Plugin-Admin": ADMIN,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


suffix = str(os.getpid())
remote = "wgp-r-" + suffix
client = "wgp-c-" + suffix
daemon = server = None
log = None
TOKEN = os.urandom(32).hex()
ADMIN = os.urandom(32).hex()
results = []
parallel = int(os.environ.get("WG_PERF_PARALLEL", "1"))
signal.signal(
    signal.SIGTERM, lambda *_: (_ for _ in ()).throw(RuntimeError("terminated"))
)
try:
    for name in [remote, client]:
        ip("netns", "add", name)
        ip("-n", name, "link", "set", "lo", "up")
    ip("link", "set", "lo", "up")
    run(["sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2"])
    ip("link", "add", "br-lan", "type", "bridge")
    ip("addr", "add", "192.168.10.1/24", "dev", "br-lan")
    ip("link", "set", "br-lan", "up")
    ip("link", "add", "port0", "type", "veth", "peer", "name", "client0")
    ip("link", "set", "port0", "master", "br-lan")
    ip("link", "set", "port0", "mtu", "1420")
    ip("link", "set", "port0", "up")
    ip("link", "set", "client0", "netns", client)
    ip("-n", client, "addr", "add", "192.168.10.2/24", "dev", "client0")
    ip("-n", client, "link", "set", "client0", "mtu", "1420")
    ip("-n", client, "link", "set", "client0", "up")
    ip("-n", client, "route", "add", "default", "via", "192.168.10.1")
    ip("link", "add", "wan", "type", "veth", "peer", "name", "outside")
    ip("link", "set", "outside", "netns", remote)
    ip("addr", "add", "192.0.2.1/24", "dev", "wan")
    ip("link", "set", "wan", "up")
    ip("-n", remote, "addr", "add", "192.0.2.2/24", "dev", "outside")
    ip("-n", remote, "link", "set", "outside", "up")
    ip("route", "add", "default", "via", "192.0.2.2")
    ip("-n", remote, "addr", "add", "203.0.113.1/32", "dev", "lo")
    localkey = run(["wg", "genkey"])
    remotekey = run(["wg", "genkey"])
    nativekey = run(["wg", "genkey"])
    nativeremotekey = run(["wg", "genkey"])
    pub = lambda k: run(["wg", "pubkey"], k + "\n")
    ip("-n", remote, "link", "add", "wgpeer", "type", "wireguard")
    run(
        ["ip", "netns", "exec", remote, "wg", "syncconf", "wgpeer", "/dev/stdin"],
        f"[Interface]\nPrivateKey = {remotekey}\nListenPort = 51820\n[Peer]\nPublicKey = {pub(localkey)}\nAllowedIPs = 10.77.0.1/32\n",
    )
    ip("-n", remote, "link", "set", "wgpeer", "mtu", "1420")
    ip("-n", remote, "link", "set", "wgpeer", "up")
    ip("-n", remote, "route", "add", "10.77.0.1/32", "dev", "wgpeer")
    ip("-n", remote, "link", "add", "wgnpeer", "type", "wireguard")
    run(
        ["ip", "netns", "exec", remote, "wg", "syncconf", "wgnpeer", "/dev/stdin"],
        f"[Interface]\nPrivateKey = {nativeremotekey}\nListenPort = 51830\n[Peer]\nPublicKey = {pub(nativekey)}\nAllowedIPs = 10.78.0.1/32\n",
    )
    ip("-n", remote, "link", "set", "wgnpeer", "mtu", "1420")
    ip("-n", remote, "link", "set", "wgnpeer", "up")
    ip("-n", remote, "route", "add", "10.78.0.1/32", "dev", "wgnpeer")
    ip("link", "add", "wgnative", "type", "wireguard")
    ip("addr", "add", "10.78.0.1/32", "dev", "wgnative")
    run(
        ["wg", "syncconf", "wgnative", "/dev/stdin"],
        f"[Interface]\nPrivateKey = {nativekey}\nListenPort = 51831\n[Peer]\nPublicKey = {pub(nativeremotekey)}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.2:51830\nPersistentKeepalive = 25\n",
    )
    ip("link", "set", "wgnative", "mtu", "1420")
    ip("link", "set", "wgnative", "up")
    run(
        ["nft", "-f", "/dev/stdin"],
        'add table inet wgp_native\nadd chain inet wgp_native nat { type nat hook postrouting priority 100; policy accept; }\nadd rule inet wgp_native nat ip saddr 192.168.10.2 oifname "wgnative" snat to 10.78.0.1\n',
    )
    cfg = {
        "web_bind": "127.0.0.1",
        "web_port": 39888,
        "web_token": TOKEN,
        "plugin_admin_token": ADMIN,
        "max_workers": 1,
        "default_engine": "kernel",
        "kernel_engine_order": ["tc"],
        "plugins_enabled": True,
        "plugins_dataplane_enabled": True,
        "plugins_isolation": False,
        "plugins_min_sandbox_level": "none",
        "plugins_require_signed_packages": False,
        "plugins_remote_install_enabled": False,
        "plugins_dir": str(BASE / "plugins"),
        "experimental_features": {"kernel_tc_prepared_l2": True},
    }
    (BASE / "config.json").write_text(json.dumps(cfg))
    os.chmod(BASE / "config.json", 0o600)
    log = open(BASE / "daemon.log", "w")
    env = dict(
        os.environ,
        VEER_RUNTIME_STATE_DIR=str(BASE / "runtime"),
        VEER_BPF_STATE_DIR="/sys/fs/bpf/veer-wg-perf-" + suffix,
    )
    daemon = subprocess.Popen(
        [str(BASE / "veer"), "--config", str(BASE / "config.json")],
        cwd=BASE,
        stdout=log,
        stderr=log,
        env=env,
    )
    for _ in range(100):
        try:
            api("GET", "/api/plugins/vpn_core/resources/profiles")
            break
        except Exception:
            time.sleep(0.15)
    else:
        raise RuntimeError("daemon not ready")
    api(
        "POST",
        "/api/plugins/vpn_core/actions/set_key",
        {"payload": {"key": "default", "value": localkey}},
    )
    api(
        "POST",
        "/api/plugins/vpn_core/resources/profiles",
        {
            "key": "default",
            "enabled": True,
            "data": {
                "slot": 1,
                "mtu": 1420,
                "addresses": ["10.77.0.1/32"],
                "peers": [
                    {
                        "public_key": pub(remotekey),
                        "endpoint": "192.0.2.2:51820",
                        "allowed_ips": ["0.0.0.0/0"],
                        "keepalive": 25,
                    }
                ],
            },
        },
    )
    print(
        "WG_APPLY",
        json.dumps(
            api(
                "POST",
                "/api/plugins/vpn_core/actions/apply",
                {"payload": {"key": "default"}},
            )
        ),
        flush=True,
    )
    server = subprocess.Popen(
        ["ip", "netns", "exec", remote, "iperf3", "-s", "-B", "203.0.113.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    natid = None

    def mode(name):
        global natid
        if natid is not None:
            api("DELETE", "/api/egress-nats?id=" + str(natid))
            natid = None
        run(["ip", "route", "del", "203.0.113.1/32"], check=False)
        if name == "native_wg":
            ip("route", "add", "203.0.113.1/32", "dev", "wgnative")
        else:
            payload = {
                "parent_interface": "br-lan",
                "child_interface": "port0",
                "out_interface": "veerwg1" if name == "veer_wg" else "wan",
                "out_source_ip": "10.77.0.1" if name == "veer_wg" else "192.0.2.1",
                "protocol": "tcp+udp+icmp",
            }
            if name == "veer_wg":
                payload["redirect_mode"] = "prepared_l2"
            natid = api("POST", "/api/egress-nats", payload)["id"]
        ns(client, "ping", "-c", "3", "-i", ".1", "-W", "2", "203.0.113.1")

    # Same MTU and endpoints, rotate order to limit thermal/noisy-neighbour bias.
    orders = [["veer_wg"], ["veer_wg"], ["veer_wg"]]
    if parallel > 1:
        orders = [
            ["native_wg", "veer_wg"],
            ["veer_wg", "native_wg"],
            ["native_wg", "veer_wg"],
        ]
    hz = os.sysconf("SC_CLK_TCK")

    def tunnel_bytes(name):
        tunnel = "wgnpeer" if name == "native_wg" else "wgpeer"
        parts = ns(remote, "wg", "show", tunnel, "transfer").split()
        return list(map(int, parts[-2:]))

    for roundindex, order in enumerate(orders):
        for name in order:
            mode(name)
            ping = ns(
                client, "ping", "-n", "-c", "30", "-i", ".02", "-W", "2", "203.0.113.1"
            )
            times = [float(x) for x in re.findall(r"time=([\d.]+)", ping)]
            for reverse in [False, True]:
                command = [
                    "ip",
                    "netns",
                    "exec",
                    client,
                    "iperf3",
                    "-c",
                    "203.0.113.1",
                    "-t",
                    "6",
                    "-O",
                    "1",
                    "-P",
                    str(parallel),
                    "-J",
                ] + (["-R"] if reverse else [])
                rss = []
                stop = threading.Event()

                def sample():
                    while not stop.wait(0.15):
                        rss.append(process_stats(daemon.pid)[1])

                thread = threading.Thread(target=sample)
                thread.start()
                wg0 = tunnel_bytes(name) if name != "direct_tc" else [0, 0]
                c0 = cpu_snapshot()
                p0 = process_stats(daemon.pid)
                start = time.monotonic()
                try:
                    raw = run(command, timeout=20)
                finally:
                    elapsed = time.monotonic() - start
                    c1 = cpu_snapshot()
                    p1 = process_stats(daemon.pid)
                    stop.set()
                    thread.join()
                data = json.loads(raw)
                if "error" in data:
                    raise RuntimeError(data["error"])
                end = data["end"]
                bps = end["sum_received"]["bits_per_second"]
                result = {
                    "round": roundindex + 1,
                    "mode": name,
                    "direction": "download" if reverse else "upload",
                    "mbps": bps / 1e6,
                    "retransmits": end["sum_sent"].get("retransmits"),
                    "host_busy_cores": (c1[0] - c0[0]) / hz / elapsed,
                    "host_steal_cores": (c1[1] - c0[1]) / hz / elapsed,
                    "veer_cpu_one_core_percent": 100 * (p1[0] - p0[0]) / hz / elapsed,
                    "veer_max_rss_mib": max(rss + [p0[1], p1[1]]) / 1048576,
                    "ping_median_ms": statistics.median(times),
                    "ping_p95_ms": sorted(times)[int((len(times) - 1) * 0.95)],
                }
                wg1 = tunnel_bytes(name) if name != "direct_tc" else [0, 0]
                result.update(
                    parallel_streams=parallel,
                    remote_wg_received_bytes=wg1[0] - wg0[0],
                    remote_wg_sent_bytes=wg1[1] - wg0[1],
                )
                results.append(result)
                (BASE / "results.json").write_text(json.dumps(results, indent=2))
                print(json.dumps(result), flush=True)
    print("PERFORMANCE_COMPLETE", flush=True)
finally:
    for process in [server, daemon]:
        if process:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    if log:
        log.close()
    for name in [client, remote]:
        run(["ip", "netns", "del", name], check=False)
    pins = pathlib.Path("/sys/fs/bpf/veer-wg-perf-" + suffix)
    if pins.exists():
        import shutil

        shutil.rmtree(pins)
