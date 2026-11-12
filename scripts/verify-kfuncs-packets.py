"""PPPoE base/enhanced wire correctness and optional same-host throughput."""

import argparse
import fcntl
import json
import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser(
    description="Isolated PPPoE kfunc correctness and optional throughput checks"
)
parser.add_argument(
    "--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent
)
parser.add_argument("--loader", type=pathlib.Path, required=True)
parser.add_argument("--output", type=pathlib.Path)
parser.add_argument("--performance", action="store_true")
parser.add_argument("--direct", action="store_true", help="Test the helper-owned single WAN boundary")
parser.add_argument("--mode", choices=["all", "bpf", "kfuncs"], default="all")
parser.add_argument("--veer", type=pathlib.Path, help="Also verify real TC NAT through the selected boundary")
parser.add_argument("--tcx", action="store_true", help="Attach the plugin programs through tcx, as the Veer core does on Linux 6.6+")
parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()
if args.direct and args.mode == "bpf":
    parser.error("--direct requires the kfuncs dataplane")
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
    p = subprocess.Popen(a, stdout=f, stderr=f, cwd=BASE)
    procs.append(p)
    return p


def idx(name, ns=None):
    return json.loads(
        run((["ip", "-n", ns] if ns else ["ip"]) + ["-j", "link", "show", name])
    )[0]


def cfg(ns, side):
    l, p, w = [idx(n, ns) for n in ["local" + side, ("local" if args.direct else "pipe") + side, "wan" + side]]
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


def nonlinear_frames(mode, clamp=True, linear=False):
    # NAPI_FRAGS preserves writev's first iovec as the skb's linear head.
    # Short first iovecs force the real plugin to parse headers in skb frags.
    # Echo the source skb after handoff to verify the kfunc's clone contract.
    label = mode + ("-linear" if linear else "-frags") + ("" if clamp else "-unclamped")
    source = BASE / (label + ".c")
    obj = BASE / (label + ".o")
    guard = "!= skb->len" if linear else ">= 22"
    source.write_text(
        '#include "' + str(ROOT / "plugins/pppoe_client/pppoe_tunnel.bpf.c") + '"\n'
        'static long (*source_echo)(struct __sk_buff *, __u32, __u64) = (void *)13;\n'
        'SEC("tc/test_frags") int test_frags(struct __sk_buff *skb) {\n'
        '  if (skb->data_end - skb->data ' + guard + ') return TC_ACT_SHOT;\n'
        '  int result = tc_tunnel(skb);\n'
        '#ifdef VEER_KFUNCS\n'
        '  source_echo(skb, skb->ifindex, 0);\n'
        '#endif\n'
        '  return result;\n}\n'
        # Match the next TC NAT parser's direct-access requirements. Capture
        # only packets that actually pass this classifier, after handoff.
        'SEC("tc/test_headers") int test_headers(struct __sk_buff *skb) {\n'
        '  void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;\n'
        '  struct ethhdr *eth = data; __u32 key = 0, off = 14; __u8 proto;\n'
        '  struct pppoe_tunnel_config *cfg = bpf_map_lookup_elem(&pppoe_tunnel_config, &key);\n'
        '  if (!cfg || (void *)(eth + 1) > end) return TC_ACT_SHOT;\n'
        '  if (eth->h_proto == htons16(ETH_P_IP)) {\n'
        '    struct ipv4_min_hdr *ip = data + off;\n'
        '    if ((void *)(ip + 1) > end) return TC_ACT_SHOT;\n'
        '    off += (ip->ver_ihl & 15) * 4; proto = ip->protocol;\n'
        '  } else if (eth->h_proto == htons16(ETH_P_IPV6)) {\n'
        '    struct ipv6_min_hdr *ip = data + off;\n'
        '    if ((void *)(ip + 1) > end) return TC_ACT_SHOT;\n'
        '    off += 40; proto = ip->nexthdr;\n'
        '  } else return TC_ACT_SHOT;\n'
        '  if (proto == IPPROTO_TCP) {\n'
        '    struct tcp_min_hdr *tcp = data + off;\n'
        '    if ((void *)(tcp + 1) > end || (tcp->doff_res >> 4) < 5) return TC_ACT_SHOT;\n'
        '    off += (tcp->doff_res >> 4) * 4;\n'
        '  } else if (proto == IPPROTO_UDP) off += 8;\n'
        '  else return TC_ACT_SHOT;\n'
        '  if (data + off > end) return TC_ACT_SHOT;\n'
        '  return bpf_redirect(cfg->pipeline_ifindex, 0);\n}\n'
    )
    run(
        ["clang", "-O2", "-g", "-target", "bpf"]
        + (["-DVEER_KFUNCS=1"] if mode == "kfuncs" else [])
        + ["-c", str(source), "-o", str(obj)]
    )
    tap = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    loaders = []
    client = None
    try:
        # IFF_TAP | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS, TUNSETIFF.
        fcntl.ioctl(tap, 0x400454CA, struct.pack("16sH", b"fragwan", 0x1032))
        ip("link", "set", "fragwan", "address", idx("wan0")["address"], "up")
        run(["ethtool", "-K", "fragwan", "gro", "off"])
        ip("link", "add", "fragcap0", "type", "veth", "peer", "name", "fragcap1")
        for name in ["fragcap0", "fragcap1"]:
            ip("link", "set", name, "up")
        value = bytearray(cfg(None, "0"))
        struct.pack_into("<I", value, 12, idx("fragwan")["ifindex"])
        struct.pack_into("<I", value, 8, idx("fragcap0")["ifindex"])
        if not clamp:
            struct.pack_into("<HH", value, 20, 0, 0)
        for program, interface in [("test_frags", "fragwan"), ("test_headers", "local0")]:
            config = BASE / (label + "-" + program + ".json")
            config.write_text(json.dumps({
                "Object": str(obj), "Program": program, "Map": "pppoe_tunnel_config",
                "Interfaces": [interface],
                "Entries": [{"Key": "00000000", "Value": value.hex()}],
                "TCX": args.tcx,
            }))
            loaders.append(proc([str(LOADER), str(config)], label + "-" + program))
        time.sleep(0.3)
        if any(loader.poll() is not None for loader in loaders):
            raise RuntimeError("fragment test loader exited")
        client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        client.bind(("fragcap1", 0))

        def receive(timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                client.settimeout(max(0.001, deadline - time.monotonic()))
                frame = client.recv(65536)
                if frame[12:14] in [b"\x08\x00", b"\x86\xdd"] and b"veer-frags:" in frame:
                    return frame[14:]
            raise socket.timeout()

        def inject(frame, linear):
            while select.select([tap], [], [], 0)[0]:
                os.read(tap, 65536)
            os.writev(tap, [part for part in [frame[:linear], frame[linear:]] if part])
            if mode == "kfuncs":
                if not select.select([tap], [], [], 1)[0]:
                    raise RuntimeError("source skb echo missing after kfunc handoff")
                if os.read(tap, 65536) != frame:
                    raise RuntimeError("kfunc changed the original PPPoE skb")

        def checksum(data):
            if len(data) % 2:
                data += b"\0"
            total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
            while total >> 16:
                total = (total & 65535) + (total >> 16)
            return (~total) & 65535

        eth = bytes.fromhex(idx("wan0")["address"].replace(":", ""))
        eth += bytes.fromhex(idx("wan1", remote)["address"].replace(":", "")) + b"\x88\x64"
        for v6 in [False, True]:
            for protocol, options, length, flags in [(17, 0, 64, 0), (17, 0, 1444 if v6 else 1464, 0),
                                                     (6, 0, 64, 16), (6, 12, 64, 16), (6, 40, 64, 16),
                                                     (6, 4, 64, 2)]:
                payload = b"veer-frags:" + os.urandom(length - 11)
                if protocol == 17:
                    transport = struct.pack("!HHHH", 39994, 39993, length + 8, 0) + payload
                    csum_offset = 6
                else:
                    transport = struct.pack("!HHIIBBHHH", 39994, 39993, 100, 200,
                                            (5 + options // 4) << 4, flags, 4096, 0, 0)
                    transport += (b"\x02\x04\xff\xff" if flags == 2 else b"\x01" * options) + payload
                    csum_offset = 16
                if v6:
                    addresses = socket.inet_pton(socket.AF_INET6, "fd90::2")
                    addresses += socket.inet_pton(socket.AF_INET6, "fd90::1")
                    pseudo = addresses + struct.pack("!I3xB", len(transport), protocol)
                    header = struct.pack("!IHBB", 6 << 28, len(transport), protocol, 64) + addresses
                else:
                    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, protocol, 0,
                                         socket.inet_aton("10.90.0.2"), socket.inet_aton("10.90.0.1"))
                    pseudo = header[12:20] + struct.pack("!BBH", 0, protocol, len(transport))
                    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
                transport = transport[:csum_offset] + struct.pack("!H", checksum(pseudo + transport) or 65535) + transport[csum_offset + 2:]
                packet = header + transport
                frame = eth + struct.pack("!BBHHH", 0x11, 0, 1234, len(packet) + 2, 0x57 if v6 else 0x21) + packet
                expected = packet
                if flags == 2 and clamp:
                    clamped = transport[:22] + struct.pack("!H", 1432 if v6 else 1452) + transport[24:]
                    clamped = clamped[:16] + b"\0\0" + clamped[18:]
                    clamped = clamped[:16] + struct.pack("!H", checksum(pseudo + clamped)) + clamped[18:]
                    expected = header + clamped
                for head in ([len(frame)] if linear else [14, 15, 20, 21]):
                    inject(frame, head)
                    try:
                        received = receive(1)
                    except socket.timeout as error:
                        raise RuntimeError(
                            f"{mode}: fragmented IPv{6 if v6 else 4} protocol={protocol} "
                            f"TCP options={options} linear={head} clamp={clamp} did not pass TC"
                        ) from error
                    if received != expected:
                        raise RuntimeError("fragmented PPPoE payload changed")
            for bad in [frame[:20], frame[:21], frame[:-1], frame[:16] + b"\x04\xd3" + frame[18:]]:
                inject(bad, len(bad) if linear else 14)
                try:
                    receive(0.15)
                except socket.timeout:
                    continue
                raise RuntimeError("malformed fragmented PPPoE frame reached the next classifier")
        print(label, "IPv4/IPv6 PPP, TCP/UDP headers, truncated frames and source skb checks passed; clamp=" + str(clamp), flush=True)
    finally:
        if client is not None:
            client.close()
        for loader in loaders:
            loader.terminate()
            loader.wait(timeout=4)
            procs.remove(loader)
        os.close(tap)
        run(["ip", "link", "del", "fragcap0"], check=False)


def nat_path():
    binary = args.veer.resolve()
    client_ns = remote + "-lan"
    ip("netns", "add", client_ns)
    daemon = echo = None
    try:
        ip("link", "add", "br-lan", "type", "bridge")
        ip("addr", "add", "192.168.90.1/24", "dev", "br-lan")
        ip("link", "set", "br-lan", "up")
        ip("link", "add", "lan0", "type", "veth", "peer", "name", "client0")
        ip("link", "set", "lan0", "master", "br-lan")
        ip("link", "set", "lan0", "up")
        ip("link", "set", "client0", "netns", client_ns)
        ip("-n", client_ns, "link", "set", "lo", "up")
        ip("-n", client_ns, "link", "set", "client0", "up")
        ip("-n", client_ns, "addr", "add", "192.168.90.2/24", "dev", "client0")
        ip("-n", client_ns, "route", "add", "default", "via", "192.168.90.1")
        port_socket = socket.socket()
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
        port_socket.close()
        token = "isolated-pppoe-nat-verification-token"
        config = BASE / "veer.json"
        config.write_text(json.dumps({
            "web_bind": "127.0.0.1", "web_port": port, "web_token": token,
            "max_workers": 1, "default_engine": "kernel", "kernel_engine_order": ["tc"],
            "plugins_enabled": False, "experimental_features": {"kernel_tc_prepared_l2": True},
        }))
        daemon = proc([str(binary), "--config", str(config)], "veer-nat")

        def api(method, path, data=None):
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}" + path,
                data=None if data is None else json.dumps(data).encode(), method=method,
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)

        deadline = time.monotonic() + 20
        while True:
            try:
                api("GET", "/api/egress-nats")
                break
            except (OSError, urllib.error.URLError):
                if daemon.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Veer NAT daemon failed to start")
                time.sleep(0.1)
        api("POST", "/api/egress-nats", {
            "parent_interface": "br-lan", "out_interface": "local0", "out_source_ip": "10.90.0.1",
            "protocol": "tcp+udp+icmp", "redirect_mode": "prepared_l2",
        })
        deadline = time.monotonic() + 20
        while True:
            entries = api("GET", "/api/egress-nats")
            if any(entry.get("status") == "running" and entry.get("effective_kernel_engine") == "tc" for entry in entries):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("TC NAT did not become ready: " + str(entries))
            time.sleep(0.1)
        for reverse in [False, True]:
            result = json.loads(run(["ip", "netns", "exec", client_ns, "iperf3", "-c", "10.90.0.2", "-n", "8M", "-J"] + (["-R"] if reverse else [])))
            assert "error" not in result and result["end"]["sum_received"]["bytes"] >= 8 * 1024 * 1024, result
        echo_code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.90.0.2',39989));\nwhile True:\n d,a=s.recvfrom(65536);s.sendto(a[0].encode()+b':'+d,a)"
        echo = proc(["ip", "netns", "exec", remote, "python3", "-u", "-c", echo_code], "nat-udp")
        time.sleep(0.2)
        client_code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);\nfor i in range(8):\n p=('packet'+str(i)).encode();s.sendto(p,('10.90.0.2',39989));assert s.recv(65536)==b'10.90.0.1:'+p"
        run(["ip", "netns", "exec", client_ns, "python3", "-c", client_code])
        print("real Veer TC prepared_l2 NAT TCP upload/download and UDP source translation passed", flush=True)
    finally:
        for process in [echo, daemon]:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                procs.remove(process)
        ip("netns", "del", client_ns)
        run(["ip", "link", "del", "br-lan"], check=False)
        run(["ip", "link", "del", "lan0"], check=False)


def gro_paths():
    # Observe actual skbs delivered after decapsulation, rather than merely
    # checking ethtool flags. PPPoE wire frames are always <= MTU + 22.
    cases = [(destination, gro, tso, aggregate)
             for destination in ["10.90.0.2", "fd90::2"]
             for gro, tso, aggregate in ([(True, False, True), (False, False, False)] if args.direct else [(True, False, True), (False, False, False), (True, True, False)])]
    for destination, gro, tso, aggregate in cases:
        run(["ethtool", "-K", "local0", "gro", "on" if gro else "off"])
        if not args.direct: run(["ethtool", "-K", "pipe0", "tso", "on" if tso else "off"])
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        capture.bind(("local0", 0))
        capture.settimeout(0.1)
        transfer = proc(["iperf3", "-c", destination, "-R", "-t", "1", "-J"], "gro-" + destination.replace(":", "") + str(gro) + str(tso))
        large = False
        received = 0
        try:
            deadline = time.monotonic() + 6
            while transfer.poll() is None and time.monotonic() < deadline:
                try:
                    frame, address = capture.recvfrom(131072)
                except socket.timeout:
                    continue
                if address[2] != socket.PACKET_OUTGOING and frame[12:14] == (b"\x86\xdd" if ":" in destination else b"\x08\x00"):
                    received += 1
                    large |= len(frame) > 1492 + 14
            transfer.wait(timeout=3)
            log = pathlib.Path(logs[-1].name)
            data = json.loads(log.read_text())
            assert "error" not in data and data["end"]["sum_received"]["bytes"] > 0, data
            assert received and large == aggregate, (gro, tso, received, large)
        finally:
            capture.close()
        procs.remove(transfer)
        print("kfuncs GRO delivery/fallback passed:", {"destination": destination, "gro": gro, "peer_tso": tso, "aggregated": large}, flush=True)
    if args.direct:
        run(["ethtool", "-K", "local0", "gro", "on"])
        return
    run(["ethtool", "-K", "pipe0", "tso", "off"])
    # Upload ACKs received from the WAN must not take peer TX. SYN/FIN/RST and
    # data may use it, but a pure ACK would add NAPI latency to the reverse path.
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind(("pipe0", 0))
    capture.settimeout(0.1)
    transfer = proc(["iperf3", "-c", "10.90.0.2", "-b", "10M", "-t", "1", "-J"], "ack-path")
    peer_tx = 0
    try:
        deadline = time.monotonic() + 6
        while transfer.poll() is None and time.monotonic() < deadline:
            try:
                frame, address = capture.recvfrom(131072)
            except socket.timeout:
                continue
            if frame[12:14] != b"\x08\x00" or len(frame) < 54 or frame[23] != 6:
                continue
            ip_length = struct.unpack_from("!H", frame, 16)[0]
            off = 14 + (frame[14] & 15) * 4
            if address[2] == socket.PACKET_OUTGOING and frame[26:30] == socket.inet_aton("10.90.0.2"):
                peer_tx += 1
            if len(frame) < off + 20 or frame[off + 13] & 7:
                continue
            if ip_length != off - 14 + (frame[off + 12] >> 4) * 4:
                continue
            if frame[26:30] == socket.inet_aton("10.90.0.2"):
                assert address[2] != socket.PACKET_OUTGOING, "pure ACK unexpectedly sent through GRO peer"
        transfer.wait(timeout=3)
        data = json.loads(pathlib.Path(logs[-1].name).read_text())
        assert "error" not in data and data["end"]["sum_received"]["bytes"] > 0, data
        assert peer_tx, "capture did not observe peer TX for TCP handshake/control"
        # Successful upload proves ACK delivery; peer sees no pure ACK TX.
        print("kfuncs pure ACK bypass and upload passed", flush=True)
    finally:
        capture.close()
    procs.remove(transfer)


try:
    ip("link", "set", "lo", "up")
    ip("netns", "add", remote)
    ip("-n", remote, "link", "set", "lo", "up")
    ip("link", "add", "wan0", "type", "veth", "peer", "name", "wan1")
    ip("link", "set", "wan1", "netns", remote)
    for side, ns in [("0", None), ("1", remote)]:
        prefix = ["ip"] + (["-n", ns] if ns else [])
        if args.direct:
            run(prefix + ["link", "add", "local" + side, "type", "veerwan"])
        else:
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
        for name in (["local" + side] if args.direct else ["local" + side, "pipe" + side]):
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
                idx(("local" if args.direct else "pipe") + side, ns)["address"],
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
                idx(("local" if args.direct else "pipe") + side, ns)["address"],
                "nud",
                "permanent",
                "dev",
                "local" + side,
            ]
        )
    server = proc(["ip", "netns", "exec", remote, "iperf3", "-s"], "server")
    for mode in (["kfuncs"] if args.direct else (["bpf", "kfuncs"] if args.mode == "all" else [args.mode])):
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
                    "gro",
                    "on" if mode == "kfuncs" else "off",
                ]
            )
            if not args.direct:
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
                        "tso",
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
                "Interfaces": ["wan" + side] + ([] if args.direct else ["pipe" + side]),
                "EgressInterfaces": ["local" + side] if args.direct else [],
                "Entries": [{"Key": "00000000", "Value": cfg(ns, side).hex()}],
                "TCX": args.tcx,
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
        nonlinear_frames(mode)
        if mode == "kfuncs":
            nonlinear_frames(mode, clamp=False)
            nonlinear_frames(mode, linear=True)
            gro_paths()
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
                    "mode": "direct_gro" if args.direct else mode,
                    "direction": "rx" if reverse else "tx",
                    "round": round + 1,
                    "mbps": d["end"]["sum_received"]["bits_per_second"] / 1e6,
                    "busy_cores": busy,
                    "retransmits": d["end"]["sum_sent"].get("retransmits"),
                }
                results.append(r)
                print(json.dumps(r), flush=True)
        if args.veer:
            nat_path()
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
