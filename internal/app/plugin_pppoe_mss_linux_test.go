//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestBundledPPPoEMSSClampLinux(t *testing.T) {
	if os.Getenv("FORWARD_RUN_PLUGIN_DATAPLANE_TEST") != "1" {
		t.Skip("set FORWARD_RUN_PLUGIN_DATAPLANE_TEST=1 to run the PPPoE BPF tests")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(findRepoRoot(t), "plugins", "pppoe_client", "pppoe_tunnel.bpf.c")
	dir := t.TempDir()
	wrapper := fmt.Sprintf(`#include %q
SEC("tc/test_mss_v4") int test_mss_v4(struct __sk_buff *skb) { return clamp_tcp_mss_v4(skb, 1400); }
SEC("tc/test_mss_v6") int test_mss_v6(struct __sk_buff *skb) { return clamp_tcp_mss_v6(skb, 1400); }
SEC("tc/test_mss_off") int test_mss_off(struct __sk_buff *skb) { return clamp_tcp_mss_v6(skb, 0); }
SEC("tc/test_compact") int test_compact(struct __sk_buff *skb) { return compact_pppoe_payload_to_l3(skb, skb->len - 22); }
SEC("tc/test_dhcpv6") int test_dhcpv6(struct __sk_buff *skb) { return pppoe_dhcpv6_to_client(skb, skb->len - 22); }
`, source)
	cfile, object := filepath.Join(dir, "mss.c"), filepath.Join(dir, "mss.o")
	if err := os.WriteFile(cfile, []byte(wrapper), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", cfile, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile PPPoE: %v\n%s", err, output)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	// Without vmlinux BTF, older kernels cannot identify a global function's
	// __sk_buff argument as PTR_TO_CTX. The portable object must retain local
	// subprograms so the verifier inherits that type from the actual caller.
	for _, name := range []string{"clamp_tcp_mss_options", "compact_pppoe_payload_to_l3"} {
		var function *btf.Func
		if err := spec.Types.TypeByName(name, &function); err != nil {
			t.Fatalf("PPPoE subprogram %s: %v", name, err)
		}
		if function.Linkage != btf.StaticFunc {
			t.Fatalf("PPPoE subprogram %s needs kernel BTF: linkage=%v", name, function.Linkage)
		}
	}
	for _, program := range spec.Programs {
		program.Flags |= unix.BPF_F_STRICT_ALIGNMENT
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("PPPoE verifier: %+v", verifier)
		}
		t.Fatalf("load PPPoE programs: %+v", err)
	}
	defer collection.Close()
	t.Run("installed_tunnel_dhcpv6_socket", func(t *testing.T) {
		assertPPPoEDHCPv6ControlSocket(t, collection)
	})
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		want   uint32
	}{
		{"dhcpv6_link_local", func(p []byte) []byte { return p }, 1},
		{"dhcpv6_multicast", func(p []byte) []byte { p[46], p[47] = 0xff, 2; return p }, 1},
		{"ordinary_udp", func(p []byte) []byte { binary.BigEndian.PutUint16(p[62:64], 45203); return p }, 0},
		{"downstream_global", func(p []byte) []byte { p[46], p[47] = 0x20, 1; return p }, 0},
		{"dhcpv6_wrong_direction", func(p []byte) []byte {
			binary.BigEndian.PutUint16(p[62:64], 546)
			binary.BigEndian.PutUint16(p[64:66], 547)
			return p
		}, 0},
		{"dhcpv6_truncated", func(p []byte) []byte { return p[:len(p)-1] }, 0},
		{"dhcpv6_bad_ip_length", func(p []byte) []byte { binary.BigEndian.PutUint16(p[26:28], 999); return p }, 0},
		{"dhcpv6_bad_udp_length", func(p []byte) []byte { binary.BigEndian.PutUint16(p[66:68], 999); return p }, 0},
		{"dhcpv6_not_udp", func(p []byte) []byte { p[28] = 6; return p }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := make([]byte, 22+48)
			packet[22], packet[28], packet[46], packet[47] = 0x60, 17, 0xfe, 0x80
			binary.BigEndian.PutUint16(packet[26:28], 8)
			binary.BigEndian.PutUint16(packet[62:64], 547)
			binary.BigEndian.PutUint16(packet[64:66], 546)
			binary.BigEndian.PutUint16(packet[66:68], 8)
			packet = tc.mutate(packet)
			result, output, err := collection.Programs["test_dhcpv6"].Test(packet)
			if err != nil || result != tc.want || !bytes.Equal(output, packet) {
				t.Fatalf("DHCPv6 control classification: result=%d want=%d err=%v; changed packet=%t", result, tc.want, err, !bytes.Equal(output, packet))
			}
		})
	}
	for _, tc := range []struct {
		name, program string
		v6            bool
		extension     byte
		flags         byte
		mss, want     uint16
	}{
		{"ipv4_syn", "test_mss_v4", false, 0, 2, 1460, 1400},
		{"ipv4_ack", "test_mss_v4", false, 0, 16, 1460, 1460},
		{"ipv6_syn", "test_mss_v6", true, 0, 2, 1460, 1400},
		{"ipv6_synack", "test_mss_v6", true, 0, 18, 1460, 1400},
		{"ipv6_small", "test_mss_v6", true, 0, 2, 1200, 1200},
		{"ipv6_ack", "test_mss_v6", true, 0, 16, 1460, 1460},
		{"ipv6_destination_options", "test_mss_v6", true, 60, 2, 1460, 1400},
		{"ipv6_fragment", "test_mss_v6", true, 44, 2, 1460, 1460},
		{"disabled", "test_mss_off", true, 0, 2, 1460, 1460},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, tcpOffset, pseudo := pppoeMSSTestPacket(tc.v6, tc.extension, tc.flags, tc.mss)
			result, output, err := collection.Programs[tc.program].Test(packet)
			if err != nil || result != 0 {
				t.Fatalf("run MSS program: result=%d, err=%v", result, err)
			}
			if len(output) < tcpOffset+24 || binary.BigEndian.Uint16(output[tcpOffset+22:]) != tc.want {
				t.Fatalf("MSS did not become %d", tc.want)
			}
			if pppoeTestChecksum(append(pseudo, output[tcpOffset:tcpOffset+24]...)) != 0 {
				t.Fatal("TCP checksum invalid after MSS adjustment")
			}
		})
	}
	for _, length := range []int{20, 40, 63, 64, 65, 127, 128, 129, 1491, 1492} {
		t.Run(fmt.Sprintf("decap_copy_%d", length), func(t *testing.T) {
			packet := make([]byte, 22+length)
			packet[12], packet[13] = 0x88, 0x64
			for i := 22; i < len(packet); i++ {
				packet[i] = byte(i * 31)
			}
			result, output, err := collection.Programs["test_compact"].Test(packet)
			if err != nil || result != 0 {
				t.Fatalf("compact PPPoE: result=%d, err=%v", result, err)
			}
			if len(output) != 14+length || !bytes.Equal(output[:14], packet[:14]) || !bytes.Equal(output[14:], packet[22:]) {
				t.Fatal("PPPoE decapsulation changed payload bytes or packet length")
			}
		})
	}
}

func assertPPPoEDHCPv6ControlSocket(t *testing.T, collection *ebpf.Collection) {
	t.Helper()
	admin := linuxPluginControlNetAdmin{}
	wan, peer, local := pluginIntegrationLinkName("pdw"), pluginIntegrationLinkName("pdp"), pluginIntegrationLinkName("pdl")
	defer deletePluginIntegrationLinkQuietly(t, wan)
	defer deletePluginIntegrationLinkQuietly(t, local)
	pair, err := admin.LinkEnsureVeth(pluginControlNetVethRequest{Host: wan, Peer: peer, Up: true})
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := admin.LinkEnsureDummy(pluginControlNetDummyRequest{Name: local, Up: true})
	if err != nil {
		t.Fatal(err)
	}
	hostMAC, _ := net.ParseMAC(pair.Host.MAC)
	peerMAC, _ := net.ParseMAC(pair.Peer.MAC)
	config := make([]byte, 52)
	binary.NativeEndian.PutUint32(config, 1)
	binary.NativeEndian.PutUint32(config[4:], uint32(boundary.Link.IfIndex))
	binary.NativeEndian.PutUint32(config[12:], uint32(pair.Host.IfIndex))
	binary.NativeEndian.PutUint16(config[16:], 77)
	copy(config[36:42], hostMAC)
	copy(config[42:48], peerMAC)
	if err := collection.Maps["pppoe_tunnel_config"].Update(uint32(0), config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := ensureClsactQdisc(pair.Host.IfIndex); err != nil {
		t.Fatal(err)
	}
	filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: pair.Host.IfIndex, Parent: netlink.HANDLE_MIN_INGRESS, Handle: 1, Priority: 1, Protocol: unix.ETH_P_ALL}, Fd: collection.Programs["tc_tunnel"].FD(), Name: "veer_pd_test", DirectAction: true}
	if err := netlink.FilterReplace(filter); err != nil {
		t.Fatal(err)
	}
	req := pluginControlL2RecvRequest{Interface: wan, EtherType: 0x8864, Timeout: time.Second, MaxBytes: 1500, PPPoESessionID: 77, HasPPPoESessionID: true}
	fd, iface, err := openPluginControlL2RecvSocket(req)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	payload := make([]byte, 8+52)
	payload[0], payload[6], payload[7], payload[8], payload[14] = 0x11, 0, 0x57, 0x60, 17
	binary.BigEndian.PutUint16(payload[2:4], 77)
	binary.BigEndian.PutUint16(payload[4:6], 54)
	binary.BigEndian.PutUint16(payload[12:14], 12)
	payload[16], payload[17], payload[31], payload[32], payload[33], payload[47] = 0xfe, 0x80, 1, 0xfe, 0x80, 2
	binary.BigEndian.PutUint16(payload[48:50], 547)
	binary.BigEndian.PutUint16(payload[50:52], 546)
	binary.BigEndian.PutUint16(payload[52:54], 12)
	payload[56] = 7 // DHCPv6 Reply.
	send := pluginControlL2SendRequest{Interface: peer, EtherType: 0x8864, Payload: payload}
	copy(send.DstMAC[:], hostMAC)
	if err := (linuxPluginControlL2Transport{}).Send(send); err != nil {
		t.Fatal(err)
	}
	frame, err := recvPluginControlL2Frame(fd, iface, req)
	if err != nil || !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("installed tunnel hid DHCPv6 from protocol-bound control socket: %v", err)
	}
	// A normal UDP packet must still enter the tunnel, including when its
	// destination is link-local. Keeping every IPv6 UDP frame would break it.
	binary.BigEndian.PutUint16(payload[50:52], 45203)
	if err := (linuxPluginControlL2Transport{}).Send(send); err != nil {
		t.Fatal(err)
	}
	req.Timeout = 100 * time.Millisecond
	if _, err := recvPluginControlL2Frame(fd, iface, req); !errors.Is(err, errPluginControlL2Timeout) {
		t.Fatalf("ordinary UDP escaped tunnel: %v", err)
	}
}

func pppoeMSSTestPacket(v6 bool, extension, flags byte, mss uint16) ([]byte, int, []byte) {
	ipLen, extLen := 20, 0
	if v6 {
		ipLen = 40
		if extension != 0 {
			extLen = 8
		}
	}
	tcpOffset := 14 + ipLen + extLen
	packet := make([]byte, tcpOffset+24)
	ip := packet[14:]
	var pseudo []byte
	if v6 {
		packet[12], packet[13], ip[0], ip[6], ip[7] = 0x86, 0xdd, 0x60, 6, 64
		binary.BigEndian.PutUint16(ip[4:6], uint16(24+extLen))
		ip[8], ip[9], ip[23], ip[24], ip[25], ip[39] = 0x20, 1, 1, 0x20, 1, 2
		pseudo = append(append([]byte(nil), ip[8:40]...), 0, 0, 0, 24, 0, 0, 0, 6)
		if extLen != 0 {
			ip[6], ip[40] = extension, 6
		}
	} else {
		packet[12], packet[13], ip[0], ip[8], ip[9] = 8, 0, 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:4], 44)
		copy(ip[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
		binary.BigEndian.PutUint16(ip[10:12], pppoeTestChecksum(ip[:20]))
		pseudo = append(append([]byte(nil), ip[12:20]...), 0, 6, 0, 24)
	}
	tcp := packet[tcpOffset:]
	binary.BigEndian.PutUint16(tcp[:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12], tcp[13], tcp[20], tcp[21] = 0x60, flags, 2, 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	binary.BigEndian.PutUint16(tcp[16:18], pppoeTestChecksum(append(append([]byte(nil), pseudo...), tcp...)))
	return packet, tcpOffset, pseudo
}

func pppoeTestChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
