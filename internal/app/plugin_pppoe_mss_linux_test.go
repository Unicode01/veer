//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
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
`, source)
	cfile, object := filepath.Join(dir, "mss.c"), filepath.Join(dir, "mss.o")
	if err := os.WriteFile(cfile, []byte(wrapper), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("clang", "-O2", "-target", "bpf", "-c", cfile, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile PPPoE: %v\n%s", err, output)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
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
