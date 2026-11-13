//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	tcActRedirect = 7
	tcActUnspec   = math.MaxUint32 // TC_ACT_UNSPEC (-1)
)

// loadTCProgramsForTest loads the named programs of the embedded TC object
// with only the maps they use, hash maps cut down to test size.
func loadTCProgramsForTest(t *testing.T, names ...string) *ebpf.Collection {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	spec, err := loadEmbeddedKernelCollectionSpec(false)
	if err != nil {
		t.Skipf("embedded tc object is unavailable: %v", err)
	}
	programs := make(map[string]*ebpf.ProgramSpec, len(names))
	maps := make(map[string]*ebpf.MapSpec)
	for _, name := range names {
		progSpec := spec.Programs[name]
		if progSpec == nil {
			t.Fatalf("embedded tc object has no %s program", name)
		}
		programs[name] = progSpec
		for _, ins := range progSpec.Instructions {
			if m := spec.Maps[ins.Reference()]; m != nil {
				maps[ins.Reference()] = m
			}
		}
	}
	for _, m := range maps {
		if (m.Type == ebpf.Hash || m.Type == ebpf.LRUHash) && m.MaxEntries > 4096 {
			m.MaxEntries = 4096
		}
	}
	for name, v := range spec.Variables {
		if maps[v.SectionName] == nil {
			delete(spec.Variables, name)
		}
	}
	spec.Programs = programs
	spec.Maps = maps
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load %v: %v", names, err)
	}
	t.Cleanup(coll.Close)
	return coll
}

// loadFlowCacheProgramForTest loads tc_flow_cache with only the maps it uses.
func loadFlowCacheProgramForTest(t *testing.T) *ebpf.Collection {
	t.Helper()
	return loadTCProgramsForTest(t, kernelFlowCacheProgramName)
}

// flowCacheTestFrame builds an untagged IPv4 UDP frame.
func flowCacheTestFrame(dstMAC net.HardwareAddr, src, dst net.IP, srcPort, dstPort uint16) []byte {
	payload := []byte("veer flow cache test payload....")
	frame := make([]byte, 14+20+8+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[8] = 64
	ip[9] = syscall.IPPROTO_UDP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipv4HeaderChecksumForTest(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(frame[42:], payload)
	return frame
}

func ipv4HeaderChecksumForTest(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func ipv4ToHostOrderForTest(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

// tc_flow_cache serves a packet only like the one the core recorded: same
// arrival interface and destination MAC, current generation, unexpired. A
// reply entering a bridge port is found under the port's parent.
func TestTCFlowCacheProgramServesOnlyMatchingPackets(t *testing.T) {
	coll := loadFlowCacheProgramForTest(t)
	prog := coll.Programs[kernelFlowCacheProgramName]
	cacheMap := coll.Maps[kernelTCFlowCacheMapName]
	stateMap := coll.Maps[kernelTCFlowCacheStateMapName]
	parentMap := coll.Maps[kernelIfParentMapName]
	if cacheMap == nil || stateMap == nil || parentMap == nil {
		t.Fatalf("maps of %s: cache=%v state=%v parent=%v", kernelFlowCacheProgramName, cacheMap, stateMap, parentMap)
	}
	// BPF_PROG_TEST_RUN runs on the loopback device unless told otherwise.
	const arrival = 1
	const parent = 9
	if err := stateMap.Put(uint32(0), tcFlowCacheStateV4{Generation: 3, Enabled: 1}); err != nil {
		t.Fatalf("write cache state: %v", err)
	}
	routerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}
	otherMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xbb}
	nextHopMAC := [6]byte{0x02, 0, 0, 0, 0, 0xcc}
	uplinkMAC := [6]byte{0x02, 0, 0, 0, 0, 0xdd}
	client := net.IPv4(192, 0, 2, 10)
	remote := net.IPv4(198, 51, 100, 7)
	natAddr := net.IPv4(203, 0, 113, 1)

	type testCase struct {
		name     string
		dstMAC   net.HardwareAddr
		keyIf    uint32
		parentOf map[uint32]uint32
		mutate   func(*tcFlowCacheValueV4)
		want     uint32
	}
	cases := []testCase{
		{name: "matching packet", dstMAC: routerMAC, keyIf: arrival, want: tcActRedirect},
		{name: "other destination MAC", dstMAC: otherMAC, keyIf: arrival, want: tcActUnspec},
		{name: "other arrival interface", dstMAC: routerMAC, keyIf: arrival, mutate: func(v *tcFlowCacheValueV4) { v.InIfIndex = 5 }, want: tcActUnspec},
		{name: "stale generation", dstMAC: routerMAC, keyIf: arrival, mutate: func(v *tcFlowCacheValueV4) { v.Generation = 2 }, want: tcActUnspec},
		{name: "expired", dstMAC: routerMAC, keyIf: arrival, mutate: func(v *tcFlowCacheValueV4) { v.ExpiresNS = 1 }, want: tcActUnspec},
		{name: "reply under the port's parent", dstMAC: routerMAC, keyIf: parent, parentOf: map[uint32]uint32{arrival: parent}, want: tcActRedirect},
		{name: "parent entry from another port", dstMAC: routerMAC, keyIf: parent, parentOf: map[uint32]uint32{arrival: parent}, mutate: func(v *tcFlowCacheValueV4) { v.InIfIndex = 4 }, want: tcActUnspec},
		{name: "parent entry without a parent", dstMAC: routerMAC, keyIf: parent, want: tcActUnspec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := tcFlowKeyV4{
				IfIndex: tc.keyIf,
				SrcAddr: ipv4ToHostOrderForTest(remote),
				DstAddr: ipv4ToHostOrderForTest(natAddr),
				SrcPort: 443,
				DstPort: 40000,
				Proto:   syscall.IPPROTO_UDP,
			}
			value := tcFlowCacheValueV4{
				ExpiresNS:  math.MaxUint64,
				Generation: 3,
				OutIfIndex: 42,
				MaxLen:     1500,
				SrcAddr:    ipv4ToHostOrderForTest(remote),
				DstAddr:    ipv4ToHostOrderForTest(client),
				SrcPort:    443,
				DstPort:    51000,
				DMAC:       nextHopMAC,
				SMAC:       uplinkMAC,
				InIfIndex:  arrival,
			}
			copy(value.InDMAC[:], routerMAC)
			if tc.mutate != nil {
				tc.mutate(&value)
			}
			if err := cacheMap.Put(key, value); err != nil {
				t.Fatalf("write cache entry: %v", err)
			}
			t.Cleanup(func() { _ = cacheMap.Delete(key) })
			for child, p := range tc.parentOf {
				if err := parentMap.Put(child, p); err != nil {
					t.Fatalf("write parent mapping: %v", err)
				}
				child := child
				t.Cleanup(func() { _ = parentMap.Delete(child) })
			}

			frame := flowCacheTestFrame(tc.dstMAC, remote, natAddr, 443, 40000)
			out := make([]byte, len(frame)+64)
			ret, err := prog.Run(&ebpf.RunOptions{Data: frame, DataOut: out})
			if err != nil {
				t.Fatalf("run %s: %v", kernelFlowCacheProgramName, err)
			}
			if ret != tc.want {
				t.Fatalf("%s returned %d, want %d", kernelFlowCacheProgramName, int32(ret), int32(tc.want))
			}
			out = out[:len(frame)]
			if tc.want != tcActRedirect {
				if !bytes.Equal(out, frame) {
					t.Fatal("a packet the cache declined was changed")
				}
				return
			}
			if !bytes.Equal(out[0:6], nextHopMAC[:]) || !bytes.Equal(out[6:12], uplinkMAC[:]) {
				t.Fatalf("MACs = %x -> %x, want %x -> %x", out[6:12], out[0:6], uplinkMAC, nextHopMAC)
			}
			if got := net.IP(out[30:34]); !got.Equal(client) {
				t.Fatalf("destination = %v, want %v", got, client)
			}
			if got := binary.BigEndian.Uint16(out[36:38]); got != 51000 {
				t.Fatalf("destination port = %d, want 51000", got)
			}
			if got, want := binary.BigEndian.Uint16(out[24:26]), ipv4HeaderChecksumForTest(out[14:34]); got != want {
				t.Fatalf("IPv4 checksum = %#04x, want %#04x", got, want)
			}
		})
	}
}
