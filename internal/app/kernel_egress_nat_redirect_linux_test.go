//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// An Ethernet exit without ARP (a VPN core's veervpn* dummy or ARP-less veth,
// a veerwan device) addresses every frame from and to its own MAC; an exit
// with ARP, or one without Ethernet addresses, has neighbours to resolve.
func TestKernelEgressNATExitWithoutARP(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	attrs := func(flags uint32, encap string, hw net.HardwareAddr) netlink.LinkAttrs {
		return netlink.LinkAttrs{Name: "x", Index: 7, RawFlags: flags, EncapType: encap, HardwareAddr: hw}
	}
	for _, tc := range []struct {
		name string
		link netlink.Link
		want bool
	}{
		{"dummy without ARP", &netlink.Dummy{LinkAttrs: attrs(unix.IFF_UP|unix.IFF_NOARP, "ether", mac)}, true},
		{"veerwan without ARP", &netlink.GenericLink{LinkAttrs: attrs(unix.IFF_NOARP, "ether", mac), LinkType: "veerwan"}, true},
		{"veth without ARP", &netlink.Veth{LinkAttrs: attrs(unix.IFF_UP|unix.IFF_NOARP, "", mac)}, true},
		{"dummy with ARP", &netlink.Dummy{LinkAttrs: attrs(unix.IFF_UP, "ether", mac)}, false},
		{"veth with ARP", &netlink.Veth{LinkAttrs: attrs(unix.IFF_UP, "ether", mac)}, false},
		{"without a MAC", &netlink.Dummy{LinkAttrs: attrs(unix.IFF_NOARP, "ether", nil)}, false},
		{"zero MAC", &netlink.Dummy{LinkAttrs: attrs(unix.IFF_NOARP, "ether", make(net.HardwareAddr, 6))}, false},
		{"tun", &netlink.Tuntap{LinkAttrs: attrs(unix.IFF_NOARP|unix.IFF_POINTOPOINT, "none", nil)}, false},
		{"infiniband", &netlink.GenericLink{LinkAttrs: attrs(unix.IFF_NOARP, "infiniband", make(net.HardwareAddr, 20)), LinkType: "ipoib"}, false},
		{"nil", nil, false},
	} {
		got, ok := kernelEgressNATExitWithoutARP(tc.link)
		if ok != tc.want {
			t.Errorf("%s: kernelEgressNATExitWithoutARP ok = %v, want %v", tc.name, ok, tc.want)
			continue
		}
		if ok && !bytes.Equal(got[:], mac) {
			t.Errorf("%s: MAC = %x, want the device's own %s", tc.name, got, mac)
		}
	}
}

const (
	egressNATVPNBoundaryAddr = "198.19.9.1"
	// A remote on none of this host's networks: traffic to those stays
	// with the kernel's routing (egress_nat_dst_is_local_v4).
	egressNATVPNRemoteAddr   = "203.0.113.9"
	egressNATVPNBoundaryPort = 24011
)

// flowFastRecordsForProto lists, per key ifindex of the flow entries of
// proto that hold a fast-path record, the arrival ifindex of each record.
func flowFastRecordsForProto(m *ebpf.Map, proto uint8) (map[int][]int, error) {
	records := map[int][]int{}
	iter := m.Iterate()
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		if key.Proto == proto && value.Fast.Stamp != 0 {
			records[int(key.IfIndex)] = append(records[int(key.IfIndex)], int(value.Fast.InIfIndex))
		}
	}
	return records, iter.Err()
}

// boundaryFrameWatch reads the IPv4 UDP frames a device transmits.
type boundaryFrameWatch struct {
	fd       int
	done     chan struct{}
	mu       sync.Mutex
	matched  int
	problems []string
}

// watchBoundaryFrames counts the frames leaving ifName from src to dst:port
// and notes any that is not addressed from and to mac.
func watchBoundaryFrames(t *testing.T, ifName string, mac net.HardwareAddr, src, dst net.IP, port int) *boundaryFrameWatch {
	t.Helper()
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("resolve %s: %v", ifName, err)
	}
	// Transmitted frames reach only ETH_P_ALL sockets. Protocol 0 receives
	// nothing until the bind below picks the device.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open packet socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		t.Fatalf("bind packet socket to %s: %v", ifName, err)
	}
	tv := unix.NsecToTimeval(int64(100 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		t.Fatalf("set packet socket timeout: %v", err)
	}
	w := &boundaryFrameWatch{fd: fd, done: make(chan struct{})}
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-w.done:
				return
			default:
			}
			n, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
					continue
				}
				return
			}
			ll, ok := from.(*unix.SockaddrLinklayer)
			if !ok || ll.Pkttype != unix.PACKET_OUTGOING || n < 14+20+8 {
				continue
			}
			frame := buf[:n]
			if binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP {
				continue
			}
			ip := frame[14:]
			ihl := int(ip[0]&0x0f) * 4
			if ip[9] != unix.IPPROTO_UDP || ihl < 20 || len(ip) < ihl+8 ||
				!net.IP(ip[12:16]).Equal(src) || !net.IP(ip[16:20]).Equal(dst) ||
				int(binary.BigEndian.Uint16(ip[ihl+2:ihl+4])) != port {
				continue
			}
			w.mu.Lock()
			w.matched++
			if !bytes.Equal(frame[0:6], mac) || !bytes.Equal(frame[6:12], mac) {
				w.problems = append(w.problems, "frame "+net.HardwareAddr(frame[6:12]).String()+" -> "+net.HardwareAddr(frame[0:6]).String())
			}
			w.mu.Unlock()
		}
	}()
	t.Cleanup(w.close)
	return w
}

func (w *boundaryFrameWatch) close() {
	select {
	case <-w.done:
	default:
		close(w.done)
		unix.Close(w.fd)
	}
}

func (w *boundaryFrameWatch) result() (int, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.matched, append([]string(nil), w.problems...)
}

func ipv4HostOrderForTest(t *testing.T, addr string) uint32 {
	t.Helper()
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		t.Fatalf("%q is not IPv4", addr)
	}
	return binary.BigEndian.Uint32(ip)
}

func diagForTest(t *testing.T, diagMap *ebpf.Map) kernelDiagValueV4 {
	t.Helper()
	var values []kernelDiagValueV4
	if err := diagMap.Lookup(uint32(0), &values); err != nil {
		t.Fatalf("read diag counters: %v", err)
	}
	return aggregateKernelPerCPUDiag(values)
}

// An egress NAT whose exit is a VPN core's boundary, which the core's plugin
// consumes on TC egress (a dummy with one /32, or in the segmented mode a
// veth with ARP off), needs no redirect_mode. The FIB has no route by such a
// device, and a device without ARP addresses every frame from and to itself,
// so the rule takes prepared_l2 with that address: every packet leaves by
// the boundary as the kernel would address it, without a FIB lookup or
// bpf_redirect_neigh. The flow cache records the flow and serves it, for
// both NAT types, also after a lapsed fast-path window has sent a packet
// through the full path again.
func TestEgressNATTCVPNBoundaryExit(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	for _, kind := range []string{"dummy", "veth"} {
		for _, natType := range []string{egressNATTypeSymmetric, egressNATTypeFullCone} {
			t.Run(kind+"/"+natType, func(t *testing.T) {
				testEgressNATTCVPNBoundaryExit(t, kind, natType)
			})
		}
	}
}

func testEgressNATTCVPNBoundaryExit(t *testing.T, kind string, natType string) {
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)
	boundary := truncateIfName("fwvd" + strconv.Itoa(os.Getpid()%100000))
	runDataplanePerfCmd("ip", "link", "del", boundary)
	t.Cleanup(func() { runDataplanePerfCmd("ip", "link", "del", boundary) })
	if kind == "veth" {
		// The plugin's end of a segmented boundary stays in this namespace.
		peer := truncateIfName("fwvp" + strconv.Itoa(os.Getpid()%100000))
		mustRunDataplanePerfCmd(t, "ip", "link", "add", boundary, "type", "veth", "peer", "name", peer)
		mustRunDataplanePerfCmd(t, "ip", "link", "set", boundary, "arp", "off")
		mustRunDataplanePerfCmd(t, "ip", "link", "set", peer, "up")
	} else {
		mustRunDataplanePerfCmd(t, "ip", "link", "add", boundary, "type", "dummy")
	}
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", egressNATVPNBoundaryAddr+"/32", "dev", boundary)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", boundary, "up")
	boundaryLink, err := netlink.LinkByName(boundary)
	if err != nil {
		t.Fatalf("resolve %s: %v", boundary, err)
	}
	boundaryMAC := boundaryLink.Attrs().HardwareAddr
	child, err := netlink.LinkByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.ChildHostIF, err)
	}

	enabled := true
	rt := newTCKernelRuleRuntime(&Config{KernelTCFlowCacheSetting: &enabled})
	defer rt.Close()
	rule := buildEgressNATSyntheticRule(EgressNAT{
		ID:              1,
		ParentInterface: topology.BridgeIF,
		OutInterface:    boundary,
		OutSourceIP:     egressNATVPNBoundaryAddr,
		Protocol:        "udp",
		NATType:         natType,
		Enabled:         true,
	}, topology.ChildHostIF, 1, "udp")
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("egress NAT result = %+v, want running tc", result)
	}
	rulesMap := rt.coll.Maps[kernelRulesMapNameV4]
	flowsMap := rt.coll.Maps[kernelFlowsMapNameV4]
	diagMap := rt.coll.Maps[kernelDiagMapName]
	if rulesMap == nil || flowsMap == nil || diagMap == nil {
		t.Fatal("rule, flow or diag map is unavailable")
	}
	var ruleKey tcRuleKeyV4
	var ruleValue tcRuleValueV4
	found := false
	for iter := rulesMap.Iterate(); iter.Next(&ruleKey, &ruleValue); {
		if ruleKey.IfIndex == uint32(child.Attrs().Index) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no rule for %s", topology.ChildHostIF)
	}
	if ruleValue.Flags&kernelRuleFlagPreparedL2 == 0 || !bytes.Equal(ruleValue.EgressSrcMAC[:], boundaryMAC) ||
		!bytes.Equal(ruleValue.EgressDstMAC[:], boundaryMAC) {
		t.Fatalf("rule flags %#x, egress MACs %x -> %x, want prepared_l2 from and to %s",
			ruleValue.Flags, ruleValue.EgressSrcMAC, ruleValue.EgressDstMAC, boundaryMAC)
	}

	watch := watchBoundaryFrames(t, boundary, boundaryMAC, net.ParseIP(egressNATVPNBoundaryAddr).To4(),
		net.ParseIP(egressNATVPNRemoteAddr).To4(), egressNATVPNBoundaryPort)
	before := diagForTest(t, diagMap)
	// Long enough that the uplink check looks the path up, which the FIB
	// cannot judge for the boundary.
	payload := bytes.Repeat([]byte{'v'}, 1200)
	const perBurst = 200
	send := func() {
		t.Helper()
		err := runInNetNSForTest(topology.ClientNS, func() error {
			conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(egressNATVPNRemoteAddr), Port: egressNATVPNBoundaryPort})
			if err != nil {
				return err
			}
			defer conn.Close()
			for i := 0; i < perBurst; i++ {
				if _, err := conn.Write(payload); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
					return err
				}
				time.Sleep(time.Millisecond)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("send datagrams from %s: %v", topology.ClientNS, err)
		}
	}
	send()
	deadline := time.Now().Add(3 * time.Second)
	for {
		records, err := flowFastRecordsForProto(flowsMap, unix.IPPROTO_UDP)
		if err != nil {
			t.Fatalf("read flow entries: %v", err)
		}
		if len(records[child.Attrs().Index]) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fast-path records per key ifindex = %v, want one under %s", records, topology.ChildHostIF)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Past the fast-path window the flow takes the full path once more.
	time.Sleep(1200 * time.Millisecond)
	send()
	time.Sleep(200 * time.Millisecond)
	after := diagForTest(t, diagMap)
	watch.close()

	matched, problems := watch.result()
	if matched < 2*perBurst-4 {
		t.Fatalf("%d of %d datagrams left by %s translated", matched, 2*perBurst, boundary)
	}
	if len(problems) > 0 {
		t.Fatalf("frames on %s not addressed from and to %s: %v", boundary, boundaryMAC, problems[:minInt(len(problems), 5)])
	}
	if n := after.FIBNonSuccess - before.FIBNonSuccess; n != 0 {
		t.Fatalf("%d next-hop lookups failed, want none", n)
	}
	if n := after.RedirectNeighUsed - before.RedirectNeighUsed; n != 0 {
		t.Fatalf("%d packets used bpf_redirect_neigh, want none", n)
	}
	// The uplink check found no route by the boundary to judge a length by
	// and keeps that finding without a next hop, so fast paths skip the
	// lookup until a full path looks again.
	l2Map := rt.coll.Maps["tc_l2_cache_v4"]
	if l2Map == nil {
		t.Fatal("tc_l2_cache_v4 is unavailable")
	}
	l2Key := struct {
		IfIndex uint32
		SrcAddr uint32
		DstAddr uint32
	}{uint32(boundaryLink.Attrs().Index), ipv4HostOrderForTest(t, egressNATVPNBoundaryAddr), ipv4HostOrderForTest(t, egressNATVPNRemoteAddr)}
	var l2Value struct {
		DstMAC     [6]byte
		SrcMAC     [6]byte
		OutIfIndex uint32
		MaxLen     uint32
	}
	if err := l2Map.Lookup(&l2Key, &l2Value); err != nil {
		t.Fatalf("uplink check entry for %s -> %s: %v", egressNATVPNBoundaryAddr, egressNATVPNRemoteAddr, err)
	}
	if l2Value.OutIfIndex != 0 || l2Value.MaxLen != 0xffff {
		t.Fatalf("uplink check entry = %+v, want no next hop and an unchecked length", l2Value)
	}
	hits := after.FlowCacheHit - before.FlowCacheHit
	t.Logf("%d datagrams left by %s, %d from fast-path records", matched, boundary, hits)
	// Each burst takes the full path for its first packet and the next one,
	// which records; everything else must leave from the record.
	if hits+8 < 2*perBurst {
		t.Fatalf("%d of %d datagrams left from fast-path records, want all but the first few of each burst", hits, 2*perBurst)
	}
}
