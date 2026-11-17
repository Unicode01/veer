//go:build linux

package app

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/Unicode01/veer/internal/netservice"
)

// ipv4TCPPayloadCounter sums the TCP payload of the IPv4 frames from src to
// dst that enter an interface. Like ipv4TCPFlowCounter it reads a packet
// socket bound to every protocol, which sees each frame before the TC
// ingress hook.
type ipv4TCPPayloadCounter struct {
	fd       int
	draining atomic.Bool
	done     chan struct{}
	bytes    uint64
	frames   uint64
}

func openIPv4TCPPayloadCounter(t *testing.T, ifName, src, dst string) *ipv4TCPPayloadCounter {
	t.Helper()
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("resolve %s: %v", ifName, err)
	}
	srcIP, dstIP := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	if srcIP == nil || dstIP == nil {
		t.Fatalf("flow %s -> %s is not IPv4", src, dst)
	}
	raw, err := bpf.Assemble(netservice.BuildPacketSocketEqualityFilter([]netservice.PacketSocketEqualityCheck{
		{Offset: 12, Size: 2, Value: unix.ETH_P_IP},
		{Offset: 14 + 9, Size: 1, Value: unix.IPPROTO_TCP},
		{Offset: 14 + 12, Size: 4, Value: binary.BigEndian.Uint32(srcIP)},
		{Offset: 14 + 16, Size: 4, Value: binary.BigEndian.Uint32(dstIP)},
	}))
	if err != nil {
		t.Fatalf("assemble packet filter: %v", err)
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, inst := range raw {
		filter[i] = unix.SockFilter{Code: inst.Op, Jt: inst.Jt, Jf: inst.Jf, K: inst.K}
	}
	// Protocol 0 receives nothing until the bind below starts the count.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open packet socket: %v", err)
	}
	counter := &ipv4TCPPayloadCounter{fd: fd, done: make(chan struct{})}
	fail := func(format string, args ...any) {
		_ = unix.Close(fd)
		t.Fatalf(format, args...)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		fail("attach packet filter: %v", err)
	}
	// Reads time out so that close can drain the queue and stop the reader.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 50_000}); err != nil {
		fail("set read timeout: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: htons(unix.ETH_P_ALL)}); err != nil {
		fail("bind packet socket to %s: %v", ifName, err)
	}
	go counter.read()
	t.Cleanup(func() {
		if counter.fd >= 0 {
			counter.draining.Store(true)
			<-counter.done
			_ = unix.Close(counter.fd)
		}
	})
	return counter
}

func (counter *ipv4TCPPayloadCounter) read() {
	defer close(counter.done)
	buf := make([]byte, 65536)
	for {
		n, from, err := unix.Recvfrom(counter.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) || (errors.Is(err, unix.EAGAIN) && !counter.draining.Load()) {
				continue
			}
			// Draining, and nothing came within the read timeout.
			return
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		if n < 14+20 {
			continue
		}
		ip := buf[14:n]
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl+20 {
			continue
		}
		payload := int(binary.BigEndian.Uint16(ip[2:4])) - ihl - int(ip[ihl+12]>>4)*4
		if payload > 0 {
			counter.bytes += uint64(payload)
		}
		counter.frames++
	}
}

// close drains what the socket still holds, stops the count and returns the
// payload bytes and frames counted. A frame the full queue dropped fails the
// test, since its payload is unknown.
func (counter *ipv4TCPPayloadCounter) close(t *testing.T) (bytes, frames uint64) {
	t.Helper()
	counter.draining.Store(true)
	<-counter.done
	stats, err := unix.GetsockoptTpacketStats(counter.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	_ = unix.Close(counter.fd)
	counter.fd = -1
	if err != nil {
		t.Fatalf("read packet socket statistics: %v", err)
	}
	if stats.Drops != 0 {
		t.Fatalf("packet socket dropped %d frames", stats.Drops)
	}
	return counter.bytes, counter.frames
}

func sumKernelRuleStatsForTest(t *testing.T, rt *linuxKernelRuleRuntime) kernelRuleStats {
	t.Helper()
	snapshot, err := rt.SnapshotStats()
	if err != nil {
		t.Fatalf("SnapshotStats() error = %v", err)
	}
	var total kernelRuleStats
	for _, stats := range snapshot.ByRuleID {
		total.BytesIn += stats.BytesIn
		total.BytesOut += stats.BytesOut
	}
	return total
}

// With traffic stats on, a packet the flow cache sends from its record counts
// into its rule as the full path would count it: over a whole TCP stream the
// rule's byte counters equal the TCP payload that entered the router in each
// direction, with the cache serving most packets as without it.
func TestEgressNATTCFlowCacheCountsTrafficStats(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	for _, natType := range []string{egressNATTypeSymmetric, egressNATTypeFullCone} {
		for _, cache := range []bool{false, true} {
			name := natType + "/cache off"
			if cache {
				name = natType + "/cache on"
			}
			t.Run(name, func(t *testing.T) {
				testEgressNATTCFlowCacheCountsTrafficStats(t, natType, cache)
			})
		}
	}
}

func testEgressNATTCFlowCacheCountsTrafficStats(t *testing.T, natType string, cache bool) {
	t.Setenv(egressNATHelperStreamCyclesEnv, "240")
	// Data both ways, so both directions count payload from records.
	t.Setenv(egressNATHelperStreamEchoEnv, "1")
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	rt := newTCKernelRuleRuntime(&Config{
		KernelTCFlowCacheSetting: &cache,
		Experimental:             map[string]bool{experimentalFeatureKernelTraffic: true},
	})
	defer rt.Close()
	if rt.enableFlowCache != cache || rt.flowCacheDisabledBy != "" {
		t.Fatalf("enableFlowCache = %t, flowCacheDisabledBy = %q; want %t beside traffic stats", rt.enableFlowCache, rt.flowCacheDisabledBy, cache)
	}
	rule := buildEgressNATSyntheticRule(EgressNAT{
		ID:              1,
		ParentInterface: topology.BridgeIF,
		OutInterface:    topology.UplinkHostIF,
		OutSourceIP:     egressNATUplinkAddr,
		Protocol:        "tcp",
		NATType:         natType,
		Enabled:         true,
	}, topology.ChildHostIF, 1, "tcp")
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("egress NAT result = %+v, want running tc", result)
	}
	diagMap := rt.coll.Maps[kernelDiagMapName]
	if diagMap == nil {
		t.Fatal("diag map is unavailable")
	}

	hitsBefore := flowCacheHitsForTest(t, diagMap)
	before := sumKernelRuleStatsForTest(t, rt)
	// Where the stream's packets enter the router: the client's at the
	// child, the backend's at the uplink.
	sent := openIPv4TCPPayloadCounter(t, topology.ChildHostIF, egressNATClientAddr, egressNATBackendAddr)
	replied := openIPv4TCPPayloadCounter(t, topology.UplinkHostIF, egressNATBackendAddr, egressNATUplinkAddr)
	stream := startEgressNATTCStream(t, topology)
	stream.wait(t)
	time.Sleep(100 * time.Millisecond)
	sentBytes, sentFrames := sent.close(t)
	repliedBytes, repliedFrames := replied.close(t)
	after := sumKernelRuleStatsForTest(t, rt)
	hits := flowCacheHitsForTest(t, diagMap) - hitsBefore

	bytesIn, bytesOut := uint64(after.BytesIn-before.BytesIn), uint64(after.BytesOut-before.BytesOut)
	frames := sentFrames + repliedFrames
	t.Logf("client sent %d payload bytes in %d frames, the backend %d in %d; the rule counted %d in, %d out; %d frames left from fast-path records",
		sentBytes, sentFrames, repliedBytes, repliedFrames, bytesIn, bytesOut, hits)
	if sentBytes == 0 || repliedBytes == 0 {
		t.Fatalf("the stream carried no payload one way: sent %d, replied %d", sentBytes, repliedBytes)
	}
	if bytesIn != sentBytes || bytesOut != repliedBytes {
		t.Fatalf("rule counted %d bytes in and %d out, want the stream's %d and %d", bytesIn, bytesOut, sentBytes, repliedBytes)
	}
	switch {
	case !cache && hits != 0:
		t.Fatalf("%d frames left from records with the cache off", hits)
	case cache && (hits > frames || hits*2 < frames):
		t.Fatalf("%d of %d frames left from records, want most of them", hits, frames)
	}
}
