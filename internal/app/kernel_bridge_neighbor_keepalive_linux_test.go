//go:build linux

package app

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestBridgeNeighborKeepaliveEvery(t *testing.T) {
	cases := []struct {
		ageing time.Duration
		want   time.Duration
	}{
		{ageing: 300 * time.Second, want: 60 * time.Second},
		{ageing: 120 * time.Second, want: 30 * time.Second},
		{ageing: 2 * time.Second, want: time.Second},
	}
	for _, tc := range cases {
		if got := bridgeNeighborKeepaliveEvery(tc.ageing); got != tc.want {
			t.Fatalf("bridgeNeighborKeepaliveEvery(%s) = %s, want %s", tc.ageing, got, tc.want)
		}
	}
}

// A guest that sends nothing through its bridge is forgotten after the
// bridge's ageing time. Given only a stale neighbour entry of the host for
// it, the keepalive has it answer probes through the bridge, which learns it
// again and keeps it. The keepalive is given the guest's port, as the
// dataplane is attached there, and finds the bridge itself.
func TestBridgeNeighborKeepaliveKeepsGuestsLearned(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	for _, command := range []string{"ip", "bridge", "ping"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s command is required", command)
		}
	}

	topology := setupEgressNATIntegrationTopology(t)
	const ageing = 6 * time.Second
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BridgeIF, "type", "bridge", "ageing_time", "600")
	// The guest must send nothing on its own, or it would refresh the bridge
	// without the keepalive: no ARP probes of the host, and no IPv6, whose
	// router solicitations go out every few seconds while no router answers.
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "neigh", "replace", egressNATBridgeAddr, "lladdr", mustReadHostInterfaceMAC(t, topology.BridgeIF), "dev", topology.ClientNSIF, "nud", "permanent")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "sysctl", "-qw", "net.ipv6.conf."+topology.ClientNSIF+".disable_ipv6=1")
	clientMAC := strings.ToLower(mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF))
	port, err := net.InterfaceByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("read port %s: %v", topology.ChildHostIF, err)
	}
	learned := func() bool {
		out, err := exec.Command("bridge", "fdb", "show", "br", topology.BridgeIF).CombinedOutput()
		if err != nil {
			t.Fatalf("bridge fdb show: %v: %s", err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			// An entry past its ageing time is listed as stale until the
			// bridge collects it.
			if len(fields) >= 3 && strings.ToLower(fields[0]) == clientMAC && fields[1] == "dev" && fields[2] == topology.ChildHostIF &&
				!strings.Contains(line, "permanent") && !strings.Contains(line, "stale") {
				return true
			}
		}
		return false
	}

	// Without the keepalive: learned from a ping, then forgotten. The host's
	// neighbour entry goes too, so that the host does not probe the guest on
	// its own either.
	mustRunDataplanePerfCmd(t, "ping", "-c", "1", "-W", "2", egressNATClientAddr)
	if !learned() {
		t.Fatalf("bridge did not learn the guest %s from a ping", clientMAC)
	}
	mustRunDataplanePerfCmd(t, "ip", "neigh", "del", egressNATClientAddr, "dev", topology.BridgeIF)
	time.Sleep(ageing + 3*time.Second)
	if learned() {
		t.Fatalf("guest %s still learned after the ageing time without traffic; the test cannot tell the keepalive apart", clientMAC)
	}

	// With it, from a stale neighbour entry alone, as the host keeps for a
	// guest the dataplane serves. Quick neighbour state changes make the
	// probes come within the short ageing time; the sysctls go with the
	// test bridge.
	mustRunDataplanePerfCmd(t, "sysctl", "-qw", "net.ipv4.neigh."+topology.BridgeIF+".delay_first_probe_time=1")
	mustRunDataplanePerfCmd(t, "sysctl", "-qw", "net.ipv4.neigh."+topology.BridgeIF+".base_reachable_time_ms=1000")
	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", egressNATClientAddr, "lladdr", clientMAC, "dev", topology.BridgeIF, "nud", "stale")
	deadline := time.Now().Add(3 * ageing)
	for time.Now().Before(deadline) {
		refreshBridgeNeighbors([]int{port.Index})
		time.Sleep(time.Second)
	}
	if !learned() {
		t.Fatalf("guest %s not learned by the bridge despite the keepalive", clientMAC)
	}
}
