//go:build linux

package app

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	transparentProxyIntegrationClientAddr = "203.0.113.77"
	transparentProxyIntegrationTable      = "197"
	transparentProxyIntegrationPort       = 24101
)

// dialAsTransparentClient connects from the host to target with source
// address from, the way Veer's user space transparent proxy dials a backend as
// the original client.
func dialAsTransparentClient(t *testing.T, from string, target string) (net.Conn, error) {
	t.Helper()
	dialer := net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)},
		Control: func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return dialer.DialContext(context.Background(), "tcp4", target)
}

// TestEgressNATTCLeavesTransparentProxyRepliesToTheHost covers a transparent
// shared site or user space forward whose backend is a guest behind egress
// NAT. The proxy dials the guest from the client's address, so the guest's
// answers go to that address; they belong to the host's transparent socket,
// not to a new outbound mapping. A host socket listening on a wildcard
// address must not take a guest's own outbound traffic.
func TestEgressNATTCLeavesTransparentProxyRepliesToTheHost(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)
	rt := newTCKernelRuleRuntime(&Config{})
	defer rt.Close()
	var rules []Rule
	for i, proto := range []string{"tcp", "udp"} {
		rules = append(rules, buildEgressNATSyntheticRule(EgressNAT{
			ID:              1,
			ParentInterface: topology.BridgeIF,
			OutInterface:    topology.UplinkHostIF,
			OutSourceIP:     egressNATUplinkAddr,
			Protocol:        "tcp+udp",
			NATType:         egressNATTypeSymmetric,
			Enabled:         true,
		}, topology.ChildHostIF, int64(i+1), proto))
	}
	results, err := rt.Reconcile(rules)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for _, rule := range rules {
		if result := results[rule.ID]; !result.Running || result.Error != "" {
			t.Fatalf("egress NAT rule %d result = %+v, want running", rule.ID, result)
		}
	}

	// Policy routing a transparent proxy relies on: answers to the client's
	// address are delivered to this host.
	cleanupRoute := func() {
		runDataplanePerfCmd("ip", "rule", "del", "to", transparentProxyIntegrationClientAddr, "lookup", transparentProxyIntegrationTable)
		runDataplanePerfCmd("ip", "route", "flush", "table", transparentProxyIntegrationTable)
	}
	cleanupRoute()
	t.Cleanup(cleanupRoute)
	mustRunDataplanePerfCmd(t, "ip", "route", "add", "local", "default", "dev", "lo", "table", transparentProxyIntegrationTable)
	mustRunDataplanePerfCmd(t, "ip", "rule", "add", "to", transparentProxyIntegrationClientAddr, "lookup", transparentProxyIntegrationTable, "priority", "50")

	listen := net.JoinHostPort(egressNATClientAddr, strconv.Itoa(transparentProxyIntegrationPort))
	observedFile := filepath.Join(t.TempDir(), "observed.txt")
	guestCmd, guestLogs := startEgressNATBackendHelperInNamespace(t, topology.ClientNS, "tcp", listen, observedFile)
	t.Cleanup(func() {
		if guestCmd != nil && guestCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, guestCmd)
		}
	})

	conn, err := dialAsTransparentClient(t, transparentProxyIntegrationClientAddr, listen)
	if err != nil {
		t.Fatalf("transparent dial to the guest failed: %v\nguest logs:\n%s", err, guestLogs.String())
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(egressNATProbePayload)); err != nil {
		t.Fatalf("write to the guest: %v", err)
	}
	echo := make([]byte, len(egressNATProbePayload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read the guest's answer: %v\nguest logs:\n%s", err, guestLogs.String())
	}
	_ = conn.Close()
	waitForEgressNATHelperExit(t, guestCmd, "tcp", guestLogs.String())
	data, err := os.ReadFile(observedFile)
	if err != nil {
		t.Fatalf("read observed peer: %v", err)
	}
	if got := strings.TrimSpace(string(data)); !strings.HasPrefix(got, transparentProxyIntegrationClientAddr) {
		t.Fatalf("guest saw the connection from %q, want the client's address %s", got, transparentProxyIntegrationClientAddr)
	}

	// A host UDP socket on every address, at the port the guest talks to
	// outside, is no transparent socket: the guest's datagram is translated.
	hostSocket, err := net.ListenPacket("udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(egressNATProbePort)))
	if err != nil {
		t.Fatalf("listen on the host: %v", err)
	}
	defer hostSocket.Close()
	if observed := runEgressNATIntegrationProbe(t, topology, "udp"); observed != egressNATUplinkAddr {
		t.Fatalf("guest datagram reached the outside from %q, want the NAT address %s", observed, egressNATUplinkAddr)
	}
}
