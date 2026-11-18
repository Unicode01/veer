//go:build linux

package app

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	hairpinIntegrationServerAddr = "198.18.0.3"
	hairpinIntegrationFrontPort  = 18080
	hairpinIntegrationServerPort = 19000
)

// setupHairpinIntegrationServer puts a second guest on the egress NAT
// topology's bridge, in its own namespace: the backend of a port forward on
// the uplink address that the first guest reaches by hairpin.
func setupHairpinIntegrationServer(t *testing.T, topology egressNATIntegrationTopology) string {
	t.Helper()
	suffix := strconv.Itoa(os.Getpid() % 100000)
	serverNS := "fwhs" + suffix
	hostIF := truncateIfName("fwhh" + suffix)
	nsIF := truncateIfName("fwhn" + suffix)
	cleanup := func() {
		runDataplanePerfCmd("ip", "link", "del", hostIF)
		runDataplanePerfCmd("ip", "netns", "del", serverNS)
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRunDataplanePerfCmd(t, "ip", "netns", "add", serverNS)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", hostIF, "type", "veth", "peer", "name", nsIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", hostIF, "master", topology.BridgeIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", hostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", nsIF, "netns", serverNS)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", serverNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", serverNS, "ip", "addr", "add", hairpinIntegrationServerAddr+"/24", "dev", nsIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", serverNS, "ip", "link", "set", nsIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", serverNS, "ip", "route", "replace", "default", "via", egressNATBridgeAddr, "dev", nsIF)
	return serverNS
}

// runHairpinIntegrationProbe has a TCP client in clientNS connect to target
// and returns the source address the server in serverNS saw.
func runHairpinIntegrationProbe(t *testing.T, clientNS string, serverNS string, target string) string {
	t.Helper()
	listen := net.JoinHostPort(hairpinIntegrationServerAddr, strconv.Itoa(hairpinIntegrationServerPort))
	observedFile := filepath.Join(t.TempDir(), "observed.txt")
	serverCmd, serverLogs := startEgressNATBackendHelperInNamespace(t, serverNS, "tcp", listen, observedFile)
	t.Cleanup(func() {
		if serverCmd != nil && serverCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, serverCmd)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", clientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"=tcp",
		egressNATHelperTargetAddrEnv+"="+target,
	)
	if output, err := clientCmd.CombinedOutput(); err != nil {
		t.Fatalf("client in %s to %s failed: %v\nclient output:\n%s\nserver logs:\n%s", clientNS, target, err, output, serverLogs.String())
	}
	waitForEgressNATHelperExit(t, serverCmd, "tcp", serverLogs.String())
	data, err := os.ReadFile(observedFile)
	if err != nil {
		t.Fatalf("read observed peer: %v\nserver logs:\n%s", err, serverLogs.String())
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(string(data)))
	if err != nil {
		return strings.TrimSpace(string(data))
	}
	return host
}

// TestKernelTCHairpinReachesForwardFromGuest is the managed network case: a
// guest behind egress NAT connects to the host's public address on a port the
// host forwards to another guest on the same bridge. Without hairpin the host
// itself answers with a reset. With it the connection reaches the backend from
// the bridge's address, for transparent and non-transparent forwards alike,
// while clients outside keep seeing what the forward promises.
func TestKernelTCHairpinReachesForwardFromGuest(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	for _, transparent := range []bool{true, false} {
		name := "fullnat"
		if transparent {
			name = "transparent"
		}
		t.Run(name, func(t *testing.T) {
			topology := setupEgressNATIntegrationTopology(t)
			seedEgressNATIntegrationNeighbor(t, topology)
			serverNS := setupHairpinIntegrationServer(t, topology)

			rt := newTCKernelRuleRuntime(&Config{})
			defer rt.Close()
			egress := buildEgressNATSyntheticRule(EgressNAT{
				ID:              1,
				ParentInterface: topology.BridgeIF,
				OutInterface:    topology.UplinkHostIF,
				OutSourceIP:     egressNATUplinkAddr,
				Protocol:        "tcp",
				NATType:         egressNATTypeSymmetric,
				Enabled:         true,
			}, topology.ChildHostIF, 1, "tcp")
			forward := Rule{
				ID:               2,
				InInterface:      topology.UplinkHostIF,
				InIP:             egressNATUplinkAddr,
				InPort:           hairpinIntegrationFrontPort,
				OutInterface:     topology.BridgeIF,
				OutIP:            hairpinIntegrationServerAddr,
				OutPort:          hairpinIntegrationServerPort,
				Protocol:         "tcp",
				Transparent:      transparent,
				Enabled:          true,
				EnginePreference: ruleEngineKernel,
			}
			results, err := rt.Reconcile([]Rule{egress, forward})
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			for _, rule := range []Rule{egress, forward} {
				if result := results[rule.ID]; !result.Running || result.Error != "" {
					t.Fatalf("rule %d result = %+v, want running", rule.ID, result)
				}
			}

			target := net.JoinHostPort(egressNATUplinkAddr, strconv.Itoa(hairpinIntegrationFrontPort))
			if got := runHairpinIntegrationProbe(t, topology.ClientNS, serverNS, target); got != egressNATBridgeAddr {
				t.Fatalf("hairpin connection reached the backend from %s, want the bridge address %s", got, egressNATBridgeAddr)
			}

			wantOutside := egressNATBridgeAddr
			if transparent {
				wantOutside = egressNATBackendAddr
			}
			if got := runHairpinIntegrationProbe(t, topology.BackendNS, serverNS, target); got != wantOutside {
				t.Fatalf("outside connection reached the backend from %s, want %s", got, wantOutside)
			}

			// A second hairpin connection after the first one closed.
			if got := runHairpinIntegrationProbe(t, topology.ClientNS, serverNS, target); got != egressNATBridgeAddr {
				t.Fatalf("second hairpin connection reached the backend from %s, want %s", got, egressNATBridgeAddr)
			}
		})
	}
}
