//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the integration test as root:
//      FORWARD_RUN_MANAGED_NETWORK_TEST=1 go test ./internal/app -run TestManagedNetworkIntegration -count=1 -v

const (
	managedNetworkIntegrationEnableEnv             = "FORWARD_RUN_MANAGED_NETWORK_TEST"
	managedNetworkIntegrationHelperEnv             = "FORWARD_MANAGED_NETWORK_HELPER"
	managedNetworkIntegrationHelperRoleEnv         = "FORWARD_MANAGED_NETWORK_HELPER_ROLE"
	managedNetworkIntegrationHelperIfaceEnv        = "FORWARD_MANAGED_NETWORK_HELPER_IFACE"
	managedNetworkIntegrationHelperExpectedIPv4Env = "FORWARD_MANAGED_NETWORK_HELPER_EXPECTED_IPV4"
	managedNetworkIntegrationHelperExpectedCIDREnv = "FORWARD_MANAGED_NETWORK_HELPER_EXPECTED_CIDR"
	managedNetworkIntegrationHelperGatewayEnv      = "FORWARD_MANAGED_NETWORK_HELPER_GATEWAY"
	managedNetworkIntegrationHelperRoleDHCPv4      = "dhcp4-client"
	managedNetworkIntegrationIPv4CIDR              = "10.0.0.254/24"
	managedNetworkIntegrationIPv4Gateway           = "10.0.0.254"
	managedNetworkIntegrationIPv4Lease             = "10.0.0.10"
	managedNetworkIntegrationIPv4LeaseCIDR         = "10.0.0.10/24"
	managedNetworkIntegrationIPv4PoolStart         = "10.0.0.100"
	managedNetworkIntegrationIPv4PoolEnd           = "10.0.0.150"
	managedNetworkIntegrationName                  = "managed-network-integration"
	managedNetworkIntegrationIPv6Prefix64Parent    = "2001:db8:300::/60"
	managedNetworkIntegrationIPv6Prefix64HostAddr  = "2001:db8:300::1"
	managedNetworkIntegrationIPv6Prefix64PeerAddr  = "2001:db8:300::2"
)

func TestManagedNetworkIntegrationHelperProcess(t *testing.T) {
	if os.Getenv(managedNetworkIntegrationHelperEnv) != "1" {
		return
	}

	var err error
	switch strings.TrimSpace(os.Getenv(managedNetworkIntegrationHelperRoleEnv)) {
	case managedNetworkIntegrationHelperRoleDHCPv4:
		err = runManagedNetworkDHCPv4IntegrationHelper()
	default:
		err = fmt.Errorf("unknown managed network helper role %q", os.Getenv(managedNetworkIntegrationHelperRoleEnv))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestManagedNetworkIntegration(t *testing.T) {
	if os.Getenv(managedNetworkIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux managed network integration test", managedNetworkIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "managed-network")
	topology := harness.Topology
	perfTopology := dataplanePerfTopology{
		ClientNS:      topology.ClientNS,
		BackendNS:     topology.BackendNS,
		ClientHostIF:  topology.ChildHostIF,
		ClientNSIF:    topology.ClientNSIF,
		BackendHostIF: topology.UplinkHostIF,
		BackendNSIF:   topology.BackendNSIF,
	}

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	mustEnsureIPv6AssignmentAddress(t, perfTopology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationBackendAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationParentAddr)
	seedIPv6AssignmentIntegrationBackendNeighbors(t, perfTopology)

	network := createManagedNetworkIntegrationNetwork(t, harness.APIBase, topology)
	managedIPv6 := mustBuildManagedNetworkIntegrationIPv6Assignment(t, network, topology.ChildHostIF)
	clientMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	createManagedNetworkIntegrationReservation(t, harness.APIBase, network.ID, clientMAC, managedNetworkIntegrationIPv4Lease)
	waitForManagedNetworkIntegrationReady(t, harness.APIBase, network.ID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, "initial apply")
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(perfTopology, managedIPv6.AssignedPrefix); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}

	backendHelper := startIPv6AssignmentIntegrationBackendHelperWithAddrs(t, perfTopology, ipv6AssignmentIntegrationBackendAddr, ipv6AssignmentIntegrationParentAddr, managedIPv6.Address)
	defer stopIPv6AssignmentIntegrationHelper(t, backendHelper)

	if err := runManagedNetworkDHCPv4Client(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4LeaseCIDR, managedNetworkIntegrationIPv4Gateway); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}

	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}

	ipv6Helper := startIPv6AssignmentIntegrationHelperWithExpectedAddr(
		t,
		perfTopology,
		managedIPv6.Address,
		net.JoinHostPort(ipv6AssignmentIntegrationBackendAddr, strconv.Itoa(ipv6AssignmentIntegrationBackendPort)),
	)
	if err := waitForIPv6AssignmentIntegrationHelper(ipv6Helper, 20*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(backendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
}

func TestManagedNetworkIntegrationDelegatedPrefixSLAAC(t *testing.T) {
	if os.Getenv(managedNetworkIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux managed network integration test", managedNetworkIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "managed-network-prefix64-slaac")
	topology := harness.Topology
	perfTopology := dataplanePerfTopology{
		ClientNS:      topology.ClientNS,
		BackendNS:     topology.BackendNS,
		ClientHostIF:  topology.ChildHostIF,
		ClientNSIF:    topology.ClientNSIF,
		BackendHostIF: topology.UplinkHostIF,
		BackendNSIF:   topology.BackendNSIF,
	}

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	mustEnsureIPv6AssignmentAddress(t, perfTopology.BackendHostIF, managedNetworkIntegrationIPv6Prefix64HostAddr+"/60")
	mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, managedNetworkIntegrationIPv6Prefix64PeerAddr+"/60")
	mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, managedNetworkIntegrationIPv6Prefix64HostAddr)
	seedIPv6AssignmentIntegrationBackendNeighborsForAddresses(t, perfTopology, managedNetworkIntegrationIPv6Prefix64HostAddr, managedNetworkIntegrationIPv6Prefix64PeerAddr)

	network := createManagedNetworkIntegrationNetworkWithIPv6Settings(
		t,
		harness.APIBase,
		topology,
		managedNetworkIntegrationIPv6Prefix64Parent,
		managedNetworkIPv6AssignmentModePrefix64,
	)
	managedIPv6 := mustBuildManagedNetworkIntegrationIPv6Assignment(t, network, topology.ChildHostIF)
	clientMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	createManagedNetworkIntegrationReservation(t, harness.APIBase, network.ID, clientMAC, managedNetworkIntegrationIPv4Lease)
	waitForManagedNetworkIntegrationReady(t, harness.APIBase, network.ID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, "initial apply")
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(perfTopology, managedIPv6.AssignedPrefix); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}

	ipv6Helper := startIPv6AssignmentSLAACIntegrationHelperWithExpectedPrefix(t, perfTopology, managedIPv6.AssignedPrefix)
	if err := waitForIPv6AssignmentIntegrationHelper(ipv6Helper, 25*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
}

func TestManagedNetworkIntegrationRenewsAfterForwardRestart(t *testing.T) {
	if os.Getenv(managedNetworkIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux managed network integration test", managedNetworkIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "managed-network-restart-renew")
	topology := harness.Topology
	perfTopology := dataplanePerfTopology{
		ClientNS:      topology.ClientNS,
		BackendNS:     topology.BackendNS,
		ClientHostIF:  topology.ChildHostIF,
		ClientNSIF:    topology.ClientNSIF,
		BackendHostIF: topology.UplinkHostIF,
		BackendNSIF:   topology.BackendNSIF,
	}

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	mustEnsureIPv6AssignmentAddress(t, perfTopology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationBackendAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationParentAddr)
	seedIPv6AssignmentIntegrationBackendNeighbors(t, perfTopology)

	network := createManagedNetworkIntegrationNetwork(t, harness.APIBase, topology)
	managedIPv6 := mustBuildManagedNetworkIntegrationIPv6Assignment(t, network, topology.ChildHostIF)
	clientMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	createManagedNetworkIntegrationReservation(t, harness.APIBase, network.ID, clientMAC, managedNetworkIntegrationIPv4Lease)
	waitForManagedNetworkIntegrationReady(t, harness.APIBase, network.ID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, "initial apply")
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(perfTopology, managedIPv6.AssignedPrefix); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := runManagedNetworkDHCPv4Client(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4LeaseCIDR, managedNetworkIntegrationIPv4Gateway); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	seedManagedNetworkIntegrationIPv4Neighbors(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4Gateway)
	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("initial managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}

	mustEnsureManagedNetworkIntegrationIPv6AddressAbsentInNamespace(t, topology.ClientNS, topology.ClientNSIF, managedIPv6.Address, 5*time.Second)
	initialBackendHelper := startIPv6AssignmentIntegrationBackendHelperWithAddrs(t, perfTopology, ipv6AssignmentIntegrationBackendAddr, ipv6AssignmentIntegrationParentAddr, managedIPv6.Address)
	defer stopIPv6AssignmentIntegrationHelper(t, initialBackendHelper)
	initialIPv6Helper := startIPv6AssignmentIntegrationHelperWithExpectedAddr(
		t,
		perfTopology,
		managedIPv6.Address,
		net.JoinHostPort(ipv6AssignmentIntegrationBackendAddr, strconv.Itoa(ipv6AssignmentIntegrationBackendPort)),
	)
	if err := waitForIPv6AssignmentIntegrationHelper(initialIPv6Helper, 20*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(initialBackendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}

	restartManagedNetworkIntegrationForward(t, &harness)
	waitForManagedNetworkIntegrationReady(t, harness.APIBase, network.ID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, "post-restart apply")
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(perfTopology, managedIPv6.AssignedPrefix); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := runManagedNetworkDHCPv4Client(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4LeaseCIDR, managedNetworkIntegrationIPv4Gateway); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	seedManagedNetworkIntegrationIPv4Neighbors(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4Gateway)
	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("post-restart managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}

	seedIPv6AssignmentIntegrationBackendNeighbors(t, perfTopology)
	mustEnsureManagedNetworkIntegrationIPv6AddressAbsentInNamespace(t, topology.ClientNS, topology.ClientNSIF, managedIPv6.Address, 5*time.Second)
	restartedBackendHelper := startIPv6AssignmentIntegrationBackendHelperWithAddrs(t, perfTopology, ipv6AssignmentIntegrationBackendAddr, ipv6AssignmentIntegrationParentAddr, managedIPv6.Address)
	defer stopIPv6AssignmentIntegrationHelper(t, restartedBackendHelper)
	restartedIPv6Helper := startIPv6AssignmentIntegrationHelperWithExpectedAddr(
		t,
		perfTopology,
		managedIPv6.Address,
		net.JoinHostPort(ipv6AssignmentIntegrationBackendAddr, strconv.Itoa(ipv6AssignmentIntegrationBackendPort)),
	)
	if err := waitForIPv6AssignmentIntegrationHelper(restartedIPv6Helper, 20*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(restartedBackendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
}

func TestManagedNetworkIntegrationHotRestartKeepsEstablishedEgressTCPConnection(t *testing.T) {
	if os.Getenv(managedNetworkIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux managed network integration test", managedNetworkIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "managed-network-hot-restart-established")
	topology := harness.Topology
	perfTopology := dataplanePerfTopology{
		ClientNS:      topology.ClientNS,
		BackendNS:     topology.BackendNS,
		ClientHostIF:  topology.ChildHostIF,
		ClientNSIF:    topology.ClientNSIF,
		BackendHostIF: topology.UplinkHostIF,
		BackendNSIF:   topology.BackendNSIF,
	}

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	mustEnsureIPv6AssignmentAddress(t, perfTopology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationBackendAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationParentAddr)
	seedIPv6AssignmentIntegrationBackendNeighbors(t, perfTopology)

	network := createManagedNetworkIntegrationNetwork(t, harness.APIBase, topology)
	managedIPv6 := mustBuildManagedNetworkIntegrationIPv6Assignment(t, network, topology.ChildHostIF)
	clientMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	createManagedNetworkIntegrationReservation(t, harness.APIBase, network.ID, clientMAC, managedNetworkIntegrationIPv4Lease)
	waitForManagedNetworkIntegrationReady(t, harness.APIBase, network.ID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, "initial apply")
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(perfTopology, managedIPv6.AssignedPrefix); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := runManagedNetworkDHCPv4Client(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4LeaseCIDR, managedNetworkIntegrationIPv4Gateway); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	seedManagedNetworkIntegrationIPv4Neighbors(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4Gateway)
	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("initial managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}

	backendCmd, backendLogs := startDataplanePerfBackend(t, perfTopology)
	t.Cleanup(func() {
		stopDataplanePerfHelper(t, backendCmd)
	})

	client := startTCRuleMutationSteadyClientWithDuration(
		t,
		topology.ClientNS,
		net.JoinHostPort(dataplanePerfBackendAddr, strconv.Itoa(dataplanePerfBackendPort)),
		tcRuleMutationRestartSteadyDuration,
	)
	waitForTCRuleMutationSteadyClientReady(t, client)

	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		stopTCRuleMutationSteadyClient(t, client)
		t.Fatalf("write hot restart marker: %v", err)
	}

	restartManagedNetworkIntegrationForward(t, &harness)
	waitForManagedNetworkIntegrationReady(t, harness.APIBase, network.ID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, "post-hot-restart apply")
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	seedManagedNetworkIntegrationIPv4Neighbors(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4Gateway)

	stdout, stderr, err := waitForTCRuleMutationSteadyClient(client)
	if err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf(
			"steady client failed across managed network hot restart: %v\nstdout=%s\nstderr=%s\nbackend logs=%s",
			err,
			stdout,
			stderr,
			backendLogs.String(),
		)
	}

	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("post-hot-restart managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}
}

func TestManagedNetworkIntegrationRecoversAfterBridgeIPv4AddressReset(t *testing.T) {
	if os.Getenv(managedNetworkIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux managed network integration test", managedNetworkIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "managed-network-bridge-ipv4-reset")
	topology := harness.Topology
	perfTopology := dataplanePerfTopology{
		ClientNS:      topology.ClientNS,
		BackendNS:     topology.BackendNS,
		ClientHostIF:  topology.ChildHostIF,
		ClientNSIF:    topology.ClientNSIF,
		BackendHostIF: topology.UplinkHostIF,
		BackendNSIF:   topology.BackendNSIF,
	}

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	mustEnsureIPv6AssignmentAddress(t, perfTopology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationBackendAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationParentAddr)
	seedIPv6AssignmentIntegrationBackendNeighbors(t, perfTopology)

	network := createManagedNetworkIntegrationNetwork(t, harness.APIBase, topology)
	managedIPv6 := mustBuildManagedNetworkIntegrationIPv6Assignment(t, network, topology.ChildHostIF)
	clientMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	createManagedNetworkIntegrationReservation(t, harness.APIBase, network.ID, clientMAC, managedNetworkIntegrationIPv4Lease)
	waitForManagedNetworkIntegrationReady(t, harness.APIBase, network.ID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, "initial apply")
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(perfTopology, managedIPv6.AssignedPrefix); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}

	if err := runManagedNetworkDHCPv4Client(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4LeaseCIDR, managedNetworkIntegrationIPv4Gateway); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("initial managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}

	reloadRequestedAfter := time.Now()
	if err := removeManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("remove managed network bridge ipv4 address: %v", err)
	}
	if err := waitForManagedNetworkRuntimeReload(t, harness.APIBase, reloadRequestedAfter, "link_change"); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	if err := runManagedNetworkDHCPv4Client(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4LeaseCIDR, managedNetworkIntegrationIPv4Gateway); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	seedManagedNetworkIntegrationIPv4Neighbors(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4Gateway)
	seedEgressNATIntegrationNeighbor(t, topology)
	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("post-recovery managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}
}

func runManagedNetworkDHCPv4IntegrationHelper() error {
	ifaceName := strings.TrimSpace(os.Getenv(managedNetworkIntegrationHelperIfaceEnv))
	expectedIPv4 := strings.TrimSpace(os.Getenv(managedNetworkIntegrationHelperExpectedIPv4Env))
	expectedCIDR := strings.TrimSpace(os.Getenv(managedNetworkIntegrationHelperExpectedCIDREnv))
	gateway := strings.TrimSpace(os.Getenv(managedNetworkIntegrationHelperGatewayEnv))
	if ifaceName == "" {
		return errors.New("missing helper interface name")
	}
	if expectedIPv4 == "" {
		return errors.New("missing helper expected ipv4")
	}
	if expectedCIDR == "" {
		return errors.New("missing helper expected cidr")
	}
	if gateway == "" {
		return errors.New("missing helper gateway")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("resolve interface %q: %w", ifaceName, err)
	}
	expectedIP := parseIPLiteral(expectedIPv4)
	if expectedIP == nil || expectedIP.To4() == nil {
		return fmt.Errorf("invalid expected ipv4 %q", expectedIPv4)
	}
	leaseIP, err := performManagedNetworkDHCPv4Handshake(*iface, expectedIP.To4(), 15*time.Second)
	if err != nil {
		return err
	}
	if !leaseIP.Equal(expectedIP.To4()) {
		return fmt.Errorf("dhcpv4 lease = %s, want %s", leaseIP, expectedIPv4)
	}
	if err := ensureManagedNetworkIntegrationIPv4Address(ifaceName, expectedCIDR); err != nil {
		return fmt.Errorf("install dhcpv4 address: %w", err)
	}
	if err := ensureManagedNetworkIntegrationIPv4DefaultRoute(ifaceName, gateway); err != nil {
		return fmt.Errorf("install dhcpv4 default route: %w", err)
	}
	return nil
}

func seedManagedNetworkIntegrationIPv4Neighbors(t *testing.T, topology egressNATIntegrationTopology, leaseIP string, gateway string) {
	t.Helper()

	bridgeMAC := mustReadHostInterfaceMAC(t, topology.BridgeIF)
	childPeerMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)

	leaseIP = strings.TrimSpace(leaseIP)
	gateway = strings.TrimSpace(gateway)
	if leaseIP == "" || gateway == "" {
		t.Fatalf("managed network ipv4 neighbor seed requires lease and gateway")
	}

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "neigh", "replace", gateway, "lladdr", bridgeMAC, "dev", topology.ClientNSIF, "nud", "permanent")
	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", leaseIP, "lladdr", childPeerMAC, "dev", topology.ChildHostIF, "nud", "permanent")
}

func mustBuildManagedNetworkIntegrationIPv6Assignment(t *testing.T, network ManagedNetwork, childInterface string) IPv6Assignment {
	t.Helper()

	assignments, warnings := buildManagedNetworkIPv6Assignments(
		normalizeManagedNetwork(network),
		[]string{strings.TrimSpace(childInterface)},
		nil,
		make(map[string]struct{}),
		nil,
	)
	if len(warnings) > 0 {
		t.Fatalf("build managed network ipv6 assignment warnings: %s", strings.Join(warnings, "; "))
	}
	if len(assignments) != 1 {
		t.Fatalf("build managed network ipv6 assignments = %d, want 1", len(assignments))
	}
	return assignments[0]
}

func waitForManagedNetworkRuntimeReload(t *testing.T, apiBase string, requestedAfter time.Time, source string) error {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var last ManagedNetworkRuntimeReloadStatus
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/managed-networks/runtime-status", nil)
		if err != nil {
			t.Fatalf("build managed network runtime reload status request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if err := json.NewDecoder(resp.Body).Decode(&last); err != nil {
			resp.Body.Close()
			time.Sleep(250 * time.Millisecond)
			continue
		}
		resp.Body.Close()

		if last.Pending {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if !last.LastRequestedAt.IsZero() && last.LastRequestedAt.Before(requestedAfter) {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if last.LastCompletedAt.IsZero() {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if last.LastCompletedAt.Before(requestedAfter) {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if expected := strings.TrimSpace(source); expected != "" && strings.TrimSpace(last.LastRequestSource) != expected {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if strings.TrimSpace(last.LastResult) != "success" {
			return fmt.Errorf("managed network runtime reload completed with result=%q error=%q summary=%q", last.LastResult, last.LastError, last.LastAppliedSummary)
		}
		return nil
	}
	return fmt.Errorf("timed out waiting for managed network runtime reload after %s (last source=%q result=%q error=%q summary=%q)", requestedAfter.Format(time.RFC3339Nano), last.LastRequestSource, last.LastResult, last.LastError, last.LastAppliedSummary)
}

func waitForManagedNetworkIntegrationAutoEgressNATReady(t *testing.T, apiBase string, logPath string, phase string) {
	t.Helper()

	waitForEgressNATIntegrationTCActiveEntries(t, apiBase, logPath, phase, func(entries int) bool {
		return entries > 0
	})
}

func restartManagedNetworkIntegrationForward(t *testing.T, harness *egressNATIntegrationHarness) {
	t.Helper()

	if harness == nil {
		t.Fatal("managed network integration harness is nil")
	}

	stopForwardProcessTree(t, harness.Cmd)

	logFile, err := os.OpenFile(harness.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open forward log file for restart: %v", err)
	}

	cmd := exec.Command(harness.ForwardBinary, "--config", harness.ConfigPath)
	cmd.Dir = harness.WorkDir
	cmd.Env = append(os.Environ(),
		forwardKernelMaintenanceIntervalEnv+"="+strconv.Itoa(envInt(forwardKernelMaintenanceIntervalEnv, 600000)),
		forwardHotRestartMarkerEnv+"="+harness.HotRestartMarkerPath,
		forwardBPFStateDirEnv+"="+harness.BPFStateRoot,
		forwardRuntimeStateDirEnv+"="+harness.RuntimeStateRoot,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("restart forward: %v", err)
	}
	_ = logFile.Close()

	harness.Cmd = cmd
	t.Cleanup(func() {
		stopForwardProcessTree(t, cmd)
	})
	waitForEgressNATIntegrationAPI(t, harness.APIBase, cmd, harness.LogPath)
}

func createManagedNetworkIntegrationNetwork(t *testing.T, apiBase string, topology egressNATIntegrationTopology) ManagedNetwork {
	return createManagedNetworkIntegrationNetworkWithIPv6Settings(t, apiBase, topology, ipv6AssignmentIntegrationParentPrefix, managedNetworkIPv6AssignmentModeSingle128)
}

func createManagedNetworkIntegrationNetworkWithIPv6Mode(t *testing.T, apiBase string, topology egressNATIntegrationTopology, ipv6AssignmentMode string) ManagedNetwork {
	return createManagedNetworkIntegrationNetworkWithIPv6Settings(t, apiBase, topology, ipv6AssignmentIntegrationParentPrefix, ipv6AssignmentMode)
}

func createManagedNetworkIntegrationNetworkWithIPv6Settings(t *testing.T, apiBase string, topology egressNATIntegrationTopology, ipv6ParentPrefix string, ipv6AssignmentMode string) ManagedNetwork {
	t.Helper()

	payload := ManagedNetwork{
		Name:                managedNetworkIntegrationName,
		BridgeMode:          managedNetworkBridgeModeExisting,
		Bridge:              topology.BridgeIF,
		UplinkInterface:     topology.UplinkHostIF,
		IPv4Enabled:         true,
		IPv4CIDR:            managedNetworkIntegrationIPv4CIDR,
		IPv4PoolStart:       managedNetworkIntegrationIPv4PoolStart,
		IPv4PoolEnd:         managedNetworkIntegrationIPv4PoolEnd,
		IPv4DNSServers:      "1.1.1.1",
		IPv6Enabled:         true,
		IPv6ParentInterface: topology.UplinkHostIF,
		IPv6ParentPrefix:    strings.TrimSpace(ipv6ParentPrefix),
		IPv6AssignmentMode:  normalizeManagedNetworkIPv6AssignmentMode(ipv6AssignmentMode),
		AutoEgressNAT:       true,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal managed network payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/managed-networks", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create managed network request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create managed network: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create managed network unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var item ManagedNetwork
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode create managed network response: %v", err)
	}
	return item
}

func createManagedNetworkIntegrationReservation(t *testing.T, apiBase string, networkID int64, macAddress string, ipv4Address string) {
	t.Helper()

	payload := ManagedNetworkReservation{
		ManagedNetworkID: networkID,
		MACAddress:       macAddress,
		IPv4Address:      ipv4Address,
		Remark:           "integration",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal managed network reservation payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/managed-network-reservations", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create managed network reservation request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create managed network reservation: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create managed network reservation unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func waitForManagedNetworkIntegrationPreview(t *testing.T, apiBase string, networkID int64, topology egressNATIntegrationTopology) ManagedNetworkStatus {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/managed-networks", nil)
		if err != nil {
			t.Fatalf("build list managed networks request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var items []ManagedNetworkStatus
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		for _, item := range items {
			if item.ID != networkID {
				continue
			}
			if item.ChildInterfaceCount == 1 &&
				len(item.ChildInterfaces) == 1 &&
				item.ChildInterfaces[0] == topology.ChildHostIF &&
				item.GeneratedIPv6AssignmentCount == 1 &&
				item.GeneratedEgressNAT &&
				item.ReservationCount == 1 {
				return item
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("managed network #%d preview did not become ready in time", networkID)
	return ManagedNetworkStatus{}
}

func waitForManagedNetworkIntegrationReady(t *testing.T, apiBase string, networkID int64, topology egressNATIntegrationTopology) ManagedNetworkStatus {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var last ManagedNetworkStatus
	found := false
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/managed-networks", nil)
		if err != nil {
			t.Fatalf("build list managed networks request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var items []ManagedNetworkStatus
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		for _, item := range items {
			if item.ID != networkID {
				continue
			}
			if item.ChildInterfaceCount != 1 ||
				len(item.ChildInterfaces) != 1 ||
				item.ChildInterfaces[0] != topology.ChildHostIF ||
				item.GeneratedIPv6AssignmentCount != 1 ||
				!item.GeneratedEgressNAT ||
				item.ReservationCount != 1 {
				continue
			}
			last = item
			found = true
			if strings.TrimSpace(item.IPv4RuntimeStatus) == "running" &&
				strings.TrimSpace(item.IPv6RuntimeStatus) == "running" {
				return item
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if found {
		t.Fatalf("managed network #%d runtime did not become ready in time (ipv4=%q detail=%q ipv6=%q detail=%q)", networkID, last.IPv4RuntimeStatus, last.IPv4RuntimeDetail, last.IPv6RuntimeStatus, last.IPv6RuntimeDetail)
	}
	t.Fatalf("managed network #%d runtime did not appear in time", networkID)
	return ManagedNetworkStatus{}
}

func prepareManagedNetworkIntegrationClientNamespace(t *testing.T, topology egressNATIntegrationTopology) {
	t.Helper()

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "-4", "addr", "flush", "dev", topology.ClientNSIF, "scope", "global")
	runDataplanePerfCmd("ip", "netns", "exec", topology.ClientNS, "ip", "-4", "route", "del", "default")
}

func runManagedNetworkDHCPv4Client(t *testing.T, topology egressNATIntegrationTopology, expectedIPv4 string, expectedCIDR string, gateway string) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	captures := startManagedNetworkDHCPv4PacketCaptures(t, topology)
	defer stopEgressNATPacketCaptures(captures)

	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestManagedNetworkIntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		managedNetworkIntegrationHelperEnv+"=1",
		managedNetworkIntegrationHelperRoleEnv+"="+managedNetworkIntegrationHelperRoleDHCPv4,
		managedNetworkIntegrationHelperIfaceEnv+"="+topology.ClientNSIF,
		managedNetworkIntegrationHelperExpectedIPv4Env+"="+expectedIPv4,
		managedNetworkIntegrationHelperExpectedCIDREnv+"="+expectedCIDR,
		managedNetworkIntegrationHelperGatewayEnv+"="+gateway,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logManagedNetworkIntegrationStateOnFailure(t, dataplanePerfTopology{
			ClientNS:      topology.ClientNS,
			BackendNS:     topology.BackendNS,
			ClientHostIF:  topology.ChildHostIF,
			ClientNSIF:    topology.ClientNSIF,
			BackendHostIF: topology.UplinkHostIF,
			BackendNSIF:   topology.BackendNSIF,
		})
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("managed network dhcpv4 helper timed out\n%s\npacket capture:\n%s", string(output), stopAndCollectEgressNATPacketCaptures(captures))
		}
		return fmt.Errorf("managed network dhcpv4 helper failed: %w\n%s\npacket capture:\n%s", err, string(output), stopAndCollectEgressNATPacketCaptures(captures))
	}
	return nil
}

func startManagedNetworkDHCPv4PacketCaptures(t *testing.T, topology egressNATIntegrationTopology) []*egressNATPacketCapture {
	t.Helper()

	if _, err := exec.LookPath("tcpdump"); err != nil {
		return nil
	}

	captures := []*egressNATPacketCapture{
		startManagedNetworkDHCPv4PacketCapture(t, "host "+topology.BridgeIF, "", topology.BridgeIF),
		startManagedNetworkDHCPv4PacketCapture(t, "host "+topology.ChildHostIF, "", topology.ChildHostIF),
		startManagedNetworkDHCPv4PacketCapture(t, "netns "+topology.ClientNS+"/"+topology.ClientNSIF, topology.ClientNS, topology.ClientNSIF),
	}
	anyStarted := false
	for _, capture := range captures {
		if capture != nil {
			anyStarted = true
			break
		}
	}
	if anyStarted {
		time.Sleep(300 * time.Millisecond)
	}
	return captures
}

func startManagedNetworkDHCPv4PacketCapture(t *testing.T, label string, namespace string, ifName string) *egressNATPacketCapture {
	t.Helper()

	if strings.TrimSpace(ifName) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	args := []string{"tcpdump", "-l", "-nn", "-e", "-vvv", "-c", "12", "-i", ifName}
	args = append(args, managedNetworkDHCPv4PacketCaptureFilter()...)

	var cmd *exec.Cmd
	if strings.TrimSpace(namespace) == "" {
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	} else {
		nsArgs := append([]string{"netns", "exec", namespace}, args...)
		cmd = exec.CommandContext(ctx, "ip", nsArgs...)
	}

	capture := &egressNATPacketCapture{
		Label:  label,
		cancel: cancel,
		cmd:    cmd,
	}
	cmd.Stdout = &capture.output
	cmd.Stderr = &capture.output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Logf("start dhcp packet capture %s failed: %v", label, err)
		return nil
	}
	return capture
}

func managedNetworkDHCPv4PacketCaptureFilter() []string {
	return []string{"udp", "and", "(", "port", "67", "or", "port", "68", ")"}
}

func performManagedNetworkDHCPv4Handshake(iface net.Interface, expectedIP net.IP, timeout time.Duration) (net.IP, error) {
	conn, err := openManagedNetworkDHCPv4ClientConn(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("listen dhcpv4 client socket: %w", err)
	}
	defer conn.Close()

	clientID := append([]byte{dhcpv4HWTypeEthernet}, append([]byte(nil), iface.HardwareAddr...)...)
	xid := uint32(time.Now().UnixNano())
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		discover := buildManagedNetworkDHCPv4ClientPacket(xid, iface.HardwareAddr, dhcpv4MessageDiscover, nil, nil, clientID)
		if _, err := conn.WriteToUDP(discover, &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4ServerPort}); err != nil {
			return nil, fmt.Errorf("send dhcpv4 discover: %w", err)
		}

		offer, err := waitForManagedNetworkDHCPv4Response(conn, xid, iface.HardwareAddr, 2*time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return nil, err
		}
		if offer.MessageType != dhcpv4MessageOffer {
			continue
		}
		leaseIP := offer.YIAddr.To4()
		if leaseIP == nil {
			continue
		}
		if expected := expectedIP.To4(); expected != nil && !leaseIP.Equal(expected) {
			return nil, fmt.Errorf("dhcpv4 offer = %s, want %s", leaseIP, expected)
		}

		request := buildManagedNetworkDHCPv4ClientPacket(xid, iface.HardwareAddr, dhcpv4MessageRequest, leaseIP, offer.ServerID, clientID)
		if _, err := conn.WriteToUDP(request, &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4ServerPort}); err != nil {
			return nil, fmt.Errorf("send dhcpv4 request: %w", err)
		}

		for {
			reply, err := waitForManagedNetworkDHCPv4Response(conn, xid, iface.HardwareAddr, 2*time.Second)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return nil, err
			}
			switch reply.MessageType {
			case dhcpv4MessageAck:
				if ip := reply.YIAddr.To4(); ip != nil {
					return ip, nil
				}
			case dhcpv4MessageNak:
				return nil, fmt.Errorf("dhcpv4 server returned nak")
			}
		}
	}

	return nil, fmt.Errorf("timed out waiting for dhcpv4 lease on %s", iface.Name)
}

type managedNetworkDHCPv4ClientConn struct {
	send *net.UDPConn
	recv int
}

func (conn *managedNetworkDHCPv4ClientConn) Close() error {
	if conn == nil {
		return nil
	}
	var firstErr error
	if conn.send != nil {
		if err := conn.send.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if conn.recv >= 0 {
		if err := unix.Close(conn.recv); err != nil && firstErr == nil {
			firstErr = err
		}
		conn.recv = -1
	}
	return firstErr
}

func (conn *managedNetworkDHCPv4ClientConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if conn == nil || conn.send == nil {
		return 0, fmt.Errorf("dhcpv4 client sender unavailable")
	}
	return conn.send.WriteToUDP(b, addr)
}

func openManagedNetworkDHCPv4ClientConn(ifaceName string) (*managedNetworkDHCPv4ClientConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(fd uintptr) {
				if controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); controlErr != nil {
					return
				}
				if controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1); controlErr != nil {
					return
				}
				controlErr = unix.BindToDevice(int(fd), ifaceName)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4", ":68")
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("unexpected dhcpv4 packet conn type %T", pc)
	}
	_, recvFD, err := openPacketListenerSocket(ifaceName, 2*time.Second, buildManagedNetworkDHCPv4ClientSocketFilter())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &managedNetworkDHCPv4ClientConn{
		send: conn,
		recv: recvFD,
	}, nil
}

type managedNetworkDHCPv4TimeoutError struct{}

func (managedNetworkDHCPv4TimeoutError) Error() string   { return "i/o timeout" }
func (managedNetworkDHCPv4TimeoutError) Timeout() bool   { return true }
func (managedNetworkDHCPv4TimeoutError) Temporary() bool { return true }

func waitForManagedNetworkDHCPv4Response(conn *managedNetworkDHCPv4ClientConn, xid uint32, hwAddr net.HardwareAddr, timeout time.Duration) (parsedManagedNetworkDHCPv4Message, error) {
	if conn == nil || conn.recv < 0 {
		return parsedManagedNetworkDHCPv4Message{}, fmt.Errorf("dhcpv4 client receiver unavailable")
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(conn.recv, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return parsedManagedNetworkDHCPv4Message{}, err
	}
	for {
		frame, err := readManagedNetworkDHCPv4ClientFrame(conn.recv)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return parsedManagedNetworkDHCPv4Message{}, managedNetworkDHCPv4TimeoutError{}
			}
			return parsedManagedNetworkDHCPv4Message{}, err
		}
		msg, err := parseManagedNetworkDHCPv4Message(frame.Payload)
		if err != nil {
			continue
		}
		if msg.Op != dhcpv4BootReply {
			continue
		}
		if msg.XID != xid {
			continue
		}
		if len(msg.CHAddr) < 6 || len(hwAddr) < 6 || !bytes.Equal(msg.CHAddr[:6], hwAddr[:6]) {
			continue
		}
		return msg, nil
	}
}

func readManagedNetworkDHCPv4ClientFrame(fd int) (managedNetworkDHCPv4Frame, error) {
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return managedNetworkDHCPv4Frame{}, err
		}
		frame, ok := parseManagedNetworkDHCPv4ClientFrame(buf[:n])
		if ok {
			return frame, nil
		}
	}
}

func parseManagedNetworkDHCPv4ClientFrame(frame []byte) (managedNetworkDHCPv4Frame, bool) {
	if len(frame) < 14+20+8+240 {
		return managedNetworkDHCPv4Frame{}, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return managedNetworkDHCPv4Frame{}, false
	}
	ipHeader := frame[14:]
	if version := ipHeader[0] >> 4; version != 4 {
		return managedNetworkDHCPv4Frame{}, false
	}
	ihl := int(ipHeader[0]&0x0f) * 4
	if ihl < 20 || len(ipHeader) < ihl+8 {
		return managedNetworkDHCPv4Frame{}, false
	}
	if ipHeader[9] != ipv4ProtocolUDP {
		return managedNetworkDHCPv4Frame{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(ipHeader[2:4]))
	if totalLen < ihl+8 || totalLen > len(ipHeader) {
		return managedNetworkDHCPv4Frame{}, false
	}
	udp := ipHeader[ihl:totalLen]
	if binary.BigEndian.Uint16(udp[0:2]) != dhcpv4ServerPort || binary.BigEndian.Uint16(udp[2:4]) != dhcpv4ClientPort {
		return managedNetworkDHCPv4Frame{}, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return managedNetworkDHCPv4Frame{}, false
	}
	srcIP := net.IP(append([]byte(nil), ipHeader[12:16]...))
	dstIP := net.IP(append([]byte(nil), ipHeader[16:20]...))
	return managedNetworkDHCPv4Frame{
		SrcMAC:  append(net.HardwareAddr(nil), frame[6:12]...),
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Payload: append([]byte(nil), udp[8:udpLen]...),
	}, true
}

func buildManagedNetworkDHCPv4ClientSocketFilter() []bpf.Instruction {
	return buildPacketSocketEqualityFilter([]packetSocketEqualityCheck{
		{Offset: packetSocketEtherTypeOffset, Size: 2, Value: 0x0800},
		{Offset: packetSocketIPv4ProtocolOffset, Size: 1, Value: ipv4ProtocolUDP},
		{Offset: packetSocketIPv4UDPSourcePortOffset, Size: 2, Value: dhcpv4ServerPort},
		{Offset: packetSocketIPv4UDPDestPortOffset, Size: 2, Value: dhcpv4ClientPort},
	})
}

func buildManagedNetworkDHCPv4ClientPacket(xid uint32, hwAddr net.HardwareAddr, messageType byte, requestedIP net.IP, serverID net.IP, clientID []byte) []byte {
	out := make([]byte, 240)
	out[0] = 1
	out[1] = dhcpv4HWTypeEthernet
	out[2] = 6
	out[3] = 0
	binaryBigEndianPutUint32(out[4:8], xid)
	binaryBigEndianPutUint16(out[10:12], 0x8000)
	copy(out[28:34], hwAddr)
	binaryBigEndianPutUint32(out[236:240], dhcpv4MagicCookie)
	out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionMessageType, []byte{messageType})...)
	if len(clientID) > 0 {
		out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionClientID, clientID)...)
	}
	if ip := requestedIP.To4(); ip != nil && !ip.Equal(net.IPv4zero) {
		out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionRequestedIP, ip)...)
	}
	if ip := serverID.To4(); ip != nil && !ip.Equal(net.IPv4zero) {
		out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionServerID, ip)...)
	}
	out = append(out, dhcpv4OptionEnd)
	if len(out) < dhcpv4MinMessageSize {
		out = append(out, make([]byte, dhcpv4MinMessageSize-len(out))...)
	}
	return out
}

func ensureManagedNetworkIntegrationIPv4Address(ifaceName string, cidr string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	ip, prefix, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || prefix == nil || ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid ipv4 cidr %q", cidr)
	}
	return netlink.AddrReplace(link, &netlink.Addr{
		IPNet: &net.IPNet{IP: ip.To4(), Mask: prefix.Mask},
	})
}

func removeManagedNetworkIntegrationIPv4Address(ifaceName string, cidr string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	ip, prefix, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || prefix == nil || ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid ipv4 cidr %q", cidr)
	}
	if err := netlink.AddrDel(link, &netlink.Addr{
		IPNet: &net.IPNet{IP: ip.To4(), Mask: prefix.Mask},
	}); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func waitForManagedNetworkIntegrationIPv4Address(ifaceName string, cidr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		present, err := managedNetworkIntegrationHasIPv4Address(ifaceName, cidr)
		if err == nil && present {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for ipv4 address %s on %s", cidr, ifaceName)
}

func mustEnsureManagedNetworkIntegrationIPv6AddressAbsentInNamespace(t *testing.T, namespace string, ifaceName string, address string, timeout time.Duration) {
	t.Helper()

	cidr := strings.TrimSpace(address) + "/128"
	if err := removeIPv6AssignmentAddressInNamespace(namespace, ifaceName, cidr); err != nil {
		t.Fatalf("remove ipv6 address %s from %s in %s: %v", cidr, ifaceName, namespace, err)
	}
	if err := waitForManagedNetworkIntegrationIPv6AddressAbsentInNamespace(namespace, ifaceName, address, timeout); err != nil {
		t.Fatal(err)
	}
}

func waitForManagedNetworkIntegrationIPv6AddressAbsentInNamespace(namespace string, ifaceName string, address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		present, err := managedNetworkIntegrationHasIPv6AddressInNamespace(namespace, ifaceName, address)
		if err == nil && !present {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for ipv6 address %s to disappear from %s in %s", address, ifaceName, namespace)
}

func managedNetworkIntegrationHasIPv4Address(ifaceName string, cidr string) (bool, error) {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return false, err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return false, fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	ip, prefix, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || prefix == nil || ip == nil || ip.To4() == nil {
		return false, fmt.Errorf("invalid ipv4 cidr %q", cidr)
	}
	want := (&net.IPNet{IP: ip.To4(), Mask: prefix.Mask}).String()
	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if addr.IPNet == nil || addr.IPNet.IP == nil || addr.IPNet.IP.To4() == nil {
			continue
		}
		if (&net.IPNet{IP: addr.IPNet.IP.To4(), Mask: addr.IPNet.Mask}).String() == want {
			return true, nil
		}
	}
	return false, nil
}

func managedNetworkIntegrationHasIPv6AddressInNamespace(namespace string, ifaceName string, address string) (bool, error) {
	handle, err := openIPv6AssignmentNetnsHandle(namespace)
	if err != nil {
		return false, err
	}
	defer handle.Close()

	link, err := handle.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return false, err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return false, fmt.Errorf("interface %q is unavailable", ifaceName)
	}

	want := parseIPLiteral(address)
	if want == nil || want.To4() != nil {
		return false, fmt.Errorf("invalid ipv6 address %q", address)
	}
	wantText := canonicalIPLiteral(want.To16())

	addrs, err := handle.AddrList(link, unix.AF_INET6)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil && addr.IPNet != nil {
			ip = addr.IPNet.IP
		}
		ip = ip.To16()
		if ip == nil || ip.To4() != nil {
			continue
		}
		if canonicalIPLiteral(ip) == wantText {
			return true, nil
		}
	}
	return false, nil
}

func ensureManagedNetworkIntegrationIPv4DefaultRoute(ifaceName string, gateway string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	gw := parseIPLiteral(gateway)
	if gw == nil || gw.To4() == nil {
		return fmt.Errorf("invalid ipv4 gateway %q", gateway)
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: attrs.Index,
		Gw:        gw.To4(),
		Family:    unix.AF_INET,
		Protocol:  unix.RTPROT_STATIC,
	})
}

func mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t *testing.T, namespace string, ifaceName string, cidr string) {
	t.Helper()
	if err := ensureManagedNetworkIntegrationIPv6AddressInNamespace(namespace, ifaceName, cidr); err != nil {
		t.Fatalf("configure ipv6 address %s on %s/%s: %v", cidr, namespace, ifaceName, err)
	}
}

func ensureManagedNetworkIntegrationIPv6AddressInNamespace(namespace string, ifaceName string, cidr string) error {
	handle, err := openIPv6AssignmentNetnsHandle(namespace)
	if err != nil {
		return err
	}
	defer handle.Delete()

	link, err := handle.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	ip, prefix, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || prefix == nil || ip == nil || ip.To4() != nil {
		return fmt.Errorf("invalid ipv6 cidr %q", cidr)
	}
	return handle.AddrReplace(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip.To16(),
			Mask: append(net.IPMask(nil), prefix.Mask...),
		},
		Flags: unix.IFA_F_NODAD,
	})
}

func mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t *testing.T, namespace string, ifaceName string, gateway string) {
	t.Helper()
	if err := ensureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(namespace, ifaceName, gateway); err != nil {
		t.Fatalf("configure ipv6 default route via %s on %s/%s: %v", gateway, namespace, ifaceName, err)
	}
}

func ensureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(namespace string, ifaceName string, gateway string) error {
	handle, err := openIPv6AssignmentNetnsHandle(namespace)
	if err != nil {
		return err
	}
	defer handle.Delete()

	link, err := handle.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	gw := parseIPLiteral(gateway)
	if gw == nil || gw.To4() != nil {
		return fmt.Errorf("invalid ipv6 gateway %q", gateway)
	}
	return handle.RouteReplace(&netlink.Route{
		LinkIndex: attrs.Index,
		Gw:        gw.To16(),
		Family:    unix.AF_INET6,
		Protocol:  unix.RTPROT_STATIC,
	})
}

func logManagedNetworkIntegrationStateOnFailure(t *testing.T, topology dataplanePerfTopology) {
	t.Helper()

	logIPv6AssignmentIntegrationStateOnFailure(t, topology)

	run := func(label string, name string, args ...string) {
		cmd := exec.Command(name, args...)
		output, err := cmd.CombinedOutput()
		text := strings.TrimSpace(string(output))
		if err != nil {
			if text == "" {
				text = err.Error()
			} else {
				text = text + "\nerror: " + err.Error()
			}
		}
		if text == "" {
			text = "(empty)"
		}
		t.Logf("%s:\n%s", label, text)
	}

	run("host ip -4 addr", "ip", "-4", "addr", "show")
	run("host ip -4 route", "ip", "-4", "route", "show")
	run("client ip -4 addr", "ip", "netns", "exec", topology.ClientNS, "ip", "-4", "addr", "show")
	run("client ip -4 route", "ip", "netns", "exec", topology.ClientNS, "ip", "-4", "route", "show")
	run("backend ip -4 addr", "ip", "netns", "exec", topology.BackendNS, "ip", "-4", "addr", "show")
	run("backend ip -4 route", "ip", "netns", "exec", topology.BackendNS, "ip", "-4", "route", "show")
}

func binaryBigEndianPutUint16(buf []byte, value uint16) {
	_ = buf[1]
	buf[0] = byte(value >> 8)
	buf[1] = byte(value)
}

func binaryBigEndianPutUint32(buf []byte, value uint32) {
	_ = buf[3]
	buf[0] = byte(value >> 24)
	buf[1] = byte(value >> 16)
	buf[2] = byte(value >> 8)
	buf[3] = byte(value)
}
