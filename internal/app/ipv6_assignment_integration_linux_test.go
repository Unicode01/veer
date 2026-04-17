//go:build linux

package app

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the integration test as root:
//      FORWARD_RUN_IPV6_ASSIGNMENT_TEST=1 go test ./internal/app -run TestIPv6AssignmentManagedAddressIntegration -count=1 -v

const (
	ipv6AssignmentIntegrationEnableEnv             = "FORWARD_RUN_IPV6_ASSIGNMENT_TEST"
	ipv6AssignmentIntegrationHelperEnv             = "FORWARD_IPV6_ASSIGNMENT_HELPER"
	ipv6AssignmentIntegrationHelperRoleEnv         = "FORWARD_IPV6_ASSIGNMENT_HELPER_ROLE"
	ipv6AssignmentIntegrationHelperIfaceEnv        = "FORWARD_IPV6_ASSIGNMENT_HELPER_IFACE"
	ipv6AssignmentIntegrationHelperExpectedAddrEnv = "FORWARD_IPV6_ASSIGNMENT_HELPER_EXPECTED_ADDR"
	ipv6AssignmentIntegrationHelperExpectedPrefEnv = "FORWARD_IPV6_ASSIGNMENT_HELPER_EXPECTED_PREFIX"
	ipv6AssignmentIntegrationHelperTargetEnv       = "FORWARD_IPV6_ASSIGNMENT_HELPER_TARGET"
	ipv6AssignmentIntegrationHelperListenEnv       = "FORWARD_IPV6_ASSIGNMENT_HELPER_LISTEN"
	ipv6AssignmentIntegrationHelperParentAddrEnv   = "FORWARD_IPV6_ASSIGNMENT_HELPER_PARENT_ADDR"
	ipv6AssignmentIntegrationHelperBackendAddrEnv  = "FORWARD_IPV6_ASSIGNMENT_HELPER_BACKEND_ADDR"
	ipv6AssignmentIntegrationHelperRemoteAddrEnv   = "FORWARD_IPV6_ASSIGNMENT_HELPER_REMOTE_ADDR"
	ipv6AssignmentIntegrationReadyLine             = "READY"
	ipv6AssignmentIntegrationParentPrefix          = "2001:db8:100::/64"
	ipv6AssignmentIntegrationParentAddr            = "2001:db8:100::1"
	ipv6AssignmentIntegrationBackendAddr           = "2001:db8:100::2"
	ipv6AssignmentIntegrationBackendPort           = 2089
	ipv6AssignmentIntegrationAssignedPrefix        = "2001:db8:100::1234/128"
	ipv6AssignmentIntegrationAssignedAddr          = "2001:db8:100::1234"
	ipv6AssignmentIntegrationRotatedParentPrefix   = "2001:db8:200::/64"
	ipv6AssignmentIntegrationRotatedParentAddr     = "2001:db8:200::1"
	ipv6AssignmentIntegrationRotatedBackendAddr    = "2001:db8:200::2"
	ipv6AssignmentIntegrationRotatedAssignedPrefix = "2001:db8:200::1234/128"
	ipv6AssignmentIntegrationRotatedAssignedAddr   = "2001:db8:200::1234"
)

type ipv6AssignmentIntegrationHelperHandle struct {
	cmd      *exec.Cmd
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	scanDone <-chan struct{}
}

type parsedIPv6AssignmentDHCPv6Response struct {
	Type      byte
	TxID      [3]byte
	ServerID  []byte
	Addresses []net.IP
}

func TestIPv6AssignmentIntegrationHelperProcess(t *testing.T) {
	if os.Getenv(ipv6AssignmentIntegrationHelperEnv) != "1" {
		return
	}
	var err error
	switch strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperRoleEnv)) {
	case "", "client":
		err = runIPv6AssignmentIntegrationHelper()
	case "client-slaac":
		err = runIPv6AssignmentSLAACIntegrationHelper()
	case "backend":
		err = runIPv6AssignmentIntegrationBackendHelper()
	default:
		err = fmt.Errorf("unknown ipv6 assignment helper role %q", os.Getenv(ipv6AssignmentIntegrationHelperRoleEnv))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestIPv6AssignmentManagedAddressIntegration(t *testing.T) {
	if os.Getenv(ipv6AssignmentIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux IPv6 assignment integration test", ipv6AssignmentIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required for Linux network namespace test scaffolding")
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	baseBinary := buildDataplanePerfBinary(t, repoRoot)

	topology := setupDataplanePerfTopology(t)
	runtimeDir := makeShortIPv6AssignmentIntegrationDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:     "ipv6-assignment",
		Default:  ruleEngineUserspace,
		Expected: ruleEngineUserspace,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-ipv6-assignment.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create forward log file: %v", err)
	}
	defer logFile.Close()

	cmd := exec.Command(forwardBinary, "--config", configPath)
	cmd.Dir = workDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer stopForwardProcessTree(t, cmd)

	apiBase := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	waitForDataplanePerfAPI(t, apiBase)

	mustEnsureIPv6AssignmentAddress(t, topology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	seedIPv6AssignmentIntegrationBackendNeighbors(t, topology)
	backendHelper := startIPv6AssignmentIntegrationBackendHelper(t, topology)
	defer stopIPv6AssignmentIntegrationHelper(t, backendHelper)

	helper := startIPv6AssignmentIntegrationHelper(t, topology, net.JoinHostPort(ipv6AssignmentIntegrationBackendAddr, fmt.Sprintf("%d", ipv6AssignmentIntegrationBackendPort)))
	if err := createIPv6AssignmentIntegration(apiBase, topology); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRoute(topology); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(helper, 20*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(backendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
}

func TestIPv6AssignmentManagedAddressIntegrationReacquiresAfterForwardRestart(t *testing.T) {
	if os.Getenv(ipv6AssignmentIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux IPv6 assignment integration test", ipv6AssignmentIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required for Linux network namespace test scaffolding")
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	baseBinary := buildDataplanePerfBinary(t, repoRoot)

	topology := setupDataplanePerfTopology(t)
	runtimeDir := makeShortIPv6AssignmentIntegrationDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-restart-renew")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:     "ipv6-assignment-restart-renew",
		Default:  ruleEngineUserspace,
		Expected: ruleEngineUserspace,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-ipv6-assignment-restart-renew.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create forward log file: %v", err)
	}
	defer logFile.Close()

	cmd := exec.Command(forwardBinary, "--config", configPath)
	cmd.Dir = workDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer stopForwardProcessTree(t, cmd)

	apiBase := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	waitForDataplanePerfAPI(t, apiBase)

	mustEnsureIPv6AssignmentAddress(t, topology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	seedIPv6AssignmentIntegrationBackendNeighbors(t, topology)

	if err := createIPv6AssignmentIntegration(apiBase, topology); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRoute(topology); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}

	initialBackendHelper := startIPv6AssignmentIntegrationBackendHelper(t, topology)
	defer stopIPv6AssignmentIntegrationHelper(t, initialBackendHelper)
	initialHelper := startIPv6AssignmentIntegrationHelper(t, topology, net.JoinHostPort(ipv6AssignmentIntegrationBackendAddr, fmt.Sprintf("%d", ipv6AssignmentIntegrationBackendPort)))
	if err := waitForIPv6AssignmentIntegrationHelper(initialHelper, 20*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(initialBackendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}

	restartIPv6AssignmentIntegrationForward(t, cmd, forwardBinary, workDir, configPath, apiBase, logPath)

	seedIPv6AssignmentIntegrationBackendNeighbors(t, topology)
	if err := waitForIPv6AssignmentRoute(topology); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := removeIPv6AssignmentAddressInNamespace(topology.ClientNS, topology.ClientNSIF, ipv6AssignmentIntegrationAssignedAddr+"/128"); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatalf("remove client assigned ipv6 before restart reacquire: %v", err)
	}

	restartedBackendHelper := startIPv6AssignmentIntegrationBackendHelper(t, topology)
	defer stopIPv6AssignmentIntegrationHelper(t, restartedBackendHelper)
	restartedHelper := startIPv6AssignmentIntegrationHelper(t, topology, net.JoinHostPort(ipv6AssignmentIntegrationBackendAddr, fmt.Sprintf("%d", ipv6AssignmentIntegrationBackendPort)))
	if err := waitForIPv6AssignmentIntegrationHelper(restartedHelper, 20*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(restartedBackendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
}

func TestIPv6AssignmentManagedAddressIntegrationFollowsParentPrefixChange(t *testing.T) {
	if os.Getenv(ipv6AssignmentIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux IPv6 assignment integration test", ipv6AssignmentIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required for Linux network namespace test scaffolding")
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	baseBinary := buildDataplanePerfBinary(t, repoRoot)

	topology := setupDataplanePerfTopology(t)
	runtimeDir := makeShortIPv6AssignmentIntegrationDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-prefix-rotate")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:     "ipv6-assignment-prefix-rotate",
		Default:  ruleEngineUserspace,
		Expected: ruleEngineUserspace,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-ipv6-assignment-prefix-rotate.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create forward log file: %v", err)
	}
	defer logFile.Close()

	cmd := exec.Command(forwardBinary, "--config", configPath)
	cmd.Dir = workDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer stopForwardProcessTree(t, cmd)

	apiBase := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	waitForDataplanePerfAPI(t, apiBase)

	mustEnsureIPv6AssignmentAddress(t, topology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	seedIPv6AssignmentIntegrationBackendNeighborsForAddresses(t, topology, ipv6AssignmentIntegrationParentAddr, ipv6AssignmentIntegrationBackendAddr)

	if err := createIPv6AssignmentIntegration(apiBase, topology); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(topology, ipv6AssignmentIntegrationAssignedPrefix); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}

	initialBackendHelper := startIPv6AssignmentIntegrationBackendHelperWithAddrs(
		t,
		topology,
		ipv6AssignmentIntegrationBackendAddr,
		ipv6AssignmentIntegrationParentAddr,
		ipv6AssignmentIntegrationAssignedAddr,
	)
	defer stopIPv6AssignmentIntegrationHelper(t, initialBackendHelper)
	initialHelper := startIPv6AssignmentIntegrationHelperWithExpectedAddr(
		t,
		topology,
		ipv6AssignmentIntegrationAssignedAddr,
		net.JoinHostPort(ipv6AssignmentIntegrationBackendAddr, fmt.Sprintf("%d", ipv6AssignmentIntegrationBackendPort)),
	)
	if err := waitForIPv6AssignmentIntegrationHelper(initialHelper, 20*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(initialBackendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}

	if err := removeIPv6AssignmentAddress(topology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64"); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatalf("remove old parent prefix: %v", err)
	}
	if err := removeIPv6AssignmentAddressInNamespace(topology.BackendNS, topology.BackendNSIF, ipv6AssignmentIntegrationBackendAddr+"/64"); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatalf("remove old backend address: %v", err)
	}
	if err := ensureIPv6AssignmentAddress(topology.BackendHostIF, ipv6AssignmentIntegrationRotatedParentAddr+"/64"); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatalf("install rotated parent prefix: %v", err)
	}
	seedIPv6AssignmentIntegrationBackendNeighborsForAddresses(t, topology, ipv6AssignmentIntegrationRotatedParentAddr, ipv6AssignmentIntegrationRotatedBackendAddr)

	if err := waitForIPv6AssignmentRouteForPrefix(topology, ipv6AssignmentIntegrationRotatedAssignedPrefix); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := removeIPv6AssignmentAddressInNamespace(topology.ClientNS, topology.ClientNSIF, ipv6AssignmentIntegrationAssignedAddr+"/128"); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatalf("remove old client assigned ipv6 before rotated reacquire: %v", err)
	}

	rotatedBackendHelper := startIPv6AssignmentIntegrationBackendHelperWithAddrs(
		t,
		topology,
		ipv6AssignmentIntegrationRotatedBackendAddr,
		ipv6AssignmentIntegrationRotatedParentAddr,
		ipv6AssignmentIntegrationRotatedAssignedAddr,
	)
	defer stopIPv6AssignmentIntegrationHelper(t, rotatedBackendHelper)
	rotatedHelper := startIPv6AssignmentIntegrationHelperWithExpectedAddr(
		t,
		topology,
		ipv6AssignmentIntegrationRotatedAssignedAddr,
		net.JoinHostPort(ipv6AssignmentIntegrationRotatedBackendAddr, fmt.Sprintf("%d", ipv6AssignmentIntegrationBackendPort)),
	)
	if err := waitForIPv6AssignmentIntegrationHelper(rotatedHelper, 25*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentIntegrationHelper(rotatedBackendHelper, 5*time.Second); err != nil {
		logForwardLogOnFailure(t, logPath)
		logIPv6AssignmentIntegrationStateOnFailure(t, topology)
		t.Fatal(err)
	}
}

func runIPv6AssignmentIntegrationHelper() error {
	ifaceName := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperIfaceEnv))
	expectedAddr := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperExpectedAddrEnv))
	target := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperTargetEnv))
	if ifaceName == "" {
		return errors.New("missing helper interface name")
	}
	if expectedAddr == "" {
		return errors.New("missing helper expected address")
	}
	if target == "" {
		return errors.New("missing helper tcp probe target")
	}
	expectedIP := parseIPLiteral(expectedAddr)
	if expectedIP == nil || expectedIP.To4() != nil {
		return fmt.Errorf("invalid expected IPv6 address %q", expectedAddr)
	}

	iface, srcIP, err := waitForIPv6AssignmentLinkLocal(ifaceName, 10*time.Second)
	if err != nil {
		return err
	}
	if err := ensureIPv6AddressAbsent(ifaceName, expectedAddr); err != nil {
		return err
	}

	dhcpConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: dhcpv6ClientPort})
	if err != nil {
		return fmt.Errorf("listen dhcpv6 client socket: %w", err)
	}
	defer dhcpConn.Close()

	icmpConn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("listen icmpv6 socket: %w", err)
	}
	defer icmpConn.Close()
	icmpPacketConn := icmpConn.IPv6PacketConn()
	if err := icmpPacketConn.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		return fmt.Errorf("enable icmpv6 control messages: %w", err)
	}

	fmt.Println(ipv6AssignmentIntegrationReadyLine)

	if err := sendIPv6AssignmentRouterSolicitation(*iface, srcIP); err != nil {
		return fmt.Errorf("send router solicitation: %w", err)
	}
	if err := waitForManagedIPv6RouterAdvertisement(icmpConn, icmpPacketConn, iface.Index, 15*time.Second); err != nil {
		return err
	}
	clientID := buildDHCPv6DUID(iface.HardwareAddr)
	iaid := [4]byte{0x46, 0x57, 0x36, 0x34}
	reply, err := performIPv6AssignmentDHCPv6Handshake(dhcpConn, *iface, srcIP, clientID, iaid, 15*time.Second)
	if err != nil {
		return err
	}
	found := false
	for _, addr := range reply.Addresses {
		if addr.Equal(expectedIP) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("dhcpv6 reply did not include %s (got %s)", expectedAddr, joinIPv6List(reply.Addresses))
	}
	if err := ensureIPv6AssignmentAddress(iface.Name, expectedAddr+"/128"); err != nil {
		return fmt.Errorf("install dhcpv6 address: %w", err)
	}
	if err := ensureIPv6AddressPresent(ifaceName, expectedAddr); err != nil {
		return err
	}
	if err := waitForIPv6RouteToTarget(ifaceName, target, 5*time.Second); err != nil {
		return err
	}
	return verifyIPv6AssignmentTCPConnectivity(target, expectedIP, 10*time.Second)
}

func runIPv6AssignmentSLAACIntegrationHelper() error {
	ifaceName := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperIfaceEnv))
	expectedPrefixText := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperExpectedPrefEnv))
	if ifaceName == "" {
		return errors.New("missing helper interface name")
	}
	if expectedPrefixText == "" {
		return errors.New("missing helper expected prefix")
	}

	iface, srcIP, err := waitForIPv6AssignmentLinkLocal(ifaceName, 10*time.Second)
	if err != nil {
		return err
	}
	expectedPrefix, err := parseIPv6AssignmentExpectedPrefix(expectedPrefixText)
	if err != nil {
		return err
	}
	if err := enableIPv6SLAACOnInterface(ifaceName); err != nil {
		return err
	}

	icmpConn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("listen icmpv6 socket: %w", err)
	}
	defer icmpConn.Close()
	icmpPacketConn := icmpConn.IPv6PacketConn()
	if err := icmpPacketConn.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		return fmt.Errorf("enable icmpv6 control messages: %w", err)
	}

	fmt.Println(ipv6AssignmentIntegrationReadyLine)

	if err := sendIPv6AssignmentRouterSolicitation(*iface, srcIP); err != nil {
		return fmt.Errorf("send router solicitation: %w", err)
	}
	if err := waitForIPv6RouterAdvertisementForPrefix(icmpConn, icmpPacketConn, iface.Index, expectedPrefix, 15*time.Second); err != nil {
		return err
	}
	if _, err := waitForIPv6AddressInPrefix(ifaceName, expectedPrefix, 20*time.Second); err != nil {
		return err
	}
	return nil
}

func restartIPv6AssignmentIntegrationForward(t *testing.T, cmd *exec.Cmd, forwardBinary string, workDir string, configPath string, apiBase string, logPath string) *exec.Cmd {
	t.Helper()

	stopForwardProcessTree(t, cmd)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open forward log file for restart: %v", err)
	}

	nextCmd := exec.Command(forwardBinary, "--config", configPath)
	nextCmd.Dir = workDir
	nextCmd.Stdout = logFile
	nextCmd.Stderr = logFile
	nextCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := nextCmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("restart forward: %v", err)
	}
	_ = logFile.Close()

	t.Cleanup(func() {
		stopForwardProcessTree(t, nextCmd)
	})
	waitForDataplanePerfAPI(t, apiBase)
	return nextCmd
}

func sendIPv6AssignmentRouterSolicitation(iface net.Interface, srcIP net.IP) error {
	if iface.Index <= 0 || strings.TrimSpace(iface.Name) == "" {
		return fmt.Errorf("interface %q is unavailable", iface.Name)
	}
	if len(iface.HardwareAddr) < 6 {
		return fmt.Errorf("interface %q has no usable ethernet address", iface.Name)
	}
	src := srcIP.To16()
	if src == nil || src.To4() != nil || !src.IsLinkLocalUnicast() {
		return fmt.Errorf("invalid router solicitation source %q", srcIP.String())
	}
	dst := net.ParseIP("ff02::2").To16()
	if dst == nil {
		return errors.New("router solicitation destination is unavailable")
	}

	body := make([]byte, 4)
	body = append(body, buildIPv6SourceLLAOption(iface.HardwareAddr)...)
	payload, err := (&icmp.Message{
		Type: ipv6.ICMPTypeRouterSolicitation,
		Code: 0,
		Body: &icmp.RawBody{Data: body},
	}).Marshal(icmp.IPv6PseudoHeader(src, dst))
	if err != nil {
		return fmt.Errorf("marshal router solicitation: %w", err)
	}

	frame := make([]byte, 14+40+len(payload))
	copy(frame[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x02})
	copy(frame[6:12], iface.HardwareAddr[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14 : 14+40]
	ipv6Header[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(len(payload)))
	ipv6Header[6] = 58
	ipv6Header[7] = ipv6RAHopLimit
	copy(ipv6Header[8:24], src)
	copy(ipv6Header[24:40], dst)
	copy(frame[14+40:], payload)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_IPV6)))
	if err != nil {
		return fmt.Errorf("open router solicitation packet socket: %w", err)
	}
	defer unix.Close(fd)

	var addr [8]byte
	copy(addr[:], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x02})
	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: htonsUnix(unix.ETH_P_IPV6),
		Halen:    6,
		Addr:     addr,
	}); err != nil {
		return fmt.Errorf("write router solicitation frame: %w", err)
	}
	return nil
}

func startIPv6AssignmentIntegrationHelper(t *testing.T, topology dataplanePerfTopology, target string) ipv6AssignmentIntegrationHelperHandle {
	return startIPv6AssignmentIntegrationHelperWithExpectedAddr(t, topology, ipv6AssignmentIntegrationAssignedAddr, target)
}

func startIPv6AssignmentIntegrationHelperWithExpectedAddr(t *testing.T, topology dataplanePerfTopology, expectedAddr string, target string) ipv6AssignmentIntegrationHelperHandle {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestIPv6AssignmentIntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		ipv6AssignmentIntegrationHelperEnv+"=1",
		ipv6AssignmentIntegrationHelperRoleEnv+"=client",
		ipv6AssignmentIntegrationHelperIfaceEnv+"="+topology.ClientNSIF,
		ipv6AssignmentIntegrationHelperExpectedAddrEnv+"="+strings.TrimSpace(expectedAddr),
		ipv6AssignmentIntegrationHelperTargetEnv+"="+target,
	)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout pipe: %v", err)
	}
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ipv6 assignment helper: %v", err)
	}

	ready := make(chan error, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)

		scanner := bufio.NewScanner(stdoutPipe)
		signaled := false
		for scanner.Scan() {
			line := scanner.Text()
			if !signaled && strings.TrimSpace(line) == ipv6AssignmentIntegrationReadyLine {
				signaled = true
				ready <- nil
				continue
			}
			stdoutBuf.WriteString(line)
			stdoutBuf.WriteByte('\n')
		}
		if signaled {
			return
		}
		if err := scanner.Err(); err != nil {
			ready <- err
			return
		}
		ready <- errors.New("ipv6 assignment helper exited before ready")
	}()

	select {
	case err := <-ready:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			<-scanDone
			t.Fatalf("ipv6 assignment helper ready: %v\nstdout:\n%s\n\nstderr:\n%s", err, stdoutBuf.String(), stderrBuf.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		<-scanDone
		t.Fatalf("ipv6 assignment helper ready timeout\nstdout:\n%s\n\nstderr:\n%s", stdoutBuf.String(), stderrBuf.String())
	}

	return ipv6AssignmentIntegrationHelperHandle{
		cmd:      cmd,
		stdout:   &stdoutBuf,
		stderr:   &stderrBuf,
		scanDone: scanDone,
	}
}

func startIPv6AssignmentSLAACIntegrationHelperWithExpectedPrefix(t *testing.T, topology dataplanePerfTopology, expectedPrefix string) ipv6AssignmentIntegrationHelperHandle {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestIPv6AssignmentIntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		ipv6AssignmentIntegrationHelperEnv+"=1",
		ipv6AssignmentIntegrationHelperRoleEnv+"=client-slaac",
		ipv6AssignmentIntegrationHelperIfaceEnv+"="+topology.ClientNSIF,
		ipv6AssignmentIntegrationHelperExpectedPrefEnv+"="+strings.TrimSpace(expectedPrefix),
	)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("slaac helper stdout pipe: %v", err)
	}
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ipv6 assignment slaac helper: %v", err)
	}

	ready := make(chan error, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)

		scanner := bufio.NewScanner(stdoutPipe)
		signaled := false
		for scanner.Scan() {
			line := scanner.Text()
			if !signaled && strings.TrimSpace(line) == ipv6AssignmentIntegrationReadyLine {
				signaled = true
				ready <- nil
				continue
			}
			stdoutBuf.WriteString(line)
			stdoutBuf.WriteByte('\n')
		}
		if signaled {
			return
		}
		if err := scanner.Err(); err != nil {
			ready <- err
			return
		}
		ready <- errors.New("ipv6 assignment slaac helper exited before ready")
	}()

	select {
	case err := <-ready:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			<-scanDone
			t.Fatalf("ipv6 assignment slaac helper ready: %v\nstdout:\n%s\n\nstderr:\n%s", err, stdoutBuf.String(), stderrBuf.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		<-scanDone
		t.Fatalf("ipv6 assignment slaac helper ready timeout\nstdout:\n%s\n\nstderr:\n%s", stdoutBuf.String(), stderrBuf.String())
	}

	return ipv6AssignmentIntegrationHelperHandle{
		cmd:      cmd,
		stdout:   &stdoutBuf,
		stderr:   &stderrBuf,
		scanDone: scanDone,
	}
}

func startIPv6AssignmentIntegrationBackendHelper(t *testing.T, topology dataplanePerfTopology) ipv6AssignmentIntegrationHelperHandle {
	return startIPv6AssignmentIntegrationBackendHelperWithAddrs(t, topology, ipv6AssignmentIntegrationBackendAddr, ipv6AssignmentIntegrationParentAddr, ipv6AssignmentIntegrationAssignedAddr)
}

func startIPv6AssignmentIntegrationBackendHelperWithAddrs(t *testing.T, topology dataplanePerfTopology, backendAddr string, parentAddr string, remoteAddr string) ipv6AssignmentIntegrationHelperHandle {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", topology.BackendNS, os.Args[0], "-test.run", "TestIPv6AssignmentIntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		ipv6AssignmentIntegrationHelperEnv+"=1",
		ipv6AssignmentIntegrationHelperRoleEnv+"=backend",
		ipv6AssignmentIntegrationHelperIfaceEnv+"="+topology.BackendNSIF,
		ipv6AssignmentIntegrationHelperListenEnv+"="+net.JoinHostPort(strings.TrimSpace(backendAddr), fmt.Sprintf("%d", ipv6AssignmentIntegrationBackendPort)),
		ipv6AssignmentIntegrationHelperParentAddrEnv+"="+strings.TrimSpace(parentAddr),
		ipv6AssignmentIntegrationHelperBackendAddrEnv+"="+strings.TrimSpace(backendAddr),
		ipv6AssignmentIntegrationHelperRemoteAddrEnv+"="+strings.TrimSpace(remoteAddr),
	)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("backend helper stdout pipe: %v", err)
	}
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ipv6 assignment backend helper: %v", err)
	}

	ready := make(chan error, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)

		scanner := bufio.NewScanner(stdoutPipe)
		signaled := false
		for scanner.Scan() {
			line := scanner.Text()
			if !signaled && strings.TrimSpace(line) == ipv6AssignmentIntegrationReadyLine {
				signaled = true
				ready <- nil
				continue
			}
			stdoutBuf.WriteString(line)
			stdoutBuf.WriteByte('\n')
		}
		if signaled {
			return
		}
		if err := scanner.Err(); err != nil {
			ready <- err
			return
		}
		ready <- errors.New("ipv6 assignment backend helper exited before ready")
	}()

	select {
	case err := <-ready:
		if err != nil {
			stopIPv6AssignmentIntegrationHelper(t, ipv6AssignmentIntegrationHelperHandle{cmd: cmd, stdout: &stdoutBuf, stderr: &stderrBuf, scanDone: scanDone})
			t.Fatalf("ipv6 assignment backend helper ready: %v\nstdout:\n%s\n\nstderr:\n%s", err, stdoutBuf.String(), stderrBuf.String())
		}
	case <-time.After(10 * time.Second):
		stopIPv6AssignmentIntegrationHelper(t, ipv6AssignmentIntegrationHelperHandle{cmd: cmd, stdout: &stdoutBuf, stderr: &stderrBuf, scanDone: scanDone})
		t.Fatalf("ipv6 assignment backend helper ready timeout\nstdout:\n%s\n\nstderr:\n%s", stdoutBuf.String(), stderrBuf.String())
	}

	return ipv6AssignmentIntegrationHelperHandle{
		cmd:      cmd,
		stdout:   &stdoutBuf,
		stderr:   &stderrBuf,
		scanDone: scanDone,
	}
}

func waitForIPv6AssignmentIntegrationHelper(helper ipv6AssignmentIntegrationHelperHandle, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- helper.cmd.Wait()
	}()

	select {
	case err := <-done:
		<-helper.scanDone
		if err != nil {
			return fmt.Errorf("ipv6 assignment helper failed: %w\nstdout:\n%s\n\nstderr:\n%s", err, strings.TrimSpace(helper.stdout.String()), strings.TrimSpace(helper.stderr.String()))
		}
		return nil
	case <-time.After(timeout):
		_ = helper.cmd.Process.Kill()
		err := <-done
		<-helper.scanDone
		if err == nil {
			err = errors.New("killed after timeout")
		}
		return fmt.Errorf("ipv6 assignment helper timed out after %s: %v\nstdout:\n%s\n\nstderr:\n%s", timeout, err, strings.TrimSpace(helper.stdout.String()), strings.TrimSpace(helper.stderr.String()))
	}
}

func stopIPv6AssignmentIntegrationHelper(t *testing.T, helper ipv6AssignmentIntegrationHelperHandle) {
	t.Helper()

	if helper.cmd == nil || helper.cmd.Process == nil {
		return
	}
	_ = helper.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() {
		done <- helper.cmd.Wait()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = helper.cmd.Process.Kill()
		<-done
	}
	if helper.scanDone != nil {
		<-helper.scanDone
	}
}

func runIPv6AssignmentIntegrationBackendHelper() error {
	ifaceName := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperIfaceEnv))
	listenAddr := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperListenEnv))
	parentAddr := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperParentAddrEnv))
	if parentAddr == "" {
		parentAddr = ipv6AssignmentIntegrationParentAddr
	}
	backendAddr := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperBackendAddrEnv))
	if backendAddr == "" {
		backendAddr = ipv6AssignmentIntegrationBackendAddr
	}
	remoteAddr := strings.TrimSpace(os.Getenv(ipv6AssignmentIntegrationHelperRemoteAddrEnv))
	if remoteAddr == "" {
		remoteAddr = ipv6AssignmentIntegrationAssignedAddr
	}
	if ifaceName == "" {
		return errors.New("missing backend helper interface name")
	}
	if listenAddr == "" {
		return errors.New("missing backend helper listen address")
	}

	if err := ensureIPv6AssignmentAddress(ifaceName, strings.TrimSpace(backendAddr)+"/64"); err != nil {
		return fmt.Errorf("install backend ipv6 address: %w", err)
	}
	if err := ensureIPv6DefaultRoute(ifaceName, parentAddr); err != nil {
		return fmt.Errorf("install backend ipv6 default route: %w", err)
	}

	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("parse backend helper listen address: %w", err)
	}

	ln, err := net.Listen("tcp6", net.JoinHostPort("::", port))
	if err != nil {
		return err
	}
	defer ln.Close()

	fmt.Println(ipv6AssignmentIntegrationReadyLine)
	tcpLn, _ := ln.(*net.TCPListener)
	if tcpLn != nil {
		_ = tcpLn.SetDeadline(time.Now().Add(20 * time.Second))
	}
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote == nil || remote.IP == nil {
		return fmt.Errorf("unexpected backend helper remote address %T", conn.RemoteAddr())
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || local == nil || local.IP == nil {
		return fmt.Errorf("unexpected backend helper local address %T", conn.LocalAddr())
	}
	wantLocal := parseIPLiteral(backendAddr)
	if wantLocal == nil || !local.IP.Equal(wantLocal) {
		return fmt.Errorf("backend helper local ip = %s, want %s", canonicalIPLiteral(local.IP), backendAddr)
	}
	wantRemote := parseIPLiteral(remoteAddr)
	if wantRemote == nil || !remote.IP.Equal(wantRemote) {
		return fmt.Errorf("backend helper remote ip = %s, want %s", canonicalIPLiteral(remote.IP), remoteAddr)
	}

	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	if string(payload) != "ping" {
		return fmt.Errorf("backend helper payload = %q, want %q", string(payload), "ping")
	}
	_, err = conn.Write([]byte("pong"))
	return err
}

func createIPv6AssignmentIntegration(apiBase string, topology dataplanePerfTopology) error {
	payload := map[string]any{
		"parent_interface": topology.BackendHostIF,
		"target_interface": topology.ClientHostIF,
		"parent_prefix":    ipv6AssignmentIntegrationParentPrefix,
		"assigned_prefix":  ipv6AssignmentIntegrationAssignedPrefix,
		"remark":           "ipv6-assignment-managed-address-integration",
		"enabled":          true,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal ipv6 assignment: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/ipv6-assignments", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build create ipv6 assignment request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("create ipv6 assignment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create ipv6 assignment unexpected status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func seedIPv6AssignmentIntegrationBackendNeighbors(t *testing.T, topology dataplanePerfTopology) {
	t.Helper()

	seedIPv6AssignmentIntegrationBackendNeighborsForAddresses(t, topology, ipv6AssignmentIntegrationParentAddr, ipv6AssignmentIntegrationBackendAddr)
}

func seedIPv6AssignmentIntegrationBackendNeighborsForAddresses(t *testing.T, topology dataplanePerfTopology, parentAddr string, backendAddr string) {
	t.Helper()

	if err := deleteIPv6NeighborOnInterface(topology.BackendHostIF, strings.TrimSpace(backendAddr)); err != nil {
		t.Fatalf("delete host backend neighbor: %v", err)
	}
	if err := deleteIPv6NeighborInNamespace(topology.BackendNS, topology.BackendNSIF, strings.TrimSpace(parentAddr)); err != nil {
		t.Fatalf("delete backend namespace parent neighbor: %v", err)
	}
	if err := replaceIPv6NeighborOnInterface(topology.BackendHostIF, strings.TrimSpace(backendAddr), mustParseIPv6AssignmentHardwareAddr(t, mustReadDataplanePerfNetnsMAC(t, topology.BackendNS, topology.BackendNSIF))); err != nil {
		t.Fatalf("replace host backend neighbor: %v", err)
	}
	if err := replaceIPv6NeighborInNamespace(topology.BackendNS, topology.BackendNSIF, strings.TrimSpace(parentAddr), mustParseIPv6AssignmentHardwareAddr(t, mustReadHostInterfaceMAC(t, topology.BackendHostIF))); err != nil {
		t.Fatalf("replace backend namespace parent neighbor: %v", err)
	}
}

func logIPv6AssignmentIntegrationStateOnFailure(t *testing.T, topology dataplanePerfTopology) {
	t.Helper()

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

	run("host ip -6 addr", "ip", "-6", "addr", "show")
	run("host ip -6 route", "ip", "-6", "route", "show")
	run("host ip -6 neigh show dev "+topology.BackendHostIF, "ip", "-6", "neigh", "show", "dev", topology.BackendHostIF)
	run("host ip -6 neigh show proxy dev "+topology.BackendHostIF, "ip", "-6", "neigh", "show", "proxy", "dev", topology.BackendHostIF)
	run("host ip -6 route get "+ipv6AssignmentIntegrationBackendAddr, "ip", "-6", "route", "get", ipv6AssignmentIntegrationBackendAddr)
	run("host ip -6 route get "+ipv6AssignmentIntegrationAssignedAddr, "ip", "-6", "route", "get", ipv6AssignmentIntegrationAssignedAddr)
	run("host proxy_ndp all", "cat", "/proc/sys/net/ipv6/conf/all/proxy_ndp")
	run("host proxy_ndp "+topology.BackendHostIF, "cat", "/proc/sys/net/ipv6/conf/"+topology.BackendHostIF+"/proxy_ndp")
	run("client ip -6 addr", "ip", "netns", "exec", topology.ClientNS, "ip", "-6", "addr", "show")
	run("client ip -6 route", "ip", "netns", "exec", topology.ClientNS, "ip", "-6", "route", "show")
	run("client ip -6 neigh", "ip", "netns", "exec", topology.ClientNS, "ip", "-6", "neigh", "show", "dev", topology.ClientNSIF)
	run("backend ip -6 addr", "ip", "netns", "exec", topology.BackendNS, "ip", "-6", "addr", "show")
	run("backend ip -6 route", "ip", "netns", "exec", topology.BackendNS, "ip", "-6", "route", "show")
	run("backend ip -6 neigh", "ip", "netns", "exec", topology.BackendNS, "ip", "-6", "neigh", "show", "dev", topology.BackendNSIF)
}

func waitForIPv6AssignmentRoute(topology dataplanePerfTopology) error {
	return waitForIPv6AssignmentRouteForPrefix(topology, ipv6AssignmentIntegrationAssignedPrefix)
}

func waitForIPv6AssignmentRouteForPrefix(topology dataplanePerfTopology, assignedPrefix string) error {
	link, err := resolveIPv6AssignmentRouteLink(topology.ClientHostIF)
	if err != nil {
		return fmt.Errorf("resolve target interface %q: %w", topology.ClientHostIF, err)
	}
	linkAttrs := link.Attrs()
	if linkAttrs == nil || linkAttrs.Index <= 0 {
		return fmt.Errorf("target interface %q is unavailable", topology.ClientHostIF)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		routes, err := netlink.RouteList(link, unix.AF_INET6)
		if err == nil {
			for _, route := range routes {
				if route.LinkIndex != linkAttrs.Index || route.Dst == nil {
					continue
				}
				if route.Dst.String() == strings.TrimSpace(assignedPrefix) {
					return nil
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for ipv6 assignment route for %s", strings.TrimSpace(assignedPrefix))
}

func openIPv6AssignmentNetnsHandle(namespace string) (*netlink.Handle, error) {
	ns, err := netns.GetFromName(strings.TrimSpace(namespace))
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	return netlink.NewHandleAt(ns)
}

func deleteIPv6NeighborOnInterface(ifaceName string, address string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	return deleteIPv6NeighborOnLink(link, address)
}

func deleteIPv6NeighborInNamespace(namespace string, ifaceName string, address string) error {
	handle, err := openIPv6AssignmentNetnsHandle(namespace)
	if err != nil {
		return err
	}
	defer handle.Close()

	link, err := handle.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	return deleteIPv6NeighborWithHandle(handle, link, address)
}

func deleteIPv6NeighborOnLink(link netlink.Link, address string) error {
	return deleteIPv6NeighborWithHandle(nil, link, address)
}

func deleteIPv6NeighborWithHandle(handle *netlink.Handle, link netlink.Link, address string) error {
	neigh, err := buildIPv6AssignmentNeighbor(link, address, nil)
	if err != nil {
		return err
	}
	if handle != nil {
		if err := handle.NeighDel(neigh); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return nil
	}
	if err := netlink.NeighDel(neigh); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func replaceIPv6NeighborOnInterface(ifaceName string, address string, mac net.HardwareAddr) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	return replaceIPv6NeighborOnLink(link, address, mac)
}

func replaceIPv6NeighborInNamespace(namespace string, ifaceName string, address string, mac net.HardwareAddr) error {
	handle, err := openIPv6AssignmentNetnsHandle(namespace)
	if err != nil {
		return err
	}
	defer handle.Close()

	link, err := handle.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	return replaceIPv6NeighborWithHandle(handle, link, address, mac)
}

func replaceIPv6NeighborOnLink(link netlink.Link, address string, mac net.HardwareAddr) error {
	return replaceIPv6NeighborWithHandle(nil, link, address, mac)
}

func replaceIPv6NeighborWithHandle(handle *netlink.Handle, link netlink.Link, address string, mac net.HardwareAddr) error {
	neigh, err := buildIPv6AssignmentNeighbor(link, address, mac)
	if err != nil {
		return err
	}
	if handle != nil {
		return handle.NeighSet(neigh)
	}
	return netlink.NeighSet(neigh)
}

func buildIPv6AssignmentNeighbor(link netlink.Link, address string, mac net.HardwareAddr) (*netlink.Neigh, error) {
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return nil, fmt.Errorf("neighbor link is unavailable")
	}
	ip := parseIPLiteral(address)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 neighbor address %q", address)
	}
	neigh := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    unix.AF_INET6,
		IP:        ip.To16(),
		State:     netlink.NUD_PERMANENT,
	}
	if len(mac) > 0 {
		neigh.HardwareAddr = append(net.HardwareAddr(nil), mac...)
	}
	return neigh, nil
}

func mustEnsureIPv6AssignmentAddress(t *testing.T, ifaceName string, cidr string) {
	t.Helper()

	if err := ensureIPv6AssignmentAddress(ifaceName, cidr); err != nil {
		t.Fatalf("configure ipv6 address %s on %s: %v", cidr, ifaceName, err)
	}
}

func mustParseIPv6AssignmentHardwareAddr(t *testing.T, text string) net.HardwareAddr {
	t.Helper()

	hw, err := net.ParseMAC(strings.TrimSpace(text))
	if err != nil {
		t.Fatalf("parse hardware address %q: %v", text, err)
	}
	return hw
}

func ensureIPv6AssignmentAddress(ifaceName string, cidr string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
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
	mask := append(net.IPMask(nil), prefix.Mask...)
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return fmt.Errorf("invalid ipv6 cidr %q", cidr)
	}
	prefix = &net.IPNet{
		IP:   append(net.IP(nil), ip...),
		Mask: mask,
	}

	return netlink.AddrReplace(link, &netlink.Addr{
		IPNet: prefix,
		Flags: unix.IFA_F_NODAD,
	})
}

func removeIPv6AssignmentAddress(ifaceName string, cidr string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
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
	mask := append(net.IPMask(nil), prefix.Mask...)
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return fmt.Errorf("invalid ipv6 cidr %q", cidr)
	}
	prefix = &net.IPNet{
		IP:   append(net.IP(nil), ip...),
		Mask: mask,
	}

	err = netlink.AddrDel(link, &netlink.Addr{
		IPNet: prefix,
		Flags: unix.IFA_F_NODAD,
	})
	if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return err
	}
	return nil
}

func removeIPv6AssignmentAddressInNamespace(namespace string, ifaceName string, cidr string) error {
	handle, err := openIPv6AssignmentNetnsHandle(namespace)
	if err != nil {
		return err
	}
	defer handle.Close()

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
	mask := append(net.IPMask(nil), prefix.Mask...)
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return fmt.Errorf("invalid ipv6 cidr %q", cidr)
	}
	prefix = &net.IPNet{
		IP:   append(net.IP(nil), ip...),
		Mask: mask,
	}

	err = handle.AddrDel(link, &netlink.Addr{
		IPNet: prefix,
		Flags: unix.IFA_F_NODAD,
	})
	if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return err
	}
	return nil
}

func ensureIPv6DefaultRoute(ifaceName string, gateway string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
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

	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: attrs.Index,
		Gw:        gw.To16(),
		Family:    unix.AF_INET6,
		Protocol:  unix.RTPROT_STATIC,
	})
}

func waitForIPv6AssignmentLinkLocal(ifaceName string, timeout time.Duration) (*net.Interface, net.IP, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		iface, err := net.InterfaceByName(ifaceName)
		if err == nil && iface != nil {
			if ip, err := selectIPv6AssignmentStableLinkLocal(ifaceName); err == nil {
				return iface, ip, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, nil, fmt.Errorf("interface %q has no stable IPv6 link-local address yet", ifaceName)
}

func selectIPv6AssignmentStableLinkLocal(ifaceName string) (net.IP, error) {
	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil && addr.IPNet != nil {
			ip = addr.IPNet.IP
		}
		ip = ip.To16()
		if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
			continue
		}
		if addr.Flags&unix.IFA_F_TENTATIVE != 0 {
			continue
		}
		return append(net.IP(nil), ip...), nil
	}
	return nil, fmt.Errorf("interface %q has no stable IPv6 link-local address yet", ifaceName)
}

func waitForIPv6RouteToTarget(ifaceName string, target string, timeout time.Duration) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return fmt.Errorf("parse target address %q: %w", target, err)
	}
	dst := parseIPLiteral(host)
	if dst == nil || dst.To4() != nil {
		return fmt.Errorf("invalid ipv6 target host %q", host)
	}

	link, err := netlink.LinkByName(strings.TrimSpace(ifaceName))
	if err != nil {
		return err
	}
	linkAttrs := link.Attrs()
	if linkAttrs == nil || linkAttrs.Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", ifaceName)
	}

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		routes, err := netlink.RouteGet(dst)
		if err == nil {
			for _, route := range routes {
				if route.LinkIndex == linkAttrs.Index {
					return nil
				}
			}
			lastErr = fmt.Errorf("no route to %s via %s yet", canonicalIPLiteral(dst), ifaceName)
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("route did not appear")
	}
	return fmt.Errorf("timed out waiting for ipv6 route to %s on %s: %v", canonicalIPLiteral(dst), ifaceName, lastErr)
}

func waitForManagedIPv6RouterAdvertisement(conn *icmp.PacketConn, packetConn *ipv6.PacketConn, ifIndex int, timeout time.Duration) error {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		step := time.Until(deadline)
		if step > 1*time.Second {
			step = 1 * time.Second
		}
		if err := conn.SetReadDeadline(time.Now().Add(step)); err != nil {
			return fmt.Errorf("set icmpv6 read deadline: %w", err)
		}
		n, cm, _, err := packetConn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("read icmpv6 router advertisement: %w", err)
		}
		if cm != nil && cm.IfIndex > 0 && cm.IfIndex != ifIndex {
			continue
		}
		msg, err := icmp.ParseMessage(58, buf[:n])
		if err != nil {
			continue
		}
		if msg.Type != ipv6.ICMPTypeRouterAdvertisement {
			continue
		}
		raw, ok := msg.Body.(*icmp.RawBody)
		if !ok || raw == nil || len(raw.Data) < 2 {
			continue
		}
		if raw.Data[1]&0x80 != 0 {
			return nil
		}
	}
	return fmt.Errorf("timed out waiting for managed router advertisement on ifindex %d", ifIndex)
}

func parseIPv6AssignmentExpectedPrefix(prefixText string) (*net.IPNet, error) {
	_, prefix, err := net.ParseCIDR(strings.TrimSpace(prefixText))
	if err != nil || prefix == nil || prefix.IP == nil || prefix.IP.To4() != nil {
		return nil, fmt.Errorf("invalid expected IPv6 prefix %q", prefixText)
	}
	return &net.IPNet{
		IP:   append(net.IP(nil), prefix.IP.Mask(prefix.Mask)...),
		Mask: append(net.IPMask(nil), prefix.Mask...),
	}, nil
}

func enableIPv6SLAACOnInterface(ifaceName string) error {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		return errors.New("interface name is required")
	}
	settings := []struct {
		path  string
		value string
	}{
		{path: "/proc/sys/net/ipv6/conf/all/accept_ra", value: "2\n"},
		{path: "/proc/sys/net/ipv6/conf/default/accept_ra", value: "2\n"},
		{path: "/proc/sys/net/ipv6/conf/" + ifaceName + "/accept_ra", value: "2\n"},
		{path: "/proc/sys/net/ipv6/conf/all/autoconf", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/default/autoconf", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/" + ifaceName + "/autoconf", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/all/accept_ra_pinfo", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/default/accept_ra_pinfo", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/" + ifaceName + "/accept_ra_pinfo", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/all/accept_ra_defrtr", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/default/accept_ra_defrtr", value: "1\n"},
		{path: "/proc/sys/net/ipv6/conf/" + ifaceName + "/accept_ra_defrtr", value: "1\n"},
	}
	for _, item := range settings {
		if err := os.WriteFile(item.path, []byte(item.value), 0o644); err != nil {
			return fmt.Errorf("configure slaac sysctl %s: %w", item.path, err)
		}
	}
	return nil
}

func waitForIPv6RouterAdvertisementForPrefix(conn *icmp.PacketConn, packetConn *ipv6.PacketConn, ifIndex int, expectedPrefix *net.IPNet, timeout time.Duration) error {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		step := time.Until(deadline)
		if step > time.Second {
			step = time.Second
		}
		if err := conn.SetReadDeadline(time.Now().Add(step)); err != nil {
			return fmt.Errorf("set icmpv6 read deadline: %w", err)
		}
		n, cm, _, err := packetConn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("read icmpv6 router advertisement: %w", err)
		}
		if cm != nil && cm.IfIndex > 0 && cm.IfIndex != ifIndex {
			continue
		}
		msg, err := icmp.ParseMessage(58, buf[:n])
		if err != nil {
			continue
		}
		if msg.Type != ipv6.ICMPTypeRouterAdvertisement {
			continue
		}
		raw, ok := msg.Body.(*icmp.RawBody)
		if !ok || raw == nil || len(raw.Data) < 12 {
			continue
		}
		if ipv6RouterAdvertisementIncludesPrefix(raw.Data[12:], expectedPrefix) {
			return nil
		}
	}
	return fmt.Errorf("timed out waiting for router advertisement prefix %s on ifindex %d", expectedPrefix.String(), ifIndex)
}

func ipv6RouterAdvertisementIncludesPrefix(options []byte, expectedPrefix *net.IPNet) bool {
	if expectedPrefix == nil {
		return false
	}
	expectedIP := expectedPrefix.IP.Mask(expectedPrefix.Mask).To16()
	if len(expectedIP) != net.IPv6len {
		return false
	}
	expectedOnes, expectedBits := expectedPrefix.Mask.Size()
	if expectedOnes < 0 || expectedBits != 128 {
		return false
	}

	for len(options) >= 2 {
		optionType := options[0]
		optionLenUnits := int(options[1])
		if optionLenUnits == 0 {
			return false
		}
		optionLen := optionLenUnits * 8
		if optionLen > len(options) {
			return false
		}
		option := options[:optionLen]
		options = options[optionLen:]

		if optionType != 3 || optionLen < 32 {
			continue
		}
		if int(option[2]) != expectedOnes || option[3]&0xc0 != 0xc0 {
			continue
		}
		prefixIP := net.IP(option[16:32]).Mask(expectedPrefix.Mask).To16()
		if len(prefixIP) != net.IPv6len {
			continue
		}
		if prefixIP.Equal(expectedIP) {
			return true
		}
	}
	return false
}

func waitForIPv6AddressInPrefix(ifaceName string, expectedPrefix *net.IPNet, timeout time.Duration) (net.IP, error) {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		return nil, errors.New("interface name is required")
	}
	if expectedPrefix == nil {
		return nil, errors.New("expected prefix is required")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		iface, err := net.InterfaceByName(ifaceName)
		if err == nil && iface != nil {
			addrs, err := iface.Addrs()
			if err == nil {
				for _, raw := range addrs {
					ipNet, ok := raw.(*net.IPNet)
					if !ok || ipNet == nil || ipNet.IP == nil {
						continue
					}
					ip := ipNet.IP.To16()
					if len(ip) != net.IPv6len || ip.To4() != nil || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
						continue
					}
					if expectedPrefix.Contains(ip) {
						return append(net.IP(nil), ip...), nil
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for ipv6 address in prefix %s on %s", expectedPrefix.String(), ifaceName)
}

func performIPv6AssignmentDHCPv6Handshake(conn *net.UDPConn, iface net.Interface, srcIP net.IP, clientID []byte, iaid [4]byte, timeout time.Duration) (parsedIPv6AssignmentDHCPv6Response, error) {
	deadline := time.Now().Add(timeout)

	solicitTxID := [3]byte{0x10, 0x20, 0x30}
	solicit := buildIPv6AssignmentDHCPv6Message(dhcpv6MessageSolicit, solicitTxID, clientID, nil, iaid)
	advertise, err := exchangeIPv6AssignmentDHCPv6(conn, iface, srcIP, solicit, dhcpv6MessageAdvertise, solicitTxID, deadline)
	if err != nil {
		return parsedIPv6AssignmentDHCPv6Response{}, err
	}
	if len(advertise.ServerID) == 0 {
		return parsedIPv6AssignmentDHCPv6Response{}, errors.New("dhcpv6 advertise missing server id")
	}

	requestTxID := [3]byte{0x10, 0x20, 0x31}
	request := buildIPv6AssignmentDHCPv6Message(dhcpv6MessageRequest, requestTxID, clientID, advertise.ServerID, iaid)
	reply, err := exchangeIPv6AssignmentDHCPv6(conn, iface, srcIP, request, dhcpv6MessageReply, requestTxID, deadline)
	if err != nil {
		return parsedIPv6AssignmentDHCPv6Response{}, err
	}
	return reply, nil
}

func exchangeIPv6AssignmentDHCPv6(conn *net.UDPConn, iface net.Interface, srcIP net.IP, request []byte, wantType byte, wantTxID [3]byte, deadline time.Time) (parsedIPv6AssignmentDHCPv6Response, error) {
	for time.Now().Before(deadline) {
		if err := sendIPv6AssignmentDHCPv6Frame(iface, srcIP, dhcpv6AllServersAndRelays, request); err != nil {
			return parsedIPv6AssignmentDHCPv6Response{}, fmt.Errorf("send dhcpv6 message: %w", err)
		}
		stepDeadline := time.Now().Add(1 * time.Second)
		if stepDeadline.After(deadline) {
			stepDeadline = deadline
		}
		reply, err := waitForIPv6AssignmentDHCPv6Response(conn, stepDeadline, wantType, wantTxID)
		if err == nil {
			return reply, nil
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				return parsedIPv6AssignmentDHCPv6Response{}, err
			}
		}
	}
	return parsedIPv6AssignmentDHCPv6Response{}, fmt.Errorf("timed out waiting for dhcpv6 message type %d", wantType)
}

func sendIPv6AssignmentDHCPv6Frame(iface net.Interface, srcIP net.IP, dstIP net.IP, payload []byte) error {
	frame, err := buildIPv6AssignmentDHCPv6Frame(iface, srcIP, dstIP, payload)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_IPV6)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var addr [8]byte
	copy(addr[:], []byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02})
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: htonsUnix(unix.ETH_P_IPV6),
		Halen:    6,
		Addr:     addr,
	})
}

func buildIPv6AssignmentDHCPv6Frame(iface net.Interface, srcIP net.IP, dstIP net.IP, payload []byte) ([]byte, error) {
	if len(iface.HardwareAddr) < 6 {
		return nil, fmt.Errorf("interface %q has no usable ethernet address", iface.Name)
	}
	src := srcIP.To16()
	dst := dstIP.To16()
	if src == nil || src.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 source address %q", srcIP.String())
	}
	if dst == nil || dst.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 destination address %q", dstIP.String())
	}

	udpLen := 8 + len(payload)
	if udpLen > 0xffff {
		return nil, fmt.Errorf("dhcpv6 payload too large: %d", len(payload))
	}

	frame := make([]byte, 14+40+udpLen)
	copy(frame[0:6], []byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02})
	copy(frame[6:12], iface.HardwareAddr[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14 : 14+40]
	ipv6Header[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(udpLen))
	ipv6Header[6] = 17
	ipv6Header[7] = 1
	copy(ipv6Header[8:24], src)
	copy(ipv6Header[24:40], dst)

	udp := frame[14+40:]
	binary.BigEndian.PutUint16(udp[0:2], dhcpv6ClientPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpv6ServerPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv6(src, dst, udp))
	return frame, nil
}

func udpChecksumIPv6(src net.IP, dst net.IP, udp []byte) uint16 {
	sumLen := 40 + len(udp)
	buf := make([]byte, 0, sumLen)
	buf = append(buf, src.To16()...)
	buf = append(buf, dst.To16()...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(udp)))
	buf = append(buf, length...)
	buf = append(buf, 0, 0, 0, 17)
	buf = append(buf, udp...)
	checksum := internetChecksum(buf)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func waitForIPv6AssignmentDHCPv6Response(conn *net.UDPConn, deadline time.Time, wantType byte, wantTxID [3]byte) (parsedIPv6AssignmentDHCPv6Response, error) {
	buf := make([]byte, 2048)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return parsedIPv6AssignmentDHCPv6Response{}, err
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return parsedIPv6AssignmentDHCPv6Response{}, err
		}
		reply, err := parseIPv6AssignmentDHCPv6Response(buf[:n])
		if err != nil {
			continue
		}
		if reply.Type != wantType || reply.TxID != wantTxID {
			continue
		}
		return reply, nil
	}
}

func buildIPv6AssignmentDHCPv6Message(msgType byte, txID [3]byte, clientID []byte, serverID []byte, iaid [4]byte) []byte {
	out := []byte{msgType, txID[0], txID[1], txID[2]}
	out = append(out, buildDHCPv6Option(dhcpv6OptionClientID, clientID)...)
	if len(serverID) > 0 {
		out = append(out, buildDHCPv6Option(dhcpv6OptionServerID, serverID)...)
	}
	iana := make([]byte, 12)
	copy(iana[:4], iaid[:])
	out = append(out, buildDHCPv6Option(dhcpv6OptionIANA, iana)...)
	return out
}

func parseIPv6AssignmentDHCPv6Response(packet []byte) (parsedIPv6AssignmentDHCPv6Response, error) {
	msg, err := parseDHCPv6Message(packet)
	if err != nil {
		return parsedIPv6AssignmentDHCPv6Response{}, err
	}
	reply := parsedIPv6AssignmentDHCPv6Response{
		Type:     msg.Type,
		TxID:     msg.TxID,
		ServerID: append([]byte(nil), msg.ServerID...),
	}

	options := packet[4:]
	for len(options) >= 4 {
		code := binary.BigEndian.Uint16(options[0:2])
		length := int(binary.BigEndian.Uint16(options[2:4]))
		options = options[4:]
		if length > len(options) {
			return parsedIPv6AssignmentDHCPv6Response{}, fmt.Errorf("invalid dhcpv6 option length")
		}
		value := options[:length]
		options = options[length:]
		if code != dhcpv6OptionIANA || len(value) < 12 {
			continue
		}
		nested := value[12:]
		for len(nested) >= 4 {
			nestedCode := binary.BigEndian.Uint16(nested[0:2])
			nestedLength := int(binary.BigEndian.Uint16(nested[2:4]))
			nested = nested[4:]
			if nestedLength > len(nested) {
				return parsedIPv6AssignmentDHCPv6Response{}, fmt.Errorf("invalid nested dhcpv6 option length")
			}
			nestedValue := nested[:nestedLength]
			nested = nested[nestedLength:]
			if nestedCode != dhcpv6OptionIAAddr || len(nestedValue) < 24 {
				continue
			}
			ip := net.IP(append([]byte(nil), nestedValue[:16]...))
			if ip = ip.To16(); ip != nil && ip.To4() == nil {
				reply.Addresses = append(reply.Addresses, ip)
			}
		}
	}
	return reply, nil
}

func ensureIPv6AddressAbsent(ifaceName string, address string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, raw := range addrs {
		ipNet, ok := raw.(*net.IPNet)
		if !ok || ipNet == nil {
			continue
		}
		ip := ipNet.IP.To16()
		if ip == nil || ip.To4() != nil {
			continue
		}
		if canonicalIPLiteral(ip) == address {
			return fmt.Errorf("address %s is already present on %s before dhcpv6", address, ifaceName)
		}
	}
	return nil
}

func ensureIPv6AddressPresent(ifaceName string, address string) error {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		iface, err := net.InterfaceByName(ifaceName)
		if err == nil && iface != nil {
			addrs, err := iface.Addrs()
			if err == nil {
				for _, raw := range addrs {
					ipNet, ok := raw.(*net.IPNet)
					if !ok || ipNet == nil {
						continue
					}
					ip := ipNet.IP.To16()
					if ip == nil || ip.To4() != nil {
						continue
					}
					if canonicalIPLiteral(ip) == address {
						return nil
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("address %s was not installed on %s", address, ifaceName)
}

func verifyIPv6AssignmentTCPConnectivity(target string, expectedLocalIP net.IP, timeout time.Duration) error {
	wantLocal := expectedLocalIP.To16()
	if wantLocal == nil || wantLocal.To4() != nil {
		return fmt.Errorf("invalid expected local ipv6 %q", expectedLocalIP.String())
	}

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		dialer := net.Dialer{
			Timeout:   1 * time.Second,
			LocalAddr: &net.TCPAddr{IP: append(net.IP(nil), wantLocal...)},
		}
		conn, err := dialer.Dial("tcp6", target)
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}

		local, ok := conn.LocalAddr().(*net.TCPAddr)
		if !ok || local == nil || local.IP == nil {
			_ = conn.Close()
			return fmt.Errorf("unexpected local tcp address %T", conn.LocalAddr())
		}
		localIP := local.IP.To16()
		if localIP == nil || !localIP.Equal(wantLocal) {
			_ = conn.Close()
			return fmt.Errorf("tcp local ip = %s, want %s", canonicalIPLiteral(local.IP), canonicalIPLiteral(wantLocal))
		}

		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			_ = conn.Close()
			return fmt.Errorf("set tcp connectivity deadline: %w", err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			_ = conn.Close()
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		reply := make([]byte, 4)
		if _, err := io.ReadFull(conn, reply); err != nil {
			_ = conn.Close()
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		_ = conn.Close()
		if string(reply) != "pong" {
			return fmt.Errorf("tcp connectivity reply = %q, want %q", string(reply), "pong")
		}
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("timed out verifying ipv6 assignment tcp connectivity to %s: last error: %v", target, lastErr)
	}
	return fmt.Errorf("timed out verifying ipv6 assignment tcp connectivity to %s", target)
}

func joinIPv6List(values []net.IP) string {
	if len(values) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, canonicalIPLiteral(value))
	}
	return strings.Join(out, ", ")
}

func makeShortIPv6AssignmentIntegrationDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "fwip6a-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}
