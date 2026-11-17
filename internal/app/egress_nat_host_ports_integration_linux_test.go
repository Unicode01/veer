//go:build linux

package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestEgressNATKeepsHostConnectionsOnTheNATAddress checks that egress NAT
// never maps a guest onto a port the host may pick for its own connections
// from the NAT address. The host's ephemeral range is narrowed to 100 ports
// and a guest holds a full-cone TCP connection to the backend from each of
// those very ports. A NAT that kept the guest's source ports would own every
// port the host can pick: each host connection to the same backend would then
// share the 4-tuple of a guest connection, its SYN would draw a challenge ACK
// the NAT hands to the guest, and the RST the host answers with would reset
// the guest's connection while the host's own connect stalls until its SYN
// is retransmitted. So every host connection must be quick, and every guest
// connection must survive them.
func TestEgressNATKeepsHostConnectionsOnTheNATAddress(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	const hostLow, hostHigh = 40000, 40099
	h := startEgressNATIntegrationHarnessWithConfig(t, "host-ports", func(t *testing.T, _, _, _ string) {
		original := strings.Join(strings.Fields(readDataplanePerfProcFile(t, "/proc/sys/net/ipv4/ip_local_port_range")), " ")
		t.Cleanup(func() {
			if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_local_port_range="+original).CombinedOutput(); err != nil {
				t.Logf("restore ip_local_port_range=%s: %v %s", original, err, out)
			}
		})
		mustRunDataplanePerfCmd(t, "sysctl", "-w", fmt.Sprintf("net.ipv4.ip_local_port_range=%d %d", hostLow, hostHigh))
	})
	top := h.Topology
	createEgressNATIntegrationEntryForScopeWithOptions(t, h.APIBase, top, "", "tcp+udp", egressNATTypeFullCone)
	waitForLateralEgressNATs(t, h.APIBase, h.LogPath, 1, kernelEngineTC)

	minPort, maxPort := egressNATHostPortsWindow(t, h.APIBase)
	if minPort <= hostHigh && maxPort >= hostLow {
		t.Fatalf("kernel NAT ports %d-%d overlap the host's ephemeral ports %d-%d", minPort, maxPort, hostLow, hostHigh)
	}
	t.Logf("kernel NAT ports %d-%d, host ephemeral ports %d-%d", minPort, maxPort, hostLow, hostHigh)

	target := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(egressNATSoakPort))
	startEgressNATSoakServer(t, top.BackendNS, target)

	// The guest takes a full-cone mapping from each of the host's ports.
	hold := exec.Command("ip", "netns", "exec", top.ClientNS, os.Args[0], "-test.run", "^TestEgressNATSoakHelperProcess$", "-test.v=false")
	hold.Env = append(os.Environ(), egressNATSoakHelperEnv+"=1", egressNATSoakRoleEnv+"=hold",
		egressNATSoakListenEnv+"="+target, egressNATSoakPlanEnv+fmt.Sprintf("=%d-%d", hostLow, hostHigh))
	stdin, err := hold.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := hold.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var holdErr bytes.Buffer
	hold.Stderr = &holdErr
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = hold.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = hold.Process.Kill()
		}
	})
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- strings.TrimSpace(scanner.Text())
		}
		close(lines)
	}()
	expect := func(prefix string, timeout time.Duration) string {
		t.Helper()
		deadline := time.After(timeout)
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("guest helper exited waiting for %q: %s", prefix, holdErr.String())
				}
				if strings.HasPrefix(line, prefix) {
					return line
				}
			case <-deadline:
				t.Fatalf("guest helper sent no %q: %s", prefix, holdErr.String())
			}
		}
	}
	expect(egressNATHelperReadyLine, 60*time.Second)

	// The host now connects from its NAT address; the kernel picks its local
	// ports from the narrowed range.
	const attempts = 50
	const slow = 500 * time.Millisecond
	var problems []string
	for i := 0; i < attempts; i++ {
		started := time.Now()
		dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(egressNATUplinkAddr)}}
		conn, err := dialer.Dial("tcp", target)
		took := time.Since(started)
		if err != nil {
			problems = append(problems, fmt.Sprintf("host connection %d: %v after %s", i, err, took))
			continue
		}
		local := conn.LocalAddr().(*net.TCPAddr).Port
		if took > slow {
			problems = append(problems, fmt.Sprintf("host connection %d from port %d took %s to connect", i, local, took.Round(time.Millisecond)))
		}
		msg := []byte(fmt.Sprintf("host-%d", i))
		buf := make([]byte, len(msg))
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(msg); err != nil {
			problems = append(problems, fmt.Sprintf("host connection %d from port %d: write: %v", i, local, err))
		} else if _, err := io.ReadFull(conn, buf); err != nil || !bytes.Equal(buf, msg) {
			problems = append(problems, fmt.Sprintf("host connection %d from port %d: echo: %v", i, local, err))
		}
		_ = conn.Close()
	}

	// The guest's connections must all still carry data.
	if _, err := io.WriteString(stdin, "check\n"); err != nil {
		t.Fatal(err)
	}
	check := expect("CHECK", 60*time.Second)
	if check != fmt.Sprintf("CHECK ok=%d broken=0", hostHigh-hostLow+1) {
		problems = append(problems, "guest connections after the host's: "+check)
	}
	t.Logf("guest connections after the host's: %s", check)
	if len(problems) > 0 {
		for _, problem := range problems {
			t.Log(problem)
		}
		logKernelRuntimeOnFailure(t, h.APIBase)
		t.Fatalf("%d problems with host connections from the NAT address beside a guest's mappings", len(problems))
	}
}

func egressNATHostPortsWindow(t *testing.T, apiBase string) (int, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/kernel/runtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var view struct {
		Engines []KernelEngineRuntimeView `json:"engines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	for _, engine := range view.Engines {
		if engine.Name == kernelEngineTC {
			return engine.NATPortMin, engine.NATPortMax
		}
	}
	t.Fatal("no tc engine in the runtime view")
	return 0, 0
}
