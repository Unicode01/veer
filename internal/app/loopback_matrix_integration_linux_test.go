//go:build linux

package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLoopbackAccessMatrix checks which clients reach which forwards through
// the host's own addresses (hairpin, or NAT loopback): guests behind egress
// NAT, a routed network without NAT, guests on a plain bridge, an outside
// client and the host itself, against kernel and user space, full NAT and
// transparent forwards to a guest, to 127.0.0.1 and to an address of the host.
// It prints the whole table and fails on every cell that differs from what is
// expected. Cells expected to fail are the cases left unsupported: kernel
// forwards only see traffic on the interfaces they are attached to, so the
// host itself and clients arriving elsewhere do not reach them.
//
// Topology (all IPv4, TCP):
//
//	external client 198.19.0.2 --- uplink 198.19.0.1 (host)
//	guest client 198.18.0.2, guest server 198.18.0.3 --- bridge 198.18.0.1, egress NAT to the uplink
//	routed client 198.20.0.2 --- veth 198.20.0.1 (no egress NAT, no hooks)
//	plain guest client 198.21.0.2, plain guest server 198.21.0.3 --- bridge 198.21.0.1 (no egress NAT)
//	host itself: the root namespace
//
// FORWARD_LOOPBACK_MATRIX_ONLY=name,... keeps the rules whose names contain
// one of the parts; FORWARD_LOOPBACK_MATRIX_DEBUG=1 adds packet captures of
// failing probes, the policy routing state and the daemon log.
const (
	loopbackMatrixGuestServer   = "198.18.0.3"
	loopbackMatrixRoutedHost    = "198.20.0.1"
	loopbackMatrixRoutedClient  = "198.20.0.2"
	loopbackMatrixPlainBridge   = "198.21.0.1"
	loopbackMatrixPlainClient   = "198.21.0.2"
	loopbackMatrixPlainServer   = "198.21.0.3"
	loopbackMatrixProbeDeadline = 12 * time.Second
)

type loopbackMatrixClient struct {
	name string
	ns   string // "" is the root namespace, the host itself
}

// loopbackMatrixExpect is one probe: client reaches the forward (ok), and the
// backend sees source when it is set.
type loopbackMatrixExpect struct {
	client string
	ok     bool
	source string
}

type loopbackMatrixRule struct {
	name      string
	payload   map[string]any
	target    string // address:port clients dial
	backendNS string // "" is the root namespace
	backendAt string // address:port the backend listens on
	engine    string // effective engine expected; "" when the API rejects the rule
	expect    []loopbackMatrixExpect
}

// parseLoopbackMatrixExpect reads "client+" (connects), "client-" (does not)
// and "client=source" (connects, and the backend sees source).
func parseLoopbackMatrixExpect(spec string) []loopbackMatrixExpect {
	var out []loopbackMatrixExpect
	for _, item := range strings.Fields(spec) {
		switch {
		case strings.Contains(item, "="):
			parts := strings.SplitN(item, "=", 2)
			out = append(out, loopbackMatrixExpect{client: parts[0], ok: true, source: parts[1]})
		case strings.HasSuffix(item, "+"):
			out = append(out, loopbackMatrixExpect{client: strings.TrimSuffix(item, "+"), ok: true})
		default:
			out = append(out, loopbackMatrixExpect{client: strings.TrimSuffix(item, "-")})
		}
	}
	return out
}

type loopbackMatrixRuleStatus struct {
	ID                    int64  `json:"id"`
	Remark                string `json:"remark"`
	Status                string `json:"status"`
	EffectiveEngine       string `json:"effective_engine"`
	EffectiveKernelEngine string `json:"effective_kernel_engine"`
	KernelReason          string `json:"kernel_reason"`
	FallbackReason        string `json:"fallback_reason"`
}

func TestLoopbackAccessMatrix(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	h := startEgressNATIntegrationHarness(t, "loopback-matrix")
	topo := h.Topology
	createEgressNATIntegrationEntryForScope(t, h.APIBase, topo, "")
	waitForEgressNATIntegrationStatus(t, h.APIBase, topo, "")

	guestServerNS := setupHairpinIntegrationServer(t, topo)
	routedNS := setupLoopbackMatrixRoutedClient(t)
	plainBridge, plainClientNS, plainServerNS := setupLoopbackMatrixPlainBridge(t)

	clients := map[string]loopbackMatrixClient{
		"external": {name: "external 198.19.0.2", ns: topo.BackendNS},
		"guest":    {name: "guest behind egress NAT 198.18.0.2", ns: topo.ClientNS},
		"routed":   {name: "routed client, no NAT 198.20.0.2", ns: routedNS},
		"host":     {name: "host itself", ns: ""},
		"plain":    {name: "guest on plain bridge 198.21.0.2", ns: plainClientNS},
	}

	// Every rule gets its own front port and its own backend port: transparent
	// kernel rules need a backend endpoint of their own.
	port := 25000
	rule := func(name string, inIF string, inIP string, engine string, transparent bool, outIF string, outIP string, backendNS string, wantEngine string, expect string) loopbackMatrixRule {
		port++
		backendPort := port - 6000
		return loopbackMatrixRule{
			name: name,
			payload: map[string]any{
				"in_interface": inIF, "in_ip": inIP, "in_port": port,
				"out_interface": outIF, "out_ip": outIP, "out_port": backendPort,
				"protocol": "tcp", "transparent": transparent, "engine_preference": engine,
			},
			target:    net.JoinHostPort(inIP, strconv.Itoa(port)),
			backendNS: backendNS,
			backendAt: net.JoinHostPort(outIP, strconv.Itoa(backendPort)),
			engine:    wantEngine,
			expect:    parseLoopbackMatrixExpect(expect),
		}
	}
	up, upIP := topo.UplinkHostIF, egressNATUplinkAddr
	br, brIP := topo.BridgeIF, egressNATBridgeAddr
	guest := loopbackMatrixGuestServer
	plainIP, plainServer := loopbackMatrixPlainBridge, loopbackMatrixPlainServer
	kernel, user := ruleEngineKernel, ruleEngineUserspace
	everyone := "external+ guest+ routed+ host+"
	rules := []loopbackMatrixRule{
		rule("uplink->guest fullnat kernel", up, upIP, kernel, false, br, guest, guestServerNS, kernel, "external=198.18.0.1 guest=198.18.0.1 routed- host-"),
		rule("uplink->guest transparent kernel", up, upIP, kernel, true, br, guest, guestServerNS, kernel, "external=198.19.0.2 guest=198.18.0.1 routed- host-"),
		rule("uplink->guest fullnat userspace", up, upIP, user, false, br, guest, guestServerNS, user, everyone),
		rule("uplink->guest transparent userspace", up, upIP, user, true, br, guest, guestServerNS, user, "external=198.19.0.2 guest=198.18.0.1 routed=198.20.0.2 host+"),
		rule("uplink->127.0.0.1 fullnat kernel", up, upIP, kernel, false, "lo", "127.0.0.1", "", user, everyone),
		rule("uplink->127.0.0.1 transparent kernel", up, upIP, kernel, true, "lo", "127.0.0.1", "", "", ""),
		rule("uplink->127.0.0.1 fullnat userspace", up, upIP, user, false, "lo", "127.0.0.1", "", user, everyone),
		rule("uplink->host addr fullnat kernel", up, upIP, kernel, false, br, brIP, "", user, everyone),
		rule("uplink->host addr transparent kernel", up, upIP, kernel, true, br, brIP, "", "", ""),
		rule("uplink->host addr fullnat userspace", up, upIP, user, false, br, brIP, "", user, everyone),
		rule("NAT bridge->guest fullnat kernel", br, brIP, kernel, false, br, guest, guestServerNS, kernel, "guest=198.18.0.1 external- host-"),
		rule("NAT bridge->guest transparent kernel", br, brIP, kernel, true, br, guest, guestServerNS, kernel, "guest=198.18.0.1 external- host-"),
		rule("NAT bridge->guest transparent userspace", br, brIP, user, true, br, guest, guestServerNS, user, "guest=198.18.0.1 external=198.19.0.2 host+"),
		rule("plain bridge->guest fullnat kernel", plainBridge, plainIP, kernel, false, plainBridge, plainServer, plainServerNS, kernel, "plain=198.21.0.1 external- host-"),
		rule("plain bridge->guest transparent kernel", plainBridge, plainIP, kernel, true, plainBridge, plainServer, plainServerNS, kernel, "plain=198.21.0.2 external- host-"),
		rule("plain bridge->guest transparent userspace", plainBridge, plainIP, user, true, plainBridge, plainServer, plainServerNS, user, "plain=198.21.0.1 external=198.19.0.2 host+"),
	}
	if only := strings.TrimSpace(os.Getenv("FORWARD_LOOPBACK_MATRIX_ONLY")); only != "" {
		var kept []loopbackMatrixRule
		for _, rule := range rules {
			for _, part := range strings.Split(only, ",") {
				if part = strings.TrimSpace(part); part != "" && strings.Contains(rule.name, part) {
					kept = append(kept, rule)
					break
				}
			}
		}
		rules = kept
	}
	debug := os.Getenv("FORWARD_LOOPBACK_MATRIX_DEBUG") == "1"

	created := make(map[string]string, len(rules)) // remark -> API error, "" when created
	for i := range rules {
		remark := fmt.Sprintf("lbm-%02d", i+1)
		rules[i].payload["remark"] = remark
		rules[i].payload["tag"] = "loopback-matrix"
		created[remark] = createLoopbackMatrixRule(t, h.APIBase, rules[i].payload)
	}
	statuses := waitForLoopbackMatrixRules(t, h.APIBase, created)
	if debug {
		for _, args := range [][]string{{"ip", "rule"}, {"ip", "route", "show", "table", "198"}, {"iptables", "-t", "mangle", "-S"}, {"sysctl", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"}} {
			out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
			t.Logf("$ %s\n%s", strings.Join(args, " "), out)
		}
	}

	var table strings.Builder
	var mismatches []string
	fmt.Fprintf(&table, "\n%-44s | %-34s | %s\n", "rule (engine wanted)", "client", "result")
	for i, rule := range rules {
		remark := fmt.Sprintf("lbm-%02d", i+1)
		if apiErr := created[remark]; apiErr != "" {
			fmt.Fprintf(&table, "%-44s | %-34s | API rejected: %s\n", rule.name, "-", apiErr)
			if rule.engine != "" {
				mismatches = append(mismatches, fmt.Sprintf("%s: API rejected the rule: %s", rule.name, apiErr))
			}
			continue
		}
		if rule.engine == "" {
			mismatches = append(mismatches, fmt.Sprintf("%s: API accepted the rule, want it rejected", rule.name))
		}
		st := statuses[remark]
		fmt.Fprintf(&table, "%-44s | %-34s | status=%s engine=%s/%s kernel_reason=%q fallback=%q\n",
			rule.name, "(rule)", st.Status, st.EffectiveEngine, st.EffectiveKernelEngine, st.KernelReason, st.FallbackReason)
		if rule.engine != "" && (st.Status != "running" || st.EffectiveEngine != rule.engine) {
			mismatches = append(mismatches, fmt.Sprintf("%s: status %s engine %s, want running on %s", rule.name, st.Status, st.EffectiveEngine, rule.engine))
		}
		for _, want := range rule.expect {
			client := clients[want.client]
			var capture *loopbackMatrixCapture
			if debug {
				_, backendPort, _ := net.SplitHostPort(rule.backendAt)
				_, frontPort, _ := net.SplitHostPort(rule.target)
				capture = startLoopbackMatrixCapture(backendPort, frontPort)
			}
			observed, err := runLoopbackMatrixProbe(t, client.ns, rule.backendNS, rule.backendAt, rule.target)
			result := "OK, backend saw " + observed
			if err != nil {
				result = "FAIL: " + err.Error()
			}
			switch {
			case want.ok && err != nil:
				mismatches = append(mismatches, fmt.Sprintf("%s / %s: %s, want it to connect", rule.name, client.name, result))
			case !want.ok && err == nil:
				mismatches = append(mismatches, fmt.Sprintf("%s / %s: %s, want it to fail", rule.name, client.name, result))
			case want.ok && want.source != "" && observed != want.source:
				mismatches = append(mismatches, fmt.Sprintf("%s / %s: backend saw %s, want %s", rule.name, client.name, observed, want.source))
			}
			fmt.Fprintf(&table, "%-44s | %-34s | %s\n", "", client.name, result)
			if capture != nil {
				packets := capture.stop()
				if err != nil {
					t.Logf("capture for %s / %s:\n%s", rule.name, client.name, packets)
				}
			}
		}
	}
	t.Log(table.String())
	if debug {
		logKernelRuntimeOnFailure(t, h.APIBase)
		if data, err := os.ReadFile(h.LogPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) > 150 {
				lines = lines[len(lines)-150:]
			}
			t.Logf("daemon log tail:\n%s", strings.Join(lines, "\n"))
		}
	}
	for _, mismatch := range mismatches {
		t.Error(mismatch)
	}
}

type loopbackMatrixCapture struct {
	cancel context.CancelFunc
	cmd    *exec.Cmd
	out    bytes.Buffer
}

// startLoopbackMatrixCapture records the probe's packets on every interface of
// the root namespace (bridges, their ports, the uplink, lo).
func startLoopbackMatrixCapture(backendPort string, frontPort string) *loopbackMatrixCapture {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), loopbackMatrixProbeDeadline+8*time.Second)
	c := &loopbackMatrixCapture{cancel: cancel}
	c.cmd = exec.CommandContext(ctx, "tcpdump", "-l", "-nn", "-i", "any", "-c", "40", "tcp port "+backendPort+" or tcp port "+frontPort)
	c.cmd.Stdout = &c.out
	c.cmd.Stderr = &c.out
	if err := c.cmd.Start(); err != nil {
		cancel()
		return nil
	}
	time.Sleep(400 * time.Millisecond)
	return c
}

func (c *loopbackMatrixCapture) stop() string {
	time.Sleep(300 * time.Millisecond)
	c.cancel()
	_ = c.cmd.Wait()
	return c.out.String()
}

func setupLoopbackMatrixRoutedClient(t *testing.T) string {
	t.Helper()
	suffix := strconv.Itoa(os.Getpid() % 100000)
	ns := "fwlr" + suffix
	hostIF := truncateIfName("fwlh" + suffix)
	nsIF := truncateIfName("fwln" + suffix)
	cleanup := func() {
		runDataplanePerfCmd("ip", "link", "del", hostIF)
		runDataplanePerfCmd("ip", "netns", "del", ns)
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRunDataplanePerfCmd(t, "ip", "netns", "add", ns)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", hostIF, "type", "veth", "peer", "name", nsIF)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", loopbackMatrixRoutedHost+"/24", "dev", hostIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", hostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", nsIF, "netns", ns)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", ns, "ip", "addr", "add", loopbackMatrixRoutedClient+"/24", "dev", nsIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", ns, "ip", "link", "set", nsIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", ns, "ip", "route", "replace", "default", "via", loopbackMatrixRoutedHost, "dev", nsIF)
	return ns
}

// setupLoopbackMatrixPlainBridge builds a bridge without egress NAT holding
// two guests, like guests with their own addresses on a host's LAN bridge.
func setupLoopbackMatrixPlainBridge(t *testing.T) (string, string, string) {
	t.Helper()
	suffix := strconv.Itoa(os.Getpid() % 100000)
	bridge := truncateIfName("fwpb" + suffix)
	type guest struct{ ns, hostIF, nsIF, addr string }
	guests := []guest{
		{ns: "fwpc" + suffix, hostIF: truncateIfName("fwpch" + suffix), nsIF: truncateIfName("fwpcn" + suffix), addr: loopbackMatrixPlainClient},
		{ns: "fwps" + suffix, hostIF: truncateIfName("fwpsh" + suffix), nsIF: truncateIfName("fwpsn" + suffix), addr: loopbackMatrixPlainServer},
	}
	cleanup := func() {
		for _, g := range guests {
			runDataplanePerfCmd("ip", "link", "del", g.hostIF)
			runDataplanePerfCmd("ip", "netns", "del", g.ns)
		}
		runDataplanePerfCmd("ip", "link", "del", bridge)
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRunDataplanePerfCmd(t, "ip", "link", "add", bridge, "type", "bridge")
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", loopbackMatrixPlainBridge+"/24", "dev", bridge)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", bridge, "up")
	for _, g := range guests {
		mustRunDataplanePerfCmd(t, "ip", "netns", "add", g.ns)
		mustRunDataplanePerfCmd(t, "ip", "link", "add", g.hostIF, "type", "veth", "peer", "name", g.nsIF)
		mustRunDataplanePerfCmd(t, "ip", "link", "set", g.hostIF, "master", bridge)
		mustRunDataplanePerfCmd(t, "ip", "link", "set", g.hostIF, "up")
		mustRunDataplanePerfCmd(t, "ip", "link", "set", g.nsIF, "netns", g.ns)
		mustRunDataplanePerfCmd(t, "ip", "netns", "exec", g.ns, "ip", "link", "set", "lo", "up")
		mustRunDataplanePerfCmd(t, "ip", "netns", "exec", g.ns, "ip", "addr", "add", g.addr+"/24", "dev", g.nsIF)
		mustRunDataplanePerfCmd(t, "ip", "netns", "exec", g.ns, "ip", "link", "set", g.nsIF, "up")
		mustRunDataplanePerfCmd(t, "ip", "netns", "exec", g.ns, "ip", "route", "replace", "default", "via", loopbackMatrixPlainBridge, "dev", g.nsIF)
	}
	return bridge, guests[0].ns, guests[1].ns
}

func createLoopbackMatrixRule(t *testing.T, apiBase string, payload map[string]any) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal rule payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Sprintf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return ""
}

// waitForLoopbackMatrixRules waits until every created rule has left any
// pending state, or 30 seconds pass, and returns the statuses by remark.
func waitForLoopbackMatrixRules(t *testing.T, apiBase string, created map[string]string) map[string]loopbackMatrixRuleStatus {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	var last map[string]loopbackMatrixRuleStatus
	stable := 0
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/rules", nil)
		if err != nil {
			t.Fatalf("build list rules request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var items []loopbackMatrixRuleStatus
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil {
			continue
		}
		current := make(map[string]loopbackMatrixRuleStatus, len(items))
		settled := true
		for _, item := range items {
			current[item.Remark] = item
		}
		for remark, apiErr := range created {
			if apiErr != "" {
				continue
			}
			st, ok := current[remark]
			if !ok || st.Status == "" || st.Status == "pending" || st.Status == "starting" {
				settled = false
			}
		}
		if settled && last != nil && fmt.Sprint(last) == fmt.Sprint(current) {
			stable++
		} else {
			stable = 0
		}
		last = current
		if stable >= 3 {
			break
		}
	}
	return last
}

func loopbackMatrixCommand(ctx context.Context, ns string, args ...string) *exec.Cmd {
	if ns == "" {
		return exec.CommandContext(ctx, args[0], args[1:]...)
	}
	return exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

// runLoopbackMatrixProbe has a TCP client in clientNS send a payload to target
// while a backend in backendNS listens on backendAt. It returns the source
// address the backend saw, or why the exchange failed.
func runLoopbackMatrixProbe(t *testing.T, clientNS string, backendNS string, backendAt string, target string) (string, error) {
	t.Helper()
	observedFile := filepath.Join(t.TempDir(), "observed.txt")
	ctx, cancel := context.WithTimeout(context.Background(), loopbackMatrixProbeDeadline+5*time.Second)
	defer cancel()

	backend := loopbackMatrixCommand(ctx, backendNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	backend.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleBackend,
		egressNATHelperProtocolEnv+"=tcp",
		egressNATHelperListenAddrEnv+"="+backendAt,
		egressNATHelperObservedEnv+"="+observedFile,
		egressNATHelperObservedFmtEnv+"="+egressNATObservedFmtHost,
	)
	var backendErr bytes.Buffer
	stdout, err := backend.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("backend pipe: %v", err)
	}
	backend.Stderr = &backendErr
	if err := backend.Start(); err != nil {
		return "", fmt.Errorf("backend start: %v", err)
	}
	backendDone := make(chan error, 1)
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		sent := false
		for scanner.Scan() {
			if !sent && strings.TrimSpace(scanner.Text()) == egressNATHelperReadyLine {
				ready <- true
				sent = true
			}
		}
		if !sent {
			ready <- false
		}
		backendDone <- backend.Wait()
	}()
	if ok := <-ready; !ok {
		<-backendDone
		return "", fmt.Errorf("backend did not start: %s", lastLine(backendErr.String()))
	}

	clientCtx, clientCancel := context.WithTimeout(ctx, loopbackMatrixProbeDeadline)
	defer clientCancel()
	client := loopbackMatrixCommand(clientCtx, clientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	client.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"=tcp",
		egressNATHelperTargetAddrEnv+"="+target,
	)
	output, clientErr := client.CombinedOutput()
	if clientErr != nil {
		_ = backend.Process.Kill()
		<-backendDone
		reason := lastLine(string(output))
		if errors.Is(clientCtx.Err(), context.DeadlineExceeded) {
			reason = "client timed out " + reason
		}
		if data, err := os.ReadFile(observedFile); err == nil && len(bytes.TrimSpace(data)) > 0 {
			reason += " (backend had accepted from " + strings.TrimSpace(string(data)) + ")"
		}
		return "", errors.New(reason)
	}
	select {
	case <-backendDone:
	case <-time.After(5 * time.Second):
		_ = backend.Process.Kill()
		<-backendDone
	}
	data, err := os.ReadFile(observedFile)
	if err != nil {
		return "", fmt.Errorf("client succeeded but the backend saw nothing (another listener answered?)")
	}
	return strings.TrimSpace(string(data)), nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])
	if len(line) > 140 {
		line = line[len(line)-140:]
	}
	return line
}
