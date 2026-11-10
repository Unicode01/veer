//go:build linux

package app

import (
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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// The flow churn audit drives real traffic through the running daemon, changes
// host interfaces underneath it, and then reads the kernel flow and NAT tables
// back to check that no entry refers to state that no longer exists.
const flowChurnAuditEnableEnv = "VEER_RUN_FLOW_CHURN_AUDIT"

const flowChurnHelperScript = `
import os, socket, sys, threading, time
role, addr, port, log = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
lport = int(sys.argv[5]) if len(sys.argv) > 5 else 0
def out(line):
    with open(log, 'a') as f:
        f.write("%.3f %s\n" % (time.time(), line))
if role == 'tcp-server':
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen(64); out("ready")
    def serve(c, peer):
        try:
            while True:
                data = c.recv(256)
                if not data: break
                c.sendall(("%s:%d\n" % peer).encode())
        except Exception: pass
        finally: c.close()
    while True:
        c, peer = s.accept()
        threading.Thread(target=serve, args=(c, peer), daemon=True).start()
elif role == 'udp-server':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); out("ready")
    while True:
        data, peer = s.recvfrom(2048)
        try: s.sendto(("%s:%d" % peer).encode(), peer)
        except Exception: pass
elif role == 'tcp-client':
    s = None; gen = 0; stalled = 0
    while True:
        try:
            if os.path.exists(log + ".reconnect"):
                os.remove(log + ".reconnect")
                if s is not None:
                    s.close(); s = None
            if s is None:
                s = socket.socket(); s.settimeout(1.0)
                if lport: s.bind(('', lport))
                s.connect((addr, port)); gen += 1; stalled = 0; out("connect %d" % gen)
            s.sendall(b"ping\n"); data = s.recv(256)
            if not data: raise ConnectionError("eof")
            stalled = 0
            out("ok %d %s" % (gen, data.decode().strip()))
        except socket.timeout:
            stalled += 1
            out("fail %d timeout" % gen)
            if stalled >= 25:
                out("dead %d stalled" % gen)
                try: s.close()
                except Exception: pass
                s = None; stalled = 0
        except Exception as e:
            out("dead %d %s" % (gen, type(e).__name__))
            try: s.close()
            except Exception: pass
            s = None
            time.sleep(0.3)
        time.sleep(0.2)
elif role == 'udp-client':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', lport)); s.settimeout(0.5)
    while True:
        try:
            s.sendto(b"ping", (addr, port)); data, _ = s.recvfrom(256)
            out("ok 1 %s" % data.decode().strip())
        except socket.timeout:
            out("fail 1 timeout")
        except Exception as e:
            out("fail 1 %s" % type(e).__name__)
        time.sleep(0.2)
`

type flowChurnClientState struct {
	OKs      int
	Fails    int
	Deads    int
	Connects int
	LastOK   time.Time
	Observed string
	Gen      string
}

func (s flowChurnClientState) String() string {
	age := "never"
	if !s.LastOK.IsZero() {
		age = time.Since(s.LastOK).Truncate(100 * time.Millisecond).String()
	}
	return fmt.Sprintf("ok=%d fail=%d dead=%d conn=%d gen=%s last_ok=%s observed=%s", s.OKs, s.Fails, s.Deads, s.Connects, s.Gen, age, s.Observed)
}

func readFlowChurnClientLog(path string, since time.Time) flowChurnClientState {
	var state flowChurnClientState
	data, err := os.ReadFile(path)
	if err != nil {
		return state
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		seconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		at := time.Unix(0, int64(seconds*float64(time.Second)))
		if at.Before(since) {
			continue
		}
		switch fields[1] {
		case "ok":
			state.OKs++
			state.LastOK = at
			if len(fields) >= 4 {
				state.Gen = fields[2]
				state.Observed = fields[3]
			}
		case "fail":
			state.Fails++
		case "dead":
			state.Deads++
		case "connect":
			state.Connects++
		}
	}
	return state
}

type flowChurnMaps struct {
	rules    *ebpf.Map
	flows    *ebpf.Map
	flowsOld *ebpf.Map
	nat      *ebpf.Map
	natOld   *ebpf.Map
}

func (m flowChurnMaps) Close() {
	for _, item := range []*ebpf.Map{m.rules, m.flows, m.flowsOld, m.nat, m.natOld} {
		if item != nil {
			_ = item.Close()
		}
	}
}

func maxKernelMapIDForTest() ebpf.MapID {
	var last ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(last)
		if err != nil {
			return last
		}
		last = next
	}
}

// The daemon owns the maps; the audit opens them by ID. A rebuild that fails
// leaves a newer, unused generation behind for a moment, so the oldest
// generation created since the fixture started is the one carrying traffic.
func openFlowChurnMaps(after ebpf.MapID) (flowChurnMaps, error) {
	var out flowChurnMaps
	flowKeySize := uint32(binary.Size(tcFlowKeyV4{}))
	flowValueSize := uint32(binary.Size(tcFlowValueV4{}))
	natKeySize := uint32(binary.Size(tcNATPortKeyV4{}))
	ruleKeySize := uint32(binary.Size(tcRuleKeyV4{}))
	assign := func(slot **ebpf.Map, candidate *ebpf.Map) bool {
		if *slot != nil {
			return false
		}
		*slot = candidate
		return true
	}
	id := after
	for {
		next, err := ebpf.MapGetNextID(id)
		if err != nil {
			break
		}
		id = next
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			_ = m.Close()
			continue
		}
		kept := false
		switch {
		case info.Name == "rules_v4" && m.KeySize() == ruleKeySize:
			kept = assign(&out.rules, m)
		case info.Name == "flows_v4" && m.KeySize() == flowKeySize && m.ValueSize() == flowValueSize:
			kept = assign(&out.flows, m)
		case info.Name == "flows_old_v4" && m.KeySize() == flowKeySize && m.ValueSize() == flowValueSize:
			kept = assign(&out.flowsOld, m)
		case info.Name == "nat_ports_v4" && m.KeySize() == natKeySize:
			kept = assign(&out.nat, m)
		case strings.HasPrefix(info.Name, "nat_ports_old_v") && m.KeySize() == natKeySize:
			kept = assign(&out.natOld, m)
		}
		if !kept {
			_ = m.Close()
		}
	}
	if out.rules == nil || out.flows == nil || out.nat == nil {
		out.Close()
		return flowChurnMaps{}, errors.New("daemon TC maps were not found")
	}
	return out, nil
}

type flowChurnAudit struct {
	Rules int
	Flows int
	NAT   int
	// Paths lists each rule's ingress>egress ifindex pair and flow revision,
	// which shows when a reconcile moved a rule to another path.
	Paths    []string
	Problems map[string][]string
}

func (a flowChurnAudit) count() int {
	total := 0
	for _, items := range a.Problems {
		total += len(items)
	}
	return total
}

func (a flowChurnAudit) summary() string {
	keys := make([]string, 0, len(a.Problems))
	for key := range a.Problems {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, len(a.Problems[key])))
	}
	if len(parts) == 0 {
		parts = append(parts, "clean")
	}
	return fmt.Sprintf("rules=%d[%s] flows=%d nat=%d %s", a.Rules, strings.Join(a.Paths, " "), a.Flows, a.NAT, strings.Join(parts, " "))
}

func (a flowChurnAudit) details(limit int) string {
	keys := make([]string, 0, len(a.Problems))
	for key := range a.Problems {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		items := a.Problems[key]
		for i, item := range items {
			if i >= limit {
				fmt.Fprintf(&b, "  %s: ... %d more\n", key, len(items)-limit)
				break
			}
			fmt.Fprintf(&b, "  %s: %s\n", key, item)
		}
	}
	return b.String()
}

func flowChurnIPv4(value uint32) string {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).String()
}

func describeFlowChurnEntry(key tcFlowKeyV4, value tcFlowValueV4) string {
	kind := "reply"
	if value.Flags&kernelFlowFlagFrontEntry != 0 {
		kind = "front"
	}
	return fmt.Sprintf("%s proto=%d if=%d %s:%d>%s:%d rule=%d rev=%x in_if=%d nat=%s:%d flags=%#x session=%x",
		kind, key.Proto, key.IfIndex, flowChurnIPv4(key.SrcAddr), key.SrcPort, flowChurnIPv4(key.DstAddr), key.DstPort,
		value.RuleID, value.RuleRevision, value.InIfIndex, flowChurnIPv4(value.NATAddr), value.NATPort, value.Flags, value.SessionID)
}

func auditFlowChurnTables(after ebpf.MapID) (flowChurnAudit, error) {
	audit := flowChurnAudit{Problems: map[string][]string{}}
	maps, err := openFlowChurnMaps(after)
	if err != nil {
		return audit, err
	}
	defer maps.Close()

	live := map[uint32]struct{}{}
	interfaces, err := net.Interfaces()
	if err != nil {
		return audit, err
	}
	for _, item := range interfaces {
		live[uint32(item.Index)] = struct{}{}
	}
	exists := func(ifindex uint32) bool {
		_, ok := live[ifindex]
		return ok
	}
	add := func(kind string, format string, args ...any) {
		audit.Problems[kind] = append(audit.Problems[kind], fmt.Sprintf(format, args...))
	}

	revisions := map[uint32]map[uint64]struct{}{}
	{
		var key tcRuleKeyV4
		var value tcRuleValueV4
		iter := maps.rules.Iterate()
		for iter.Next(&key, &value) {
			audit.Rules++
			if revisions[value.RuleID] == nil {
				revisions[value.RuleID] = map[uint64]struct{}{}
			}
			revisions[value.RuleID][value.Revision] = struct{}{}
			audit.Paths = append(audit.Paths, fmt.Sprintf("%d:%d>%d@%04x", value.RuleID, key.IfIndex, value.OutIfIndex, value.Revision&0xffff))
			if !exists(key.IfIndex) {
				add("rule_in_ifindex_gone", "rule=%d if=%d", value.RuleID, key.IfIndex)
			}
			if value.OutIfIndex != 0 && !exists(value.OutIfIndex) {
				add("rule_out_ifindex_gone", "rule=%d out_if=%d", value.RuleID, value.OutIfIndex)
			}
		}
		if err := iter.Err(); err != nil {
			return audit, fmt.Errorf("iterate rules: %w", err)
		}
		sort.Strings(audit.Paths)
	}

	for _, bank := range []struct {
		name  string
		flows *ebpf.Map
		nat   *ebpf.Map
	}{{"active", maps.flows, maps.nat}, {"old", maps.flowsOld, maps.natOld}} {
		if bank.flows == nil {
			continue
		}
		type pair struct {
			front, reply bool
			sample       string
		}
		sessions := map[uint64]*pair{}
		var key tcFlowKeyV4
		var value tcFlowValueV4
		iter := bank.flows.Iterate()
		for iter.Next(&key, &value) {
			audit.Flows++
			entry := bank.name + " " + describeFlowChurnEntry(key, value)
			if !exists(key.IfIndex) {
				add("flow_key_ifindex_gone", "%s", entry)
			}
			if value.InIfIndex != 0 && !exists(value.InIfIndex) {
				add("flow_in_ifindex_gone", "%s", entry)
			}
			if known, ok := revisions[value.RuleID]; !ok {
				add("flow_rule_missing", "%s", entry)
			} else if _, ok := known[value.RuleRevision]; !ok {
				add("flow_stale_revision", "%s", entry)
			}
			if value.Flags&kernelFlowFlagFullNAT != 0 {
				item := sessions[value.SessionID]
				if item == nil {
					item = &pair{sample: entry}
					sessions[value.SessionID] = item
				}
				if value.Flags&kernelFlowFlagFrontEntry != 0 {
					item.front = true
				} else {
					item.reply = true
				}
			}
		}
		if err := iter.Err(); err != nil {
			return audit, fmt.Errorf("iterate %s flows: %w", bank.name, err)
		}
		for _, item := range sessions {
			if item.front && !item.reply {
				add("front_without_reply", "%s", item.sample)
			}
			if item.reply && !item.front {
				add("reply_without_front", "%s", item.sample)
			}
		}
		if bank.nat == nil {
			continue
		}
		var natKey tcNATPortKeyV4
		var natValue tcNATPortValue
		natIter := bank.nat.Iterate()
		for natIter.Next(&natKey, &natValue) {
			audit.NAT++
			entry := fmt.Sprintf("%s nat proto=%d if=%d %s:%d rule=%d session=%x", bank.name, natKey.Proto, natKey.IfIndex, flowChurnIPv4(natKey.NATAddr), natKey.NATPort, natValue.RuleID, natValue.SessionID)
			if !exists(natKey.IfIndex) {
				add("nat_ifindex_gone", "%s", entry)
			}
			if _, ok := sessions[natValue.SessionID]; !ok {
				add("nat_without_flow", "%s", entry)
			}
		}
		if err := natIter.Err(); err != nil {
			return audit, fmt.Errorf("iterate %s nat ports: %w", bank.name, err)
		}
	}
	return audit, nil
}

type flowChurnFixture struct {
	t         *testing.T
	harness   egressNATIntegrationHarness
	mapsAfter ebpf.MapID
	dir       string
	script    string
	tcpLog    string
	udpLog    string
	procs     []*exec.Cmd
	started   time.Time
	forward   string
	// baselineGen is the TCP client's connection generation once traffic flows.
	baselineGen string
}

func (f *flowChurnFixture) helper(namespace string, args ...string) *exec.Cmd {
	f.t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", namespace, "python3", f.script}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		f.t.Fatalf("start flow churn helper %v: %v", args, err)
	}
	f.procs = append(f.procs, cmd)
	return cmd
}

func (f *flowChurnFixture) stopHelpers() {
	for _, cmd := range f.procs {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_, _ = cmd.Process.Wait()
		}
	}
	f.procs = nil
}

// Egress NAT traffic runs from the LAN client to the uplink peer. A port
// forward runs the other way: the uplink peer connects to the host address and
// the LAN client serves it.
func (f *flowChurnFixture) startServers() {
	port := strconv.Itoa(egressNATProbePort)
	namespace := f.harness.Topology.BackendNS
	if f.forward != "" {
		namespace = f.harness.Topology.ClientNS
	}
	f.helper(namespace, "tcp-server", "0.0.0.0", port, filepath.Join(f.dir, "tcp-server.log"))
	f.helper(namespace, "udp-server", "0.0.0.0", port, filepath.Join(f.dir, "udp-server.log"))
}

func (f *flowChurnFixture) startClients() {
	namespace, target, port := f.harness.Topology.ClientNS, egressNATBackendAddr, strconv.Itoa(egressNATProbePort)
	if f.forward != "" {
		namespace, target, port = f.harness.Topology.BackendNS, egressNATUplinkAddr, strconv.Itoa(egressNATForwardProbePort)
	}
	f.helper(namespace, "tcp-client", target, port, f.tcpLog)
	f.helper(namespace, "udp-client", target, port, f.udpLog, strconv.Itoa(egressNATMappingLocalPort))
}

// reconnectTCP makes the TCP client open a new connection at once instead of
// waiting until it declares the current one dead.
func (f *flowChurnFixture) reconnectTCP() {
	f.t.Helper()
	if err := os.WriteFile(f.tcpLog+".reconnect", nil, 0o600); err != nil {
		f.t.Fatalf("ask the TCP client to reconnect: %v", err)
	}
}

func (f *flowChurnFixture) status() string {
	f.t.Helper()
	if f.forward == "" {
		status := "absent"
		for _, item := range listEgressNATIntegrationStatuses(f.t, f.harness.APIBase) {
			status = fmt.Sprintf("%s/%s/%s", item.Status, item.EffectiveEngine, item.EffectiveKernelEngine)
			if reason := strings.TrimSpace(item.KernelReason + " " + item.FallbackReason); reason != "" {
				status += " (" + reason + ")"
			}
		}
		return status
	}
	output, err := flowChurnAPI(http.MethodGet, f.harness.APIBase+"/api/rules", "")
	if err != nil {
		return "unavailable"
	}
	var items []RuleStatus
	if err := json.Unmarshal(output, &items); err != nil || len(items) == 0 {
		return "absent"
	}
	item := items[0]
	status := fmt.Sprintf("%s/%s/%s", item.Status, item.EffectiveEngine, item.EffectiveKernelEngine)
	if reason := strings.TrimSpace(item.KernelReason + " " + item.FallbackReason + " " + item.RuntimeError); reason != "" {
		status += " (" + reason + ")"
	}
	return status
}

func (f *flowChurnFixture) snapshot(label string, since time.Time) flowChurnAudit {
	f.t.Helper()
	audit, err := auditFlowChurnTables(f.mapsAfter)
	if err != nil {
		f.t.Logf("[%6.1fs] %-28s audit unavailable: %v", time.Since(f.started).Seconds(), label, err)
		return audit
	}
	status := f.status()
	f.t.Logf("[%6.1fs] %-28s status=%s | %s | tcp{%s} udp{%s}", time.Since(f.started).Seconds(), label, status, audit.summary(),
		readFlowChurnClientLog(f.tcpLog, since), readFlowChurnClientLog(f.udpLog, since))
	return audit
}

type flowChurnExpectation int

const (
	// flowChurnObserve only records what the daemon does while state is away.
	flowChurnObserve flowChurnExpectation = iota
	// flowChurnClean needs consistent tables; traffic is expected to be down.
	flowChurnClean
	// flowChurnRecover needs consistent tables and working traffic. The TCP
	// client may have had to reconnect.
	flowChurnRecover
	// flowChurnSeamless additionally needs the TCP connection that existed
	// before the step to still be the one carrying traffic.
	flowChurnSeamless
)

// settle polls until the step's expectation holds or the wait runs out. It
// does not succeed before minimum has passed, so that a seamless step also
// covers changes the daemon makes a while after the step.
func (f *flowChurnFixture) settle(label string, since time.Time, wait time.Duration, expect flowChurnExpectation, wantObserved string, minimum time.Duration) bool {
	f.t.Helper()
	deadline := time.Now().Add(wait)
	// One good sample can be a moment between two reconciles.
	const stableSamples = 3
	stable := 0
	for {
		audit := f.snapshot(label, since)
		tcp := readFlowChurnClientLog(f.tcpLog, since)
		udp := readFlowChurnClientLog(f.udpLog, since)
		fresh := func(state flowChurnClientState) bool {
			if state.LastOK.IsZero() || time.Since(state.LastOK) > 1500*time.Millisecond {
				return false
			}
			return wantObserved == "" || strings.HasPrefix(state.Observed, wantObserved+":")
		}
		clean := audit.Problems != nil && audit.count() == 0
		done := false
		switch expect {
		case flowChurnClean:
			done = clean
		case flowChurnRecover:
			done = clean && fresh(tcp) && fresh(udp)
		case flowChurnSeamless:
			done = clean && fresh(tcp) && fresh(udp)
			if tcp.Gen != "" && tcp.Gen != f.baselineGen {
				f.t.Logf("%s: the TCP connection did not survive (connection %s replaced %s)", label, tcp.Gen, f.baselineGen)
				return false
			}
		}
		if done && time.Since(since) < minimum {
			done = false
			stable = stableSamples - 1
		}
		if done {
			stable++
		} else {
			stable = 0
		}
		if stable >= stableSamples {
			return true
		}
		if time.Now().After(deadline) {
			if details := audit.details(6); details != "" {
				f.t.Logf("%s: table state after %s:\n%s", label, wait, details)
			}
			return expect == flowChurnObserve
		}
		time.Sleep(time.Second)
	}
}

func newFlowChurnFixture(t *testing.T, name string, childScope bool, sourceIP string, forward string) *flowChurnFixture {
	t.Helper()
	t.Setenv(forwardKernelMaintenanceIntervalEnv, "1000")
	before := maxKernelMapIDForTest()
	harness := startEgressNATIntegrationHarness(t, name)
	dir := t.TempDir()
	script := filepath.Join(dir, "helper.py")
	if err := os.WriteFile(script, []byte(flowChurnHelperScript), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &flowChurnFixture{t: t, harness: harness, mapsAfter: before, dir: dir, script: script,
		tcpLog: filepath.Join(dir, "tcp-client.log"), udpLog: filepath.Join(dir, "udp-client.log"), started: time.Now(), forward: forward}
	t.Cleanup(f.stopHelpers)

	child := ""
	if childScope {
		child = harness.Topology.ChildHostIF
	}
	switch {
	case forward != "":
		createEgressNATForwardRule(t, harness.APIBase, harness.Topology, ruleEngineKernel, "tcp+udp", forward == "transparent", "flow churn "+forward)
		waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after forward rule enable", func(entries int) bool { return entries > 0 })
	case sourceIP == egressNATUplinkAddr:
		createFlowChurnEgressNAT(t, harness, child, sourceIP)
		waitForEgressNATIntegrationRunningStatus(t, harness.APIBase, harness.Topology, child)
	default:
		createFlowChurnEgressNAT(t, harness, child, sourceIP)
		waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after dynamic source enable", func(entries int) bool { return entries > 0 })
	}
	f.startServers()
	f.startClients()
	if !f.settle("baseline", f.started, 20*time.Second, flowChurnRecover, "", 0) {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("baseline traffic or tables did not settle")
	}
	f.baselineGen = readFlowChurnClientLog(f.tcpLog, f.started).Gen
	return f
}

func createFlowChurnEgressNAT(t *testing.T, harness egressNATIntegrationHarness, child string, sourceIP string) {
	t.Helper()
	if sourceIP == egressNATUplinkAddr {
		createEgressNATIntegrationEntryForScopeWithProtocol(t, harness.APIBase, harness.Topology, child, "tcp+udp+icmp")
		return
	}
	body := fmt.Sprintf(`{"parent_interface":%q,"child_interface":%q,"out_interface":%q,"out_source_ip":%q,"protocol":"tcp+udp+icmp"}`,
		harness.Topology.BridgeIF, child, harness.Topology.UplinkHostIF, sourceIP)
	if output, err := flowChurnAPI(http.MethodPost, harness.APIBase+"/api/egress-nats", body); err != nil {
		t.Fatalf("create egress NAT: %v\n%s", err, output)
	}
}

func flowChurnAPI(method string, url string, body string) ([]byte, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	output, err := io.ReadAll(resp.Body)
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return output, err
}

func recreateFlowChurnUplink(t *testing.T, topology egressNATIntegrationTopology, uplinkAddr string) {
	t.Helper()
	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.UplinkHostIF, "type", "veth", "peer", "name", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", uplinkAddr+"/24", "dev", topology.UplinkHostIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.UplinkHostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BackendNSIF, "netns", topology.BackendNS)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "addr", "add", egressNATBackendAddr+"/24", "dev", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", topology.BackendNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "route", "replace", "default", "via", uplinkAddr, "dev", topology.BackendNSIF)
}

func recreateFlowChurnChild(t *testing.T, topology egressNATIntegrationTopology) {
	t.Helper()
	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.ChildHostIF, "type", "veth", "peer", "name", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ChildHostIF, "master", topology.BridgeIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ChildHostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ClientNSIF, "netns", topology.ClientNS)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "addr", "add", egressNATClientAddr+"/24", "dev", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", topology.ClientNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "route", "replace", "default", "via", egressNATBridgeAddr, "dev", topology.ClientNSIF)
}

// forgetFlowChurnMember stops the bridge from learning the backend behind the
// child, flushes what it learned and adds an unrelated interface so that the
// daemon reconciles. The member path no longer resolves through the bridge,
// while the backend is still where it was.
func forgetFlowChurnMember(t *testing.T, f *flowChurnFixture) {
	t.Helper()
	topology := f.harness.Topology
	mustRunDataplanePerfCmd(t, "ip", "link", "set", "dev", topology.ChildHostIF, "type", "bridge_slave", "learning", "off")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", "dev", topology.ChildHostIF, "type", "bridge_slave", "fdb_flush")
	const dummy = "fwchurn-dmy"
	mustRunDataplanePerfCmd(t, "ip", "link", "add", dummy, "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", dummy).Run() })
	mustRunDataplanePerfCmd(t, "ip", "link", "set", dummy, "up")
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(f.harness.LogPath); err == nil && strings.Contains(string(data), "keeps its member port") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("no reconcile re-evaluated the member path after the bridge forgot the backend")
}

func TestKernelFlowTablesAcrossInterfaceChurn(t *testing.T) {
	if os.Getenv(flowChurnAuditEnableEnv) != "1" {
		t.Skipf("set %s=1 to run the interface churn flow table audit", flowChurnAuditEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Fatal("the interface churn flow table audit requires root")
	}
	for _, tool := range []string{"ip", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required tool %s: %v", tool, err)
		}
	}

	type step struct {
		name   string
		run    func(t *testing.T, f *flowChurnFixture)
		wait   time.Duration
		expect flowChurnExpectation
		// observed pins the source address the far end must see afterwards.
		observed string
		// minimum keeps the step observed for at least this long.
		minimum time.Duration
	}
	const (
		away    = 12 * time.Second
		back    = 40 * time.Second
		expired = 75 * time.Second
	)
	topologyOf := func(f *flowChurnFixture) egressNATIntegrationTopology { return f.harness.Topology }
	removeUplinkAddr := func(t *testing.T, f *flowChurnFixture) {
		mustRunDataplanePerfCmd(t, "ip", "addr", "del", egressNATUplinkAddr+"/24", "dev", topologyOf(f).UplinkHostIF)
	}
	restoreUplinkAddr := func(t *testing.T, f *flowChurnFixture) {
		mustRunDataplanePerfCmd(t, "ip", "addr", "add", egressNATUplinkAddr+"/24", "dev", topologyOf(f).UplinkHostIF)
		seedEgressNATIntegrationNeighbor(t, topologyOf(f))
	}
	deleteChild := func(t *testing.T, f *flowChurnFixture) {
		mustRunDataplanePerfCmd(t, "ip", "link", "del", topologyOf(f).ChildHostIF)
	}
	recreateChild := func(t *testing.T, f *flowChurnFixture) {
		recreateFlowChurnChild(t, topologyOf(f))
		seedEgressNATIntegrationNeighbor(t, topologyOf(f))
	}
	setLink := func(name func(egressNATIntegrationTopology) string, state string) func(*testing.T, *flowChurnFixture) {
		return func(t *testing.T, f *flowChurnFixture) {
			mustRunDataplanePerfCmd(t, "ip", "link", "set", name(topologyOf(f)), state)
			if state == "up" {
				seedEgressNATIntegrationNeighbor(t, topologyOf(f))
			}
		}
	}
	uplink := func(topology egressNATIntegrationTopology) string { return topology.UplinkHostIF }
	bridge := func(topology egressNATIntegrationTopology) string { return topology.BridgeIF }
	child := func(topology egressNATIntegrationTopology) string { return topology.ChildHostIF }

	scenarios := []struct {
		name       string
		childScope bool
		sourceIP   string
		forward    string
		steps      []step
	}{
		// A link that only loses carrier keeps its ifindex and addresses, so
		// established connections must carry on.
		{name: "uplink_link_flap", childScope: true, sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "uplink down", run: setLink(uplink, "down"), wait: away},
			{name: "uplink up", run: setLink(uplink, "up"), wait: back, expect: flowChurnSeamless},
		}},
		{name: "bridge_link_flap", sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "bridge down", run: setLink(bridge, "down"), wait: away},
			{name: "bridge up", run: setLink(bridge, "up"), wait: back, expect: flowChurnSeamless},
		}},
		{name: "child_link_flap", childScope: true, sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "child down", run: setLink(child, "down"), wait: away},
			{name: "child up", run: setLink(child, "up"), wait: back, expect: flowChurnSeamless},
		}},
		// A child that leaves its bridge and rejoins keeps its ifindex: the NAT
		// bound to it must come back by itself and keep the old connections.
		{name: "child_reparent", childScope: true, sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "detach child from bridge", run: func(t *testing.T, f *flowChurnFixture) {
				mustRunDataplanePerfCmd(t, "ip", "link", "set", topologyOf(f).ChildHostIF, "nomaster")
			}, wait: away},
			{name: "attach child to bridge", run: func(t *testing.T, f *flowChurnFixture) {
				mustRunDataplanePerfCmd(t, "ip", "link", "set", topologyOf(f).ChildHostIF, "master", topologyOf(f).BridgeIF)
				seedEgressNATIntegrationNeighbor(t, topologyOf(f))
			}, wait: back, expect: flowChurnSeamless},
		}},
		// A recreated child has a new ifindex. Nothing keyed by the old one may
		// stay behind, and the NAT must serve the new one without a reload.
		{name: "child_recreate_child_scope", childScope: true, sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "delete child", run: deleteChild, wait: away},
			{name: "recreate child", run: recreateChild, wait: back, expect: flowChurnRecover, observed: egressNATUplinkAddr},
		}},
		{name: "child_recreate_parent_scope", sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "delete child", run: deleteChild, wait: away},
			{name: "recreate child", run: recreateChild, wait: back, expect: flowChurnRecover, observed: egressNATUplinkAddr},
		}},
		// Flows of rules that never return leave after the drain grace instead
		// of waiting for their idle timeouts.
		{name: "child_delete_without_return", childScope: true, sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "delete child", run: deleteChild, wait: expired, expect: flowChurnClean},
		}},
		// Losing the exit address turns the NAT into a drop guard. The flows
		// wait for the address, so connections carry on when it comes back.
		{name: "uplink_addr_flap_static_source", childScope: true, sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "remove uplink address", run: removeUplinkAddr, wait: away},
			{name: "restore uplink address", run: restoreUplinkAddr, wait: back, expect: flowChurnSeamless, observed: egressNATUplinkAddr},
		}},
		{name: "uplink_addr_change_dynamic_source", childScope: true, steps: []step{
			{name: "replace uplink address", run: func(t *testing.T, f *flowChurnFixture) {
				topology := topologyOf(f)
				mustRunDataplanePerfCmd(t, "ip", "addr", "del", egressNATUplinkAddr+"/24", "dev", topology.UplinkHostIF)
				mustRunDataplanePerfCmd(t, "ip", "addr", "add", "198.19.0.3/24", "dev", topology.UplinkHostIF)
				mustRunDataplanePerfCmd(t, "ip", "route", "replace", egressNATBackendAddr+"/32", "dev", topology.UplinkHostIF, "src", "198.19.0.3")
			}, wait: back, expect: flowChurnRecover, observed: "198.19.0.3"},
		}},
		{name: "uplink_recreate", childScope: true, sourceIP: egressNATUplinkAddr, steps: []step{
			{name: "delete uplink", run: func(t *testing.T, f *flowChurnFixture) {
				mustRunDataplanePerfCmd(t, "ip", "link", "del", topologyOf(f).UplinkHostIF)
			}, wait: away},
			{name: "recreate uplink", run: func(t *testing.T, f *flowChurnFixture) {
				recreateFlowChurnUplink(t, topologyOf(f), egressNATUplinkAddr)
				seedEgressNATIntegrationNeighbor(t, topologyOf(f))
			}, wait: back, expect: flowChurnRecover, observed: egressNATUplinkAddr},
		}},
		// Port forwards.
		{name: "forward_fullnat_uplink_addr_flap", forward: "fullnat", steps: []step{
			{name: "remove uplink address", run: removeUplinkAddr, wait: away},
			{name: "restore uplink address", run: restoreUplinkAddr, wait: back, expect: flowChurnSeamless},
		}},
		{name: "forward_fullnat_bridge_flap", forward: "fullnat", steps: []step{
			{name: "bridge down", run: setLink(bridge, "down"), wait: away},
			{name: "bridge up", run: setLink(bridge, "up"), wait: back, expect: flowChurnSeamless},
		}},
		// A recreated member is not learned at once: sessions start on the
		// bridge path. They must survive the member path becoming resolvable.
		{name: "forward_fullnat_child_recreate", forward: "fullnat", steps: []step{
			{name: "delete child", run: deleteChild, wait: away},
			{name: "recreate child", run: func(t *testing.T, f *flowChurnFixture) {
				recreateChild(t, f)
				// Connect while the new member is still unlearned.
				f.reconnectTCP()
			}, wait: back, expect: flowChurnRecover},
			{name: "member path resolvable", run: func(*testing.T, *flowChurnFixture) {}, wait: back + 10*time.Second, expect: flowChurnSeamless, minimum: 30 * time.Second},
		}},
		// The bridge forgets an idle backend while its sessions are open. A
		// reconcile must not move them off the member path they use.
		{name: "forward_fullnat_member_forgotten", forward: "fullnat", steps: []step{
			{name: "forget member and reconcile", run: forgetFlowChurnMember, wait: back + 10*time.Second, expect: flowChurnSeamless, minimum: 30 * time.Second},
		}},
		{name: "forward_transparent_uplink_addr_flap", forward: "transparent", steps: []step{
			{name: "remove uplink address", run: removeUplinkAddr, wait: away},
			{name: "restore uplink address", run: restoreUplinkAddr, wait: back, expect: flowChurnSeamless},
		}},
		{name: "forward_transparent_child_recreate", forward: "transparent", steps: []step{
			{name: "delete child", run: deleteChild, wait: away},
			{name: "recreate child", run: recreateChild, wait: back, expect: flowChurnRecover},
		}},
	}

	only := strings.TrimSpace(os.Getenv("VEER_FLOW_CHURN_SCENARIO"))
	for _, scenario := range scenarios {
		if only != "" && only != scenario.name {
			continue
		}
		t.Run(scenario.name, func(t *testing.T) {
			f := newFlowChurnFixture(t, scenario.name, scenario.childScope, scenario.sourceIP, scenario.forward)
			failed := false
			for _, item := range scenario.steps {
				since := time.Now()
				t.Logf("--- step: %s", item.name)
				item.run(t, f)
				if !f.settle(item.name, since, item.wait, item.expect, item.observed, item.minimum) {
					failed = true
				} else if item.expect >= flowChurnRecover {
					// Later steps measure continuity from the connection that
					// carries traffic now.
					f.baselineGen = readFlowChurnClientLog(f.tcpLog, since).Gen
				}
			}
			if failed {
				logForwardLogOnFailure(t, f.harness.LogPath)
				t.Errorf("flow tables or traffic did not settle after interface churn")
			}
		})
	}
}
