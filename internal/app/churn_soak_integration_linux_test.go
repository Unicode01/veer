//go:build linux

package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	churnSoakEnableEnv      = "FORWARD_RUN_CHURN_SOAK_TEST"
	churnSoakRestartEnv     = "FORWARD_CHURN_SOAK_RESTART_CYCLES"
	churnSoakLeakCyclesEnv  = "FORWARD_CHURN_SOAK_LEAK_CYCLES"
	churnSoakPollTabsEnv    = "FORWARD_CHURN_SOAK_POLL_TABS"
	churnSoakExtraPortCount = 2
)

// churnSoakPollPaths are the requests the panel's diagnostics page refreshes.
var churnSoakPollPaths = []string{
	"/api/interfaces", "/api/host-network", "/api/tags",
	"/api/rules", "/api/sites", "/api/ranges",
	"/api/managed-networks/runtime-status", "/api/managed-networks",
	"/api/managed-network-reservations", "/api/egress-nats", "/api/ipv6-assignments",
	"/api/plugins", "/api/workers", "/api/kernel/runtime",
	"/api/rules/stats?page=1&page_size=20", "/api/ranges/stats?page=1&page_size=20",
	"/api/sites/stats", "/api/egress-nats/stats?page=1&page_size=20",
	"/api/stats/current-conns",
}

// churnSoakLogFaults are daemon log lines no churn may produce.
var churnSoakLogFaults = []string{
	"panic:", "fatal error:", "disk I/O error", "bad file descriptor",
	"use of closed", "database is locked", "illegal seek",
}

// TestDaemonChurnSoak drives a real daemon the way a busy router host does:
// guests restart (their taps go and come back), extra guests come and go,
// rules are created, toggled and deleted, and the managed network is turned
// off and on, all while the panel's diagnostics page polls the API. Phase A
// mixes in hot restarts; phase B, without restarts, checks that the daemon's
// descriptors, goroutines and threads return to where they were.
//
//	FORWARD_RUN_CHURN_SOAK_TEST=1 FORWARD_PERF_BINARY=/path/to/veer \
//	  go test ./internal/app -run '^TestDaemonChurnSoak$' -count=1 -v -timeout 30m
func TestDaemonChurnSoak(t *testing.T) {
	if os.Getenv(churnSoakEnableEnv) != "1" {
		t.Skipf("set %s=1 to run the daemon churn soak", churnSoakEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	restartCycles := envInt(churnSoakRestartEnv, 10)
	leakCycles := envInt(churnSoakLeakCyclesEnv, 20)
	tabs := envInt(churnSoakPollTabsEnv, 2)
	// A daemon stuck in shutdown is sent SIGQUIT; dump every goroutine then.
	t.Setenv("GOTRACEBACK", "all")

	harness := startEgressNATIntegrationHarness(t, "churn-soak")
	topology := harness.Topology
	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	mustEnsureIPv6AssignmentAddress(t, topology.UplinkHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	network := createManagedNetworkIntegrationNetwork(t, harness.APIBase, topology)
	c := &churnSoak{t: t, harness: &harness, networkID: network.ID}
	t.Cleanup(c.removeExtraPorts)
	c.waitNetworkRunning("after setup")

	poller := startChurnSoakPoller(harness.APIBase, tabs)
	defer poller.stop()

	// Phase A: churn with a hot restart every fifth cycle.
	for cycle := 0; cycle < restartCycles; cycle++ {
		c.cycle(cycle)
		if cycle%5 == 4 {
			c.hotRestart(poller)
		}
	}

	// Phase B: settle, take a baseline, churn, settle, compare.
	c.cycle(restartCycles)
	c.settle()
	before := c.sample()
	t.Logf("baseline: %s", before)
	for cycle := 0; cycle < leakCycles; cycle++ {
		c.cycle(restartCycles + 1 + cycle)
	}
	c.settle()
	after := c.sample()
	t.Logf("after %d cycles: %s", leakCycles, after)

	poller.stop()
	failures, total := poller.result()
	t.Logf("poller: %d requests, %d failed outside hot restarts", total, len(failures))
	poller.logLatency(t)
	for i, failure := range failures {
		if i == 10 {
			t.Errorf("... %d more", len(failures)-10)
			break
		}
		t.Errorf("poll failure: %s", failure)
	}

	if growth := after.fds - before.fds; growth > 12 {
		t.Errorf("daemon descriptors grew by %d over %d cycles (%d -> %d)", growth, leakCycles, before.fds, after.fds)
	}
	if growth := after.goroutines - before.goroutines; growth > 40 {
		t.Errorf("daemon goroutines grew by %d over %d cycles (%d -> %d)", growth, leakCycles, before.goroutines, after.goroutines)
	}
	// Threads are only logged: the Go runtime keeps the threads it started for
	// blocking system calls, so their number climbs to a plateau and stays.

	runtime := fetchDataplanePerfKernelRuntime(t, harness.APIBase)
	for _, engine := range runtime.Engines {
		if engine.Degraded || (engine.Attachments > 0 && !engine.AttachmentsHealthy) {
			t.Errorf("kernel engine %s after the churn: degraded %t (%s), %d attachments healthy %t (%s)",
				engine.Name, engine.Degraded, engine.DegradedReason, engine.Attachments, engine.AttachmentsHealthy, engine.AttachmentSummary)
		}
	}
	c.waitNetworkRunning("after the churn")

	data, err := os.ReadFile(harness.LogPath)
	if err != nil {
		t.Fatalf("read daemon log: %v", err)
	}
	for _, fault := range churnSoakLogFaults {
		if strings.Contains(string(data), fault) {
			t.Errorf("daemon log contains %q", fault)
		}
	}
	if t.Failed() {
		logForwardLogOnFailure(t, harness.LogPath)
	}
}

type churnSoak struct {
	t         *testing.T
	harness   *egressNATIntegrationHarness
	networkID int64
	nextPort  int
}

type churnSoakSample struct {
	fds, goroutines, threads int
}

func (s churnSoakSample) String() string {
	return fmt.Sprintf("%d fds, %d goroutines, %d threads", s.fds, s.goroutines, s.threads)
}

// cycle runs one round of churn and leaves the setup as it found it.
func (c *churnSoak) cycle(n int) {
	c.t.Helper()
	topology := c.harness.Topology

	// A guest restarts: its tap goes away and comes back with a new ifindex.
	mustRunDataplanePerfCmd(c.t, "ip", "link", "del", topology.ChildHostIF)
	time.Sleep(300 * time.Millisecond)
	mustRunDataplanePerfCmd(c.t, "ip", "link", "add", topology.ChildHostIF, "type", "veth", "peer", "name", topology.ClientNSIF)
	mustRunDataplanePerfCmd(c.t, "ip", "link", "set", topology.ChildHostIF, "master", topology.BridgeIF)
	mustRunDataplanePerfCmd(c.t, "ip", "link", "set", topology.ChildHostIF, "up")
	mustRunDataplanePerfCmd(c.t, "ip", "link", "set", topology.ClientNSIF, "netns", topology.ClientNS)
	mustRunDataplanePerfCmd(c.t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", topology.ClientNSIF, "up")

	// Extra guests start; each gets its own IPv6 services.
	for i := 0; i < churnSoakExtraPortCount; i++ {
		port, peer := churnSoakPortNames(i)
		mustRunDataplanePerfCmd(c.t, "ip", "link", "add", port, "type", "veth", "peer", "name", peer)
		mustRunDataplanePerfCmd(c.t, "ip", "link", "set", port, "master", topology.BridgeIF)
		mustRunDataplanePerfCmd(c.t, "ip", "link", "set", port, "up")
		mustRunDataplanePerfCmd(c.t, "ip", "link", "set", peer, "up")
	}

	// Rules come and go meanwhile, kernel and user space.
	var ids []int64
	for _, engine := range []string{ruleEngineKernel, ruleEngineUserspace} {
		c.nextPort++
		ids = append(ids, c.createRule(n, engine, 26000+c.nextPort%4000))
	}
	time.Sleep(time.Second)
	c.mustAPI(http.MethodPost, "/api/rules/toggle?id="+strconv.FormatInt(ids[0], 10), nil)
	c.mustAPI(http.MethodPost, "/api/rules/toggle?id="+strconv.FormatInt(ids[0], 10), nil)

	// The extra guests stop: their IPv6 services stop with them.
	c.removeExtraPorts()
	for _, id := range ids {
		c.mustAPI(http.MethodDelete, "/api/rules?id="+strconv.FormatInt(id, 10), nil)
	}

	// Every fourth round the whole managed network goes off and on.
	if n%4 == 3 {
		toggle := "/api/managed-networks/toggle?id=" + strconv.FormatInt(c.networkID, 10)
		c.mustAPI(http.MethodPost, toggle, nil)
		time.Sleep(time.Second)
		c.mustAPI(http.MethodPost, toggle, nil)
	}
	time.Sleep(500 * time.Millisecond)
}

func churnSoakPortNames(i int) (string, string) {
	return fmt.Sprintf("vchurn%d", i), fmt.Sprintf("vchurn%dp", i)
}

func (c *churnSoak) removeExtraPorts() {
	for i := 0; i < churnSoakExtraPortCount; i++ {
		port, _ := churnSoakPortNames(i)
		_ = exec.Command("ip", "link", "del", port).Run()
	}
}

func (c *churnSoak) createRule(n int, engine string, port int) int64 {
	c.t.Helper()
	payload := map[string]any{
		"in_interface": c.harness.Topology.UplinkHostIF, "in_ip": egressNATUplinkAddr, "in_port": port,
		"out_interface": c.harness.Topology.BridgeIF, "out_ip": managedNetworkIntegrationIPv4Lease, "out_port": port - 6000,
		"protocol": "tcp", "engine_preference": engine,
		"remark": fmt.Sprintf("churn-%d-%s", n, engine), "tag": "churn-soak",
	}
	body := c.mustAPI(http.MethodPost, "/api/rules", payload)
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ID == 0 {
		c.t.Fatalf("create %s rule: response %s (%v)", engine, body, err)
	}
	return created.ID
}

func (c *churnSoak) mustAPI(method string, path string, payload any) []byte {
	c.t.Helper()
	status, body, err := churnSoakRequest(c.harness.APIBase, method, path, payload)
	if err != nil {
		logForwardLogOnFailure(c.t, c.harness.LogPath)
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	if status != http.StatusOK {
		logForwardLogOnFailure(c.t, c.harness.LogPath)
		c.t.Fatalf("%s %s: status %d: %s", method, path, status, body)
	}
	return body
}

func churnSoakRequest(apiBase string, method string, path string, payload any) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, apiBase+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

func (c *churnSoak) hotRestart(poller *churnSoakPoller) {
	c.t.Helper()
	poller.pause()
	defer poller.resume()
	offset := hotRestartIntegrationLogSize(c.t, c.harness.LogPath)
	if err := os.WriteFile(c.harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		c.t.Fatalf("write hot restart marker: %v", err)
	}
	c.shutDownForHotRestart()
	restartManagedNetworkIntegrationForward(c.t, c.harness)
	waitForHotRestartIntegrationLog(c.t, c.harness.LogPath, offset, "kernel dataplane hot restart: adopting pinned tc maps=")
	if strings.Contains(hotRestartIntegrationLogSince(c.t, c.harness.LogPath, offset), "(cold restart)") {
		logForwardLogOnFailure(c.t, c.harness.LogPath)
		c.t.Fatal("a hot restart during the churn fell back to a cold restart")
	}
	c.waitNetworkRunning("after a hot restart")
}

// churnSoakShutdownLimit bounds a shutdown for a hot restart. The harness
// kills a daemon that is not gone after 5 seconds, which turns the hot
// restart cold, so a slower shutdown is a failure of its own.
const churnSoakShutdownLimit = 5 * time.Second

// shutDownForHotRestart stops the daemon the way systemd does and waits for it.
// A daemon that does not finish in time gets SIGQUIT, so that the Go runtime
// writes every goroutine's stack to its log, and the test fails.
func (c *churnSoak) shutDownForHotRestart() {
	c.t.Helper()
	cmd := c.harness.Cmd
	done := make(chan struct{})
	go func() {
		for processExists(cmd.Process.Pid) && !churnSoakProcessIsZombie(cmd.Process.Pid) {
			time.Sleep(20 * time.Millisecond)
		}
		close(done)
	}()
	begin := time.Now()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
		c.t.Logf("daemon shut down for a hot restart in %v", time.Since(begin).Round(time.Millisecond))
		return
	case <-time.After(churnSoakShutdownLimit):
	}
	_ = cmd.Process.Signal(syscall.SIGQUIT)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
	}
	logForwardLogOnFailure(c.t, c.harness.LogPath)
	c.t.Fatalf("the daemon did not shut down within %v for a hot restart; its goroutine stacks are at the end of the log above", churnSoakShutdownLimit)
}

func churnSoakProcessIsZombie(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	fields := strings.Fields(string(data[bytes.LastIndexByte(data, ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

// settle lets reloads, drift checks and pool trimming finish.
func (c *churnSoak) settle() {
	c.t.Helper()
	time.Sleep(managedNetworkDriftCheckEvery + 3*time.Second)
	c.waitNetworkRunning("settling")
}

func (c *churnSoak) waitNetworkRunning(phase string) {
	c.t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var last ManagedNetworkStatus
	for time.Now().Before(deadline) {
		status, body, err := churnSoakRequest(c.harness.APIBase, http.MethodGet, "/api/managed-networks", nil)
		if err == nil && status == http.StatusOK {
			var items []ManagedNetworkStatus
			if json.Unmarshal(body, &items) == nil {
				for _, item := range items {
					if item.ID != c.networkID {
						continue
					}
					last = item
					if item.ChildInterfaceCount == 1 &&
						strings.TrimSpace(item.IPv4RuntimeStatus) == "running" &&
						strings.TrimSpace(item.IPv6RuntimeStatus) == "running" {
						return
					}
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	logForwardLogOnFailure(c.t, c.harness.LogPath)
	c.t.Fatalf("managed network #%d not running %s: children %d ipv4=%q (%s) ipv6=%q (%s)", c.networkID, phase,
		last.ChildInterfaceCount, last.IPv4RuntimeStatus, last.IPv4RuntimeDetail, last.IPv6RuntimeStatus, last.IPv6RuntimeDetail)
}

func (c *churnSoak) sample() churnSoakSample {
	c.t.Helper()
	pid := c.harness.Cmd.Process.Pid
	var sample churnSoakSample
	if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err != nil {
		c.t.Fatalf("list daemon descriptors: %v", err)
	} else {
		sample.fds = len(entries)
	}
	if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid)); err != nil {
		c.t.Fatalf("list daemon threads: %v", err)
	} else {
		sample.threads = len(entries)
	}
	body := c.mustAPI(http.MethodGet, "/debug/pprof/goroutine?debug=1", nil)
	line, _, _ := bufio.NewReader(bytes.NewReader(body)).ReadLine()
	total := strings.TrimPrefix(string(line), "goroutine profile: total ")
	n, err := strconv.Atoi(strings.TrimSpace(total))
	if err != nil {
		c.t.Fatalf("goroutine profile header %q: %v", line, err)
	}
	sample.goroutines = n
	return sample
}

// churnSoakPoller refreshes the diagnostics page's requests every second from
// several tabs at once and records every failure outside a hot restart.
type churnSoakPoller struct {
	apiBase  string
	paused   atomic.Bool
	total    atomic.Int64
	mu       sync.Mutex
	failures []string
	slowest  map[string]time.Duration
	slow     []string
	quit     chan struct{}
	done     sync.WaitGroup
	once     sync.Once
}

// churnSoakSlowRequest is logged: a panel request that waits this long is
// stuck behind something.
const churnSoakSlowRequest = 3 * time.Second

func startChurnSoakPoller(apiBase string, tabs int) *churnSoakPoller {
	p := &churnSoakPoller{apiBase: apiBase, quit: make(chan struct{}), slowest: make(map[string]time.Duration)}
	for tab := 0; tab < tabs; tab++ {
		p.done.Add(1)
		go p.run()
	}
	return p
}

func (p *churnSoakPoller) run() {
	defer p.done.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
		}
		if p.paused.Load() {
			continue
		}
		var wg sync.WaitGroup
		for _, path := range churnSoakPollPaths {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				begin := time.Now()
				status, body, err := churnSoakRequest(p.apiBase, http.MethodGet, path, nil)
				took := time.Since(begin)
				if p.paused.Load() {
					return // the daemon is being replaced
				}
				p.total.Add(1)
				p.mu.Lock()
				if took > p.slowest[path] {
					p.slowest[path] = took
				}
				if took >= churnSoakSlowRequest {
					p.slow = append(p.slow, fmt.Sprintf("%s %s took %v", begin.Format("15:04:05.000"), path, took.Round(time.Millisecond)))
				}
				p.mu.Unlock()
				if err == nil && status == http.StatusOK {
					return
				}
				detail := fmt.Sprintf("%s %s: status %d", time.Now().Format("15:04:05.000"), path, status)
				if err != nil {
					detail += ": " + err.Error()
				} else {
					detail += ": " + strings.TrimSpace(string(body))
				}
				p.mu.Lock()
				p.failures = append(p.failures, detail)
				p.mu.Unlock()
			}(path)
		}
		wg.Wait()
	}
}

func (p *churnSoakPoller) pause() {
	p.paused.Store(true)
}

// resume waits a moment first: requests sent just before the pause may still
// be in flight against the daemon that went away.
func (p *churnSoakPoller) resume() {
	time.Sleep(2 * time.Second)
	p.paused.Store(false)
}

func (p *churnSoakPoller) stop() {
	p.once.Do(func() {
		close(p.quit)
		p.done.Wait()
	})
}

func (p *churnSoakPoller) logLatency(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	paths := make([]string, 0, len(p.slowest))
	for path := range p.slowest {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return p.slowest[paths[i]] > p.slowest[paths[j]] })
	for i, path := range paths {
		if i == 5 {
			break
		}
		t.Logf("slowest %s: %v", path, p.slowest[path].Round(time.Millisecond))
	}
	for _, slow := range p.slow {
		t.Logf("slow request: %s", slow)
	}
}

func (p *churnSoakPoller) result() ([]string, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.failures...), p.total.Load()
}
