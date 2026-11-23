//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// TestFirewallPluginLinuxIntegration runs the bundled firewall plugin in a
// real daemon: policies go through the HTTP API and the confirmation flow,
// and TCP connections from two network namespaces show the verdicts. One
// client reaches the host over a veth (native XDP on the host end); the
// other through a bridge (no native XDP: the firewall's tc fallback runs at
// the bridge's TC ingress, ahead of the core).
func TestFirewallPluginLinuxIntegration(t *testing.T) {
	if os.Getenv("FORWARD_RUN_PLUGIN_INTEGRATION_TEST") != "1" {
		t.Skip("set FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 to run the firewall plugin integration test")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for namespaces and XDP")
	}
	root := findRepoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "plugins", "firewall", "firewall.o")); err != nil {
		t.Skipf("build plugins/firewall first: %v", err)
	}
	suffix := strconv.Itoa(os.Getpid() % 100000)
	nsDirect, nsBridged := "fwfa"+suffix, "fwfb"+suffix
	hostDirect := truncateIfName("fwfh" + suffix)
	hostBridgePort := truncateIfName("fwfp" + suffix)
	bridge := truncateIfName("fwfbr" + suffix)
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	t.Cleanup(func() {
		for _, ns := range []string{nsDirect, nsBridged} {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
		for _, link := range []string{hostDirect, hostBridgePort, bridge} {
			_ = exec.Command("ip", "link", "del", link).Run()
		}
	})
	run("ip", "netns", "add", nsDirect)
	run("ip", "netns", "add", nsBridged)
	run("ip", "link", "add", hostDirect, "type", "veth", "peer", "name", "c0", "netns", nsDirect)
	run("ip", "address", "add", "10.199.0.1/24", "dev", hostDirect)
	run("ip", "-6", "address", "add", "fd99::1/64", "dev", hostDirect, "nodad")
	run("ip", "link", "set", hostDirect, "up")
	run("ip", "-n", nsDirect, "address", "add", "10.199.0.2/24", "dev", "c0")
	run("ip", "-n", nsDirect, "-6", "address", "add", "fd99::2/64", "dev", "c0", "nodad")
	run("ip", "-n", nsDirect, "link", "set", "c0", "up")
	run("ip", "-n", nsDirect, "link", "set", "lo", "up")
	run("ip", "link", "add", bridge, "type", "bridge")
	run("ip", "address", "add", "10.198.0.1/24", "dev", bridge)
	run("ip", "link", "set", bridge, "up")
	run("ip", "link", "add", hostBridgePort, "type", "veth", "peer", "name", "c0", "netns", nsBridged)
	run("ip", "link", "set", hostBridgePort, "master", bridge, "up")
	run("ip", "-n", nsBridged, "address", "add", "10.198.0.2/24", "dev", "c0")
	run("ip", "-n", nsBridged, "link", "set", "c0", "up")
	run("ip", "-n", nsBridged, "link", "set", "lo", "up")

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	reach := func(ns, addr string) bool {
		target := net.JoinHostPort(addr, strconv.Itoa(port))
		host, p, _ := net.SplitHostPort(target)
		script := fmt.Sprintf("exec 3<>/dev/tcp/%s/%s", host, p)
		return exec.Command("ip", "netns", "exec", ns, "timeout", "2", "bash", "-c", script).Run() == nil
	}
	expect := func(step string, want map[string]bool) {
		t.Helper()
		got := map[string]bool{
			"direct":    reach(nsDirect, "10.199.0.1"),
			"direct v6": reach(nsDirect, "fd99::1"),
			"bridged":   reach(nsBridged, "10.198.0.1"),
		}
		for name, w := range want {
			if got[name] != w {
				t.Fatalf("%s: %s reachable = %t, want %t (all: %v)", step, name, got[name], w, got)
			}
		}
	}
	expect("before the firewall", map[string]bool{"direct": true, "direct v6": true, "bridged": true})

	work := t.TempDir()
	copyDirForTest(t, filepath.Join(root, "plugins", "firewall"), filepath.Join(work, "plugins", "firewall"))
	enabled, disabled := true, false
	cfg := Config{WebBind: "127.0.0.1", WebPort: freeTCPPort(t), WebToken: egressNATTestToken,
		PluginAdminToken: "firewall-integration-admin", MaxWorkers: 1, DefaultEngine: ruleEngineKernel,
		KernelEngineOrder: []string{kernelEngineTC}, PluginsDir: filepath.Join(work, "plugins"),
		PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled,
		PluginsMinSandboxLevel: pluginSandboxLevelNone, PluginsRequireSigned: &disabled}
	data, _ := json.Marshal(cfg)
	configPath := filepath.Join(work, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(work, "veer.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	binary := buildDataplanePerfBinary(t, root)
	marker := filepath.Join(work, "hot-restart")
	env := append(os.Environ(),
		veerHotRestartMarkerEnv+"="+marker,
		veerBPFStateDirEnv+"="+requireKernelHotRestartBPFStateRoot(t),
		veerRuntimeStateDirEnv+"="+filepath.Join(work, "state"))
	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.WebPort)
	var cmd *exec.Cmd
	stop := func() {
		if cmd == nil || cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		cmd = nil
	}
	start := func() {
		t.Helper()
		cmd = exec.Command(binary, "--config", configPath)
		cmd.Dir = work
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = logFile, logFile
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waitForEgressNATIntegrationAPIWithTimeout(t, base, cmd, logPath, 45*time.Second)
		waitForEgressNATIntegrationPluginAction(t, base, cmd, logPath, "firewall", "apply")
	}
	t.Cleanup(stop)
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("daemon log:\n%s", b)
		}
	})
	start()

	api := func(method, path string, payload any) []byte {
		t.Helper()
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cfg.WebToken)
		req.Header.Set(pluginAdminTokenHeader, cfg.PluginAdminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			t.Fatalf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, out)
		}
		return out
	}
	action := func(id string) map[string]any {
		t.Helper()
		payload := map[string]any{}
		if id == "apply" {
			// Accept what the draft warns about, as the page does once the
			// user agrees; the listener's port can fall in a reply port range.
			var check struct {
				Result struct {
					Errors []string `json:"errors"`
					Token  string   `json:"token"`
				} `json:"result"`
			}
			if err := json.Unmarshal(api("POST", "/api/plugins/firewall/actions/check", map[string]any{"payload": map[string]any{}}), &check); err != nil {
				t.Fatalf("check: %v", err)
			}
			if len(check.Result.Errors) > 0 {
				t.Fatalf("check: %v", check.Result.Errors)
			}
			if check.Result.Token != "" {
				payload["accept_warnings"] = check.Result.Token
			}
		}
		var response struct {
			Result map[string]any `json:"result"`
		}
		_ = json.Unmarshal(api("POST", "/api/plugins/firewall/actions/"+id, map[string]any{"payload": payload}), &response)
		return response.Result
	}
	// dropEvents waits for drop log entries that match (the ring reader and
	// its worker deliver them asynchronously).
	dropEvents := func(match func(map[string]any) bool) []any {
		t.Helper()
		var events []any
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			var response struct {
				Result []any `json:"result"`
			}
			_ = json.Unmarshal(api("POST", "/api/plugins/firewall/actions/events", map[string]any{"payload": map[string]any{}}), &response)
			events = response.Result
			for _, raw := range events {
				if match(raw.(map[string]any)) {
					return events
				}
			}
		}
		t.Fatalf("no matching drop log entry: %v", events)
		return nil
	}
	putPolicy := func(sources []map[string]string) {
		t.Helper()
		if sources == nil {
			sources = []map[string]string{}
		}
		api("PUT", "/api/plugins/firewall/resources/policies/svc", map[string]any{
			"data": map[string]any{"name": "svc", "protocol": "tcp", "ports": []string{strconv.Itoa(port)},
				"default_action": "drop", "sources": sources},
			"enabled": true,
		})
	}

	api("POST", "/api/plugins/firewall/resources/settings", map[string]any{"key": "default", "enabled": true,
		"data": map[string]any{"interfaces": []string{hostDirect, bridge}, "confirm_timeout_seconds": 30}})
	api("POST", "/api/plugins/firewall/resources/policies", map[string]any{"key": "svc", "enabled": true,
		"data": map[string]any{"name": "svc", "protocol": "tcp", "ports": []string{strconv.Itoa(port)}, "default_action": "drop"}})

	// Everything to the port is dropped, over both attach modes.
	action("apply")
	status := action("status")
	if status["pending"] == nil {
		t.Fatalf("status after apply: %v", status)
	}
	expect("drop all", map[string]bool{"direct": false, "direct v6": false, "bridged": false})
	// The drop log works from the first apply: binding the hook from the
	// control script starts the ring reader, no restart needed.
	dropEvents(func(event map[string]any) bool {
		return event["reason"] == "acl" && event["port"].(float64) == float64(port) && event["policy"] == "svc"
	})
	action("confirm")
	direct, err := netlink.LinkByName(hostDirect)
	if err != nil {
		t.Fatal(err)
	}
	if xdp := direct.Attrs().Xdp; xdp == nil || !xdp.Attached || xdp.AttachMode != nl.XDP_ATTACHED_DRV {
		t.Fatalf("%s XDP = %+v, want driver mode", hostDirect, xdp)
	}
	bridgeLink, err := netlink.LinkByName(bridge)
	if err != nil {
		t.Fatal(err)
	}
	if xdp := bridgeLink.Attrs().Xdp; xdp != nil && xdp.Attached {
		t.Fatalf("%s XDP = %+v, want none: the bridge runs the tc fallback", bridge, xdp)
	}
	if first, err := firewallPerfFirstTCProgram(bridge); err != nil || first != "tc_firewall" {
		t.Fatalf("%s first TC ingress program = %q (err %v), want tc_firewall ahead of the core", bridge, first, err)
	}
	attachments, _ := action("status")["attachments"].(map[string]any)
	modes := map[string]string{}
	for _, raw := range func() []any { list, _ := attachments["interfaces"].([]any); return list }() {
		item, _ := raw.(map[string]any)
		name, _ := item["interface"].(string)
		mode, _ := item["mode"].(string)
		if attached, _ := item["attached"].(bool); attached {
			modes[name] = mode
		}
	}
	if modes[hostDirect] != "driver" || modes[bridge] != "tc" {
		t.Fatalf("status attachments = %v, want %s driver and %s tc", attachments, hostDirect, bridge)
	}

	// Only the direct client's IPv4 address.
	putPolicy([]map[string]string{{"cidr": "10.199.0.2", "action": "allow"}})
	action("apply")
	action("confirm")
	expect("allow one source", map[string]bool{"direct": true, "direct v6": false, "bridged": false})

	// A Veer hot restart: the successor takes over the plugin's maps, so the
	// blocked client never gets through, not even while the new dispatcher
	// replaces the old one, and the counters go on.
	policyDrops := func() float64 {
		t.Helper()
		policies, _ := action("status")["policies"].([]any)
		if len(policies) != 1 {
			t.Fatalf("status policies = %v", policies)
		}
		counters, _ := policies[0].(map[string]any)["counters"].(map[string]any)
		if counters == nil {
			t.Fatalf("no counters: %v", policies[0])
		}
		return counters["drop"].(float64)
	}
	dropsBefore := policyDrops()
	leaks, tries := filepath.Join(work, "leaks"), filepath.Join(work, "tries")
	probe := fmt.Sprintf("while :; do echo t >> %s; if timeout 0.2 bash -c 'exec 3<>/dev/tcp/10.198.0.1/%d' 2>/dev/null; then echo ok >> %s; fi; sleep 0.02; done", tries, port, leaks)
	var probers []*exec.Cmd
	for i := 0; i < 6; i++ {
		prober := exec.Command("ip", "netns", "exec", nsBridged, "bash", "-c", probe)
		if err := prober.Start(); err != nil {
			t.Fatal(err)
		}
		probers = append(probers, prober)
	}
	stopProbers := func() {
		for _, prober := range probers {
			_ = prober.Process.Kill()
			_ = prober.Wait()
		}
		probers = nil
	}
	t.Cleanup(stopProbers)
	time.Sleep(time.Second)
	if err := os.WriteFile(marker, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	stop()
	start()
	time.Sleep(3 * time.Second)
	stopProbers()
	countLines := func(path string) int {
		data, _ := os.ReadFile(path)
		return strings.Count(string(data), "\n")
	}
	if n := countLines(tries); n < 50 {
		t.Fatalf("the probes ran only %d attempts across the hot restart", n)
	}
	if n := countLines(leaks); n != 0 {
		t.Fatalf("%d connections from a blocked source got through during the hot restart", n)
	}
	expect("after hot restart", map[string]bool{"direct": true, "direct v6": false, "bridged": false})
	if dropsAfter := policyDrops(); dropsAfter < dropsBefore {
		t.Fatalf("drop counter went from %v to %v across the hot restart", dropsBefore, dropsAfter)
	}
	if logged, _ := os.ReadFile(logPath); !strings.Contains(string(logged), "firewall/firewall kept state maps") {
		t.Fatal("the successor did not report keeping the firewall's state maps")
	}

	// An unconfirmed rule set that blocks it too is undone by rollback.
	putPolicy(nil)
	action("apply")
	expect("unconfirmed drop all", map[string]bool{"direct": false})
	action("rollback")
	expect("after rollback", map[string]bool{"direct": true, "bridged": false})

	status = action("status")
	policies, _ := status["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("status policies = %v", status["policies"])
	}
	counters, _ := policies[0].(map[string]any)["counters"].(map[string]any)
	if counters == nil || counters["drop"].(float64) == 0 || counters["pass"].(float64) == 0 {
		t.Fatalf("counters = %v, want both drops and passes", counters)
	}

	// SYN limit: 5 new connections a minute per source, then a 30 s ban.
	api("PUT", "/api/plugins/firewall/resources/policies/svc", map[string]any{"enabled": true,
		"data": map[string]any{"name": "svc", "protocol": "tcp", "ports": []string{strconv.Itoa(port)}, "default_action": "allow",
			"syn_limit": map[string]any{"max_new": 5, "window_seconds": 60, "ban_seconds": 30}}})
	action("apply")
	action("confirm")
	// Only the bridged client connects here: every connection counts, and
	// expect() would spend the other clients' allowance too.
	for i := 0; i < 5; i++ {
		if !reach(nsBridged, "10.198.0.1") {
			t.Fatalf("connection %d within the limit failed", i+1)
		}
	}
	if reach(nsBridged, "10.198.0.1") {
		t.Fatal("the 6th connection in the window got through")
	}
	if !reach(nsDirect, "10.199.0.1") {
		t.Fatal("another source was limited too")
	}
	bannedSources := func() []string {
		t.Helper()
		items, _ := action("bans")["items"].([]any)
		var sources []string
		for _, raw := range items {
			item := raw.(map[string]any)
			if item["policy"] != "svc" {
				t.Fatalf("ban of another policy: %v", item)
			}
			if left, ok := item["remaining_seconds"].(float64); ok && (left <= 0 || left > 30) {
				t.Fatalf("ban time left = %v", left)
			}
			sources = append(sources, item["source"].(string))
		}
		return sources
	}
	if got := bannedSources(); len(got) != 1 || got[0] != "10.198.0.2/32" {
		t.Fatalf("bans = %v, want the bridged client", got)
	}
	// The drop log reaches the page through the ring and its worker.
	dropEvents(func(event map[string]any) bool {
		return event["reason"] == "rate" && event["source"] == "10.198.0.2" && event["port"].(float64) == float64(port) && event["policy"] == "svc"
	})

	// The ban outlives a hot restart: the successor keeps fw_ban.
	if err := os.WriteFile(marker, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	stop()
	start()
	expect("banned after hot restart", map[string]bool{"bridged": false, "direct": true})
	if got := bannedSources(); len(got) != 1 {
		t.Fatalf("bans after hot restart = %v", got)
	}
	var unbanned struct {
		Result map[string]any `json:"result"`
	}
	_ = json.Unmarshal(api("POST", "/api/plugins/firewall/actions/unban", map[string]any{"payload": map[string]any{"all": true}}), &unbanned)
	expect("unbanned", map[string]bool{"bridged": true})
	if got := bannedSources(); len(got) != 0 {
		t.Fatalf("bans after unban = %v", got)
	}

	// No interface left: the hook detaches and nothing filters.
	api("PUT", "/api/plugins/firewall/resources/settings/default", map[string]any{"enabled": true,
		"data": map[string]any{"interfaces": []string{}, "confirm_timeout_seconds": 30}})
	action("apply")
	action("confirm")
	expect("unbound", map[string]bool{"direct": true, "direct v6": true, "bridged": true})
	for _, name := range []string{hostDirect, bridge} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if xdp := link.Attrs().Xdp; xdp != nil && xdp.Attached {
			t.Fatalf("%s still has XDP attached after unbinding: %+v", name, xdp)
		}
	}
}
