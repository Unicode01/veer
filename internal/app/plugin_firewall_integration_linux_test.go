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
// other through a bridge (no native XDP: generic mode on the bridge).
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
		PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, PluginsIsolationSetting: &disabled,
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
	cmd := exec.Command(buildDataplanePerfBinary(t, root), "--config", configPath)
	cmd.Dir = work
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("daemon log:\n%s", b)
		}
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.WebPort)
	waitForEgressNATIntegrationAPIWithTimeout(t, base, cmd, logPath, 45*time.Second)
	waitForEgressNATIntegrationPluginAction(t, base, cmd, logPath, "firewall", "apply")

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
		var response struct {
			Result map[string]any `json:"result"`
		}
		_ = json.Unmarshal(api("POST", "/api/plugins/firewall/actions/"+id, map[string]any{"payload": map[string]any{}}), &response)
		return response.Result
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
	action("confirm")
	for name, want := range map[string]uint32{hostDirect: nl.XDP_ATTACHED_DRV, bridge: nl.XDP_ATTACHED_SKB} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		xdp := link.Attrs().Xdp
		if xdp == nil || !xdp.Attached || xdp.AttachMode != want {
			t.Fatalf("%s XDP = %+v, want attach mode %d", name, xdp, want)
		}
	}

	// Only the direct client's IPv4 address.
	putPolicy([]map[string]string{{"cidr": "10.199.0.2", "action": "allow"}})
	action("apply")
	action("confirm")
	expect("allow one source", map[string]bool{"direct": true, "direct v6": false, "bridged": false})

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
