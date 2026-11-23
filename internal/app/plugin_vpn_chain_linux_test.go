package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestVPNChainedExitLinuxIntegration chains proxy exits behind other exits with
// real cores: sing-box behind kernel WireGuard, and Mihomo behind sing-box.
// Each exit node is reachable only through its front and the target only
// through the exit node, so a probe that arrives proves the whole path. The
// host uses strict reverse-path filtering, which the plugin must relax on the
// front boundaries only.
func TestVPNChainedExitLinuxIntegration(t *testing.T) {
	if os.Getenv("VEER_RUN_VPN_CORE_TESTS") != "1" {
		t.Skip("set VEER_RUN_VPN_CORE_TESTS=1 with real Mihomo and sing-box binaries")
	}
	if os.Geteuid() != 0 {
		t.Fatal("VPN chain integration requires root")
	}
	for _, tool := range []string{"ip", "wg", "sysctl", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"VEER_TEST_MIHOMO", "VEER_TEST_SING_BOX"} {
		if _, err := os.Stat(os.Getenv(name)); err != nil {
			t.Fatalf("%s must name a real core: %v", name, err)
		}
	}
	if os.Getenv("VEER_VPN_CHAIN_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--", os.Args[0], "-test.run=^TestVPNChainedExitLinuxIntegration$", "-test.v", "-test.timeout=6m")
		cmd.Env = append(os.Environ(), "VEER_VPN_CHAIN_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated chain test: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	runVPNChainTopology(t)
}

func runVPNChainTopology(t *testing.T) {
	root, work := findRepoRoot(t), t.TempDir()
	run := func(input, command string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, command, args...)
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Neither stdin nor wg diagnostics may be printed: they can carry keys.
			if input != "" || command == "wg" {
				t.Fatalf("%s failed: %v", command, err)
			}
			t.Fatalf("%s %v: %v: %s", command, args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	ip := func(args ...string) string { t.Helper(); return run("", "ip", args...) }
	sysctl := func(name string) string { t.Helper(); return run("", "sysctl", "-n", name) }
	pid := os.Getpid()
	r1, r2, rt := fmt.Sprintf("vcr1-%d", pid), fmt.Sprintf("vcr2-%d", pid), fmt.Sprintf("vcrt-%d", pid)
	c1, c2 := fmt.Sprintf("vcc1-%d", pid), fmt.Sprintf("vcc2-%d", pid)
	for _, ns := range []string{r1, r2, rt, c1, c2} {
		ip("netns", "add", ns)
		ns := ns
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		ip("-n", ns, "link", "set", "lo", "up")
	}
	ip("link", "set", "lo", "up")
	// Strict reverse-path filtering, also for interfaces created later: the
	// plugin has to relax the front boundaries itself, and only those.
	run("", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=1", "net.ipv4.conf.default.rp_filter=1")
	ip("link", "add", "br-lan", "type", "bridge")
	ip("addr", "add", "192.168.10.1/24", "dev", "br-lan")
	ip("link", "set", "br-lan", "up")
	for i, ns := range []string{c1, c2} {
		host, peer := fmt.Sprintf("port%d", i+1), fmt.Sprintf("client%d", i+1)
		ip("link", "add", host, "type", "veth", "peer", "name", peer)
		ip("link", "set", host, "master", "br-lan")
		ip("link", "set", host, "up")
		ip("link", "set", peer, "netns", ns)
		ip("-n", ns, "addr", "add", fmt.Sprintf("192.168.10.%d/24", 21+i), "dev", peer)
		ip("-n", ns, "link", "set", peer, "up")
		ip("-n", ns, "route", "add", "default", "via", "192.168.10.1")
	}
	// r1 holds the WireGuard peer and node A. r2 holds node B, reachable only
	// from r1; it routes back only to r1's own address and the WireGuard
	// tunnel address, never to the host's uplink. rt holds the target, reached
	// only from node B's two source addresses.
	ip("link", "add", "wan0", "type", "veth", "peer", "name", "outside")
	ip("link", "set", "outside", "netns", r1)
	ip("addr", "add", "192.0.2.1/24", "dev", "wan0")
	ip("link", "set", "wan0", "up")
	ip("route", "add", "default", "via", "192.0.2.2")
	ip("-n", r1, "addr", "add", "192.0.2.2/24", "dev", "outside")
	ip("-n", r1, "link", "set", "outside", "up")
	ip("link", "add", "r1b", "netns", r1, "type", "veth", "peer", "name", "r2a", "netns", r2)
	ip("-n", r1, "addr", "add", "100.64.0.1/30", "dev", "r1b")
	ip("-n", r1, "link", "set", "r1b", "up")
	ip("-n", r2, "addr", "add", "100.64.0.2/30", "dev", "r2a")
	ip("-n", r2, "link", "set", "r2a", "up")
	ip("-n", r2, "route", "add", "10.77.0.1/32", "via", "100.64.0.1")
	ip("link", "add", "r2t", "netns", r2, "type", "veth", "peer", "name", "tgt", "netns", rt)
	ip("-n", r2, "addr", "add", "100.64.1.1/29", "dev", "r2t")
	ip("-n", r2, "addr", "add", "100.64.1.3/29", "dev", "r2t")
	ip("-n", r2, "link", "set", "r2t", "up")
	ip("-n", rt, "addr", "add", "100.64.1.2/29", "dev", "tgt")
	ip("-n", rt, "link", "set", "tgt", "up")
	ip("-n", rt, "addr", "add", "203.0.113.1/32", "dev", "lo")
	ip("-n", rt, "route", "add", "default", "via", "100.64.1.1")
	ip("-n", r2, "route", "add", "203.0.113.1/32", "via", "100.64.1.2")
	run("", "ip", "netns", "exec", r1, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0")
	localPrivate, peerPrivate := run("", "wg", "genkey"), run("", "wg", "genkey")
	localPublic, peerPublic := run(localPrivate+"\n", "wg", "pubkey"), run(peerPrivate+"\n", "wg", "pubkey")
	ip("-n", r1, "link", "add", "wgpeer", "type", "wireguard")
	run("[Interface]\nPrivateKey = "+peerPrivate+"\nListenPort = 51820\n[Peer]\nPublicKey = "+localPublic+"\nAllowedIPs = 10.77.0.1/32\n",
		"ip", "netns", "exec", r1, "/usr/bin/wg", "syncconf", "wgpeer", "/dev/stdin")
	ip("-n", r1, "addr", "add", "10.77.0.2/32", "dev", "wgpeer")
	ip("-n", r1, "link", "set", "wgpeer", "up")
	ip("-n", r1, "route", "add", "10.77.0.1/32", "dev", "wgpeer")

	startProcess := func(cmd *exec.Cmd) {
		t.Helper()
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
	}
	writeJSON := func(name string, value any) string {
		t.Helper()
		data, _ := json.Marshal(value)
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	singBox, mihomo := os.Getenv("VEER_TEST_SING_BOX"), os.Getenv("VEER_TEST_MIHOMO")
	ssInbound := func(tag, listen string, port int, password string) map[string]any {
		return map[string]any{"type": "shadowsocks", "tag": tag, "listen": listen, "listen_port": port, "method": "aes-128-gcm", "password": password}
	}
	nodeA := writeJSON("node-a.json", map[string]any{"log": map[string]any{"disabled": true},
		"inbounds": []any{ssInbound("a", "192.0.2.2", 8388, "chain-node-a")}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	// Node B sends to the target from a different address per chain, so the
	// target tells which chain a probe came through.
	nodeB := writeJSON("node-b.json", map[string]any{"log": map[string]any{"disabled": true},
		"inbounds": []any{ssInbound("b1", "100.64.0.2", 8388, "chain-node-b1"), ssInbound("b2", "100.64.0.2", 8389, "chain-node-b2")},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "b1", "inet4_bind_address": "100.64.1.1"},
			map[string]any{"type": "direct", "tag": "b2", "inet4_bind_address": "100.64.1.3"}},
		"route": map[string]any{"rules": []any{map[string]any{"inbound": []string{"b1"}, "outbound": "b1"},
			map[string]any{"inbound": []string{"b2"}, "outbound": "b2"}}}})
	startProcess(exec.Command("ip", "netns", "exec", r1, singBox, "run", "-c", nodeA))
	startProcess(exec.Command("ip", "netns", "exec", r2, singBox, "run", "-c", nodeB))

	for _, id := range []string{"wan_core", "vpn_core"} {
		copyDirForTest(t, filepath.Join(root, "plugins", id), filepath.Join(work, "plugins", id))
	}
	enabled, disabled := true, false
	cfg := Config{WebBind: "127.0.0.1", WebPort: freeTCPPort(t), WebToken: egressNATTestToken,
		PluginAdminToken: "vpn-chain-integration-admin", MaxWorkers: 1, DefaultEngine: ruleEngineKernel,
		KernelEngineOrder: []string{kernelEngineTC}, PluginsDir: filepath.Join(work, "plugins"),
		PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled,
		PluginsMinSandboxLevel: pluginSandboxLevelNone, PluginsRequireSigned: &disabled,
		Experimental: map[string]bool{experimentalFeatureKernelTCPreparedL2: true}}
	configPath, logPath := writeJSON("config.json", cfg), filepath.Join(work, "veer.log")
	binary, base := buildDataplanePerfBinary(t, root), fmt.Sprintf("http://127.0.0.1:%d", cfg.WebPort)
	var daemon *exec.Cmd
	startDaemon := func() {
		t.Helper()
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		daemon = exec.Command(binary, "--config", configPath)
		// No marker: a stop is a cold stop that takes the cores down with it.
		daemon.Env = append(os.Environ(), "VEER_HOT_RESTART_MARKER="+filepath.Join(work, "hot-restart"))
		daemon.Dir, daemon.Stdout, daemon.Stderr = work, logFile, logFile
		if err := daemon.Start(); err != nil {
			t.Fatal(err)
		}
		_ = logFile.Close()
		waitForEgressNATIntegrationAPIWithTimeout(t, base, daemon, logPath, 45*time.Second)
		waitForEgressNATIntegrationPluginAction(t, base, daemon, logPath, "vpn_core", "apply")
	}
	stopDaemon := func() {
		if daemon == nil || daemon.Process == nil {
			return
		}
		_ = daemon.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = daemon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = daemon.Process.Kill()
			<-done
		}
		daemon = nil
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := os.ReadFile(logPath)
			t.Logf("chain daemon log:\n%s", logs)
		}
		stopDaemon()
	})
	startDaemon()

	api := func(method, path string, payload any, allowFailure bool) []byte {
		t.Helper()
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+cfg.WebToken)
		req.Header.Set(pluginAdminTokenHeader, cfg.PluginAdminToken)
		req.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		failed := response.StatusCode < 200 || response.StatusCode >= 300
		if failed != allowFailure {
			if strings.Contains(path, "set_key") {
				t.Fatalf("key action unexpected HTTP %d", response.StatusCode)
			}
			t.Fatalf("%s %s unexpected HTTP %d: %s", method, path, response.StatusCode, body)
		}
		return body
	}
	action := func(key, name string, fails bool) []byte {
		t.Helper()
		return api("POST", "/api/plugins/vpn_core/actions/"+name, map[string]any{"payload": map[string]any{"key": key}}, fails)
	}
	refused := func(key, name, code string) {
		t.Helper()
		if body := action(key, name, true); !bytes.Contains(body, []byte("["+code+"]")) {
			t.Fatalf("%s %s: want [%s], got %s", name, key, code, body)
		}
	}
	type exitStatus struct {
		Phase  string `json:"phase"`
		Source string `json:"egress_nat_source_ip"`
		Code   string `json:"error_code"`
		Error  string `json:"error"`
	}
	statuses := func() map[string]exitStatus {
		t.Helper()
		var response struct {
			Records []struct {
				Key  string     `json:"key"`
				Data exitStatus `json:"data"`
			} `json:"records"`
		}
		if err := json.Unmarshal(api("GET", "/api/plugins/vpn_core/resources/status", nil, false), &response); err != nil {
			t.Fatal(err)
		}
		out := map[string]exitStatus{}
		for _, record := range response.Records {
			out[record.Key] = record.Data
		}
		return out
	}
	waitApplied := func(keys ...string) map[string]exitStatus {
		t.Helper()
		for end := time.Now().Add(45 * time.Second); ; {
			current, ready := statuses(), true
			for _, key := range keys {
				ready = ready && current[key].Phase == "applied"
			}
			if ready {
				return current
			}
			if time.Now().After(end) {
				t.Fatalf("exits %v not applied: %+v", keys, current)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	corePID := func(key string) int {
		t.Helper()
		var response struct {
			Result struct {
				Process struct {
					PID int `json:"pid"`
				} `json:"process"`
			} `json:"result"`
		}
		if err := json.Unmarshal(action(key, "inspect", false), &response); err != nil {
			t.Fatal(err)
		}
		return response.Result.Process.PID
	}
	share := func(password, server string, port int) string {
		return "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:"+password)) + fmt.Sprintf("@%s:%d#n", server, port)
	}
	profile := func(key string, data map[string]any) {
		t.Helper()
		api("POST", "/api/plugins/vpn_core/resources/profiles", map[string]any{"key": key, "data": data, "enabled": true}, false)
	}
	proxy := func(key, driver, core string, slot int, upstream, links string) map[string]any {
		t.Helper()
		api("POST", "/api/plugins/vpn_core/actions/set_core_config", map[string]any{"payload": map[string]any{"key": key, "driver": driver, "format": "links", "value": links}}, false)
		data := map[string]any{"driver": driver, "slot": slot, "upstream_interface": upstream, "core_path": core}
		profile(key, data)
		return data
	}
	api("POST", "/api/plugins/vpn_core/actions/set_key", map[string]any{"payload": map[string]any{"key": "wg1", "value": localPrivate}}, false)
	profile("wg1", map[string]any{"slot": 1, "listen_port": 51821, "addresses": []string{"10.77.0.1/32"},
		"peers": []any{map[string]any{"public_key": peerPublic, "endpoint": "192.0.2.2:51820", "allowed_ips": []string{"0.0.0.0/0"}, "keepalive": 1}}})
	proxy("sbw", "sing_box", singBox, 2, "veerwg1", share("chain-node-b1", "100.64.0.2", 8388))
	sba := proxy("sba", "sing_box", singBox, 3, "wan0", share("chain-node-a", "192.0.2.2", 8388))
	proxy("mhb", "mihomo", mihomo, 4, "veervpn3", share("chain-node-b2", "100.64.0.2", 8389))

	// A chained exit waits for its front.
	refused("sbw", "apply", "upstream_exit_down")
	for _, key := range []string{"wg1", "sbw", "sba", "mhb"} {
		action(key, "apply", false)
		waitApplied(key)
	}
	for _, boundary := range []string{"veerwg1", "veervpn3"} {
		if got := sysctl("net.ipv4.conf." + boundary + ".rp_filter"); got != "2" {
			t.Fatalf("front boundary %s rp_filter=%s, want 2", boundary, got)
		}
	}
	if got := sysctl("net.ipv4.conf.all.rp_filter") + sysctl("net.ipv4.conf.veervpn2.rp_filter") + sysctl("net.ipv4.conf.veervpn4.rp_filter"); got != "111" {
		t.Fatalf("the plugin relaxed more than the front boundaries: all/veervpn2/veervpn4 = %s", got)
	}

	createNAT := func(child, out, source string) {
		t.Helper()
		body := api("POST", "/api/egress-nats", map[string]any{"parent_interface": "br-lan", "child_interface": child, "out_interface": out, "out_source_ip": source, "protocol": "tcp+udp+icmp"}, false)
		var created struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(body, &created)
		for end := time.Now().Add(15 * time.Second); ; {
			var entries []EgressNATStatus
			if err := json.Unmarshal(api("GET", "/api/egress-nats", nil, false), &entries); err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.ID == created.ID && entry.Status == "running" && entry.OutSourceIP == source {
					return
				}
			}
			if time.Now().After(end) {
				t.Fatalf("NAT %s -> %s did not run: %+v", child, out, entries)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	applied := statuses()
	createNAT("port1", "veervpn2", applied["sbw"].Source)
	createNAT("port2", "veervpn4", applied["mhb"].Source)
	probe := func(ns, want string) {
		t.Helper()
		for _, protocol := range []string{"tcp", "udp"} {
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				observed := filepath.Join(t.TempDir(), "observed")
				backend, logs := startEgressNATBackendHelperInNamespace(t, rt, protocol, "203.0.113.1:24001", observed)
				client := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestEgressNATIntegrationHelperProcess$")
				client.Env = append(os.Environ(), egressNATHelperEnv+"=1", egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
					egressNATHelperProtocolEnv+"="+protocol, egressNATHelperTargetAddrEnv+"=203.0.113.1:24001")
				out, clientErr := client.CombinedOutput()
				if clientErr != nil {
					stopDataplanePerfHelper(t, backend)
					err = fmt.Errorf("%s probe from %s: %v: %s backend: %s", protocol, ns, clientErr, out, logs.String())
					time.Sleep(time.Second)
					continue
				}
				waitForEgressNATHelperExit(t, backend, protocol, logs.String())
				seen, _ := os.ReadFile(observed)
				if got := strings.TrimSpace(string(seen)); got != want {
					t.Fatalf("%s from %s observed %q, want %s", protocol, ns, got, want)
				}
				err = nil
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	wgReceived := func() int64 {
		t.Helper()
		fields := strings.Fields(run("", "ip", "netns", "exec", r1, "wg", "show", "wgpeer", "transfer"))
		if len(fields) < 3 {
			t.Fatalf("wg transfer: %v", fields)
		}
		value, _ := strconv.ParseInt(fields[1], 10, 64)
		return value
	}
	before := wgReceived()
	probe(c1, "100.64.1.1")
	if after := wgReceived(); after <= before {
		t.Fatalf("sing-box behind WireGuard did not use the tunnel: received %d -> %d", before, after)
	}
	probe(c2, "100.64.1.3")
	t.Log("sing-box behind WireGuard and Mihomo behind sing-box carried TCP/UDP; only the front boundaries were relaxed")

	// Fronts in use stay; a loop is refused before anything changes.
	refused("wg1", "teardown", "upstream_in_use")
	refused("sba", "delete_profile", "upstream_in_use")
	loop := map[string]any{}
	for k, v := range sba {
		loop[k] = v
	}
	loop["upstream_interface"] = "veervpn4"
	api("PUT", "/api/plugins/vpn_core/resources/profiles/sba", map[string]any{"key": "sba", "data": loop, "enabled": true}, false)
	refused("sba", "apply", "upstream_cycle")
	api("PUT", "/api/plugins/vpn_core/resources/profiles/sba", map[string]any{"key": "sba", "data": sba, "enabled": true}, false)
	if current := statuses(); current["sba"].Phase != "applied" || current["mhb"].Phase != "applied" {
		t.Fatalf("refused changes disturbed the chain: %+v", current)
	}

	// A rebuilt front boundary: the front recovers, then the core behind it
	// restarts bound to the new boundary, which is relaxed again.
	pidBefore := corePID("mhb")
	ip("link", "del", "veervpn3")
	for end := time.Now().Add(45 * time.Second); ; {
		current := statuses()
		if current["sba"].Phase == "applied" && current["mhb"].Phase == "applied" && corePID("mhb") != pidBefore && corePID("mhb") != 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("chain did not recover from a rebuilt front boundary: %+v", current)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if got := sysctl("net.ipv4.conf.veervpn3.rp_filter"); got != "2" {
		t.Fatalf("rebuilt front boundary rp_filter=%s, want 2", got)
	}
	probe(c2, "100.64.1.3")
	probe(c1, "100.64.1.1")
	t.Log("a rebuilt front boundary restarted the core chained behind it; both chains carried traffic")

	// A cold daemon start brings every core back, fronts first.
	stopDaemon()
	startDaemon()
	waitApplied("wg1", "sbw", "sba", "mhb")
	probe(c1, "100.64.1.1")
	probe(c2, "100.64.1.3")
	t.Log("after a cold daemon start both chains recovered and carried traffic")

	for _, key := range []string{"mhb", "sba", "sbw", "wg1"} {
		action(key, "teardown", false)
	}
}
