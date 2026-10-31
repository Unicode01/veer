package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The complete topology runs in a disposable network namespace. No route,
// firewall rule, sysctl or WireGuard device is installed in the runner's netns.
func TestWireGuardMeshLinuxIntegration(t *testing.T) {
	if role := os.Getenv("VEER_WG_BULK"); role != "" {
		runWireGuardBulkHelper(t, role)
		return
	}
	if os.Getenv("VEER_RUN_WIREGUARD_TESTS") != "1" {
		t.Skip("set VEER_RUN_WIREGUARD_TESTS=1 to test real WireGuard routing")
	}
	if os.Geteuid() != 0 {
		t.Fatal("WireGuard integration requires root")
	}
	for _, tool := range []string{"ip", "wg", "tc", "sysctl", "ping", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required tool %s: %v", tool, err)
		}
	}
	if os.Getenv("VEER_WG_TEST_CHILD") == "1" {
		runWireGuardMeshTopology(t)
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--net", "--", binary, "-test.run=^TestWireGuardMeshLinuxIntegration$", "-test.v", "-test.timeout=230s")
	cmd.Env = append(os.Environ(), "VEER_WG_TEST_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated WireGuard test: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}

func TestVPNCoreLinuxIntegration(t *testing.T) {
	if os.Getenv("VEER_RUN_VPN_CORE_TESTS") != "1" {
		t.Skip("set VEER_RUN_VPN_CORE_TESTS=1 with real Mihomo and sing-box binaries")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, driver := range []string{"mihomo", "sing_box"} {
		t.Run(driver, func(t *testing.T) {
			for _, name := range []string{"VEER_TEST_MIHOMO", "VEER_TEST_SING_BOX"} {
				if _, err := os.Stat(os.Getenv(name)); err != nil {
					t.Fatalf("%s must name an installed core: %v", name, err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "unshare", "--net", "--", binary, "-test.run=^TestWireGuardMeshLinuxIntegration$", "-test.v", "-test.timeout=230s")
			cmd.Env = append(os.Environ(), "VEER_RUN_WIREGUARD_TESTS=1", "VEER_WG_TEST_CHILD=1", "VEER_TEST_VPN_DRIVER="+driver)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s WAN integration: %v\n%s", driver, err, output)
			}
			t.Logf("%s", output)
		})
	}
}

func runWireGuardMeshTopology(t *testing.T) {
	t.Helper()
	driver := os.Getenv("VEER_TEST_VPN_DRIVER")
	tunnelInterface, wanInterface, selectedSource := "vwgdefault", "veerwg1", "10.77.0.1"
	natSource := "10.77.0.1"
	if driver != "" {
		tunnelInterface, wanInterface, selectedSource = "vtundefault", "veervpn1", "203.0.113.1"
	}
	run := func(input string, program string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Neither stdin nor wg diagnostics may be printed: they can contain keys.
			if program == "wg" || input != "" {
				t.Fatalf("%s %s failed: %v", program, args[0], err)
			}
			t.Fatalf("%s %v: %v: %s", program, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	ip := func(args ...string) string { return run("", "ip", args...) }
	suffix := fmt.Sprintf("%d", os.Getpid())
	remote, selected, direct := "vwg-r-"+suffix, "vwg-s-"+suffix, "vwg-d-"+suffix
	for _, ns := range []string{remote, selected, direct} {
		ip("netns", "add", ns)
		ns := ns
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		ip("-n", ns, "link", "set", "lo", "up")
	}
	ip("link", "set", "lo", "up")
	run("", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2", "net.ipv6.conf.all.forwarding=1")
	ip("link", "add", "br-lan", "type", "bridge")
	ip("address", "add", "192.168.10.1/24", "dev", "br-lan")
	ip("-6", "address", "add", "fd10::1/64", "dev", "br-lan", "nodad")
	ip("link", "set", "br-lan", "up")
	for i, ns := range []string{selected, direct} {
		host, peer := fmt.Sprintf("port%d", i), fmt.Sprintf("client%d", i)
		ip("link", "add", host, "type", "veth", "peer", "name", peer)
		ip("link", "set", host, "master", "br-lan")
		ip("link", "set", host, "up")
		ip("link", "set", peer, "netns", ns)
		ip("-n", ns, "address", "add", fmt.Sprintf("192.168.10.%d/24", 20+i*10), "dev", peer)
		ip("-n", ns, "-6", "address", "add", fmt.Sprintf("fd10::%d/64", 20+i*10), "dev", peer, "nodad")
		ip("-n", ns, "link", "set", peer, "up")
		ip("-n", ns, "route", "add", "default", "via", "192.168.10.1")
		ip("-n", ns, "-6", "route", "add", "default", "via", "fd10::1")
	}
	ip("link", "add", "wan", "type", "veth", "peer", "name", "outside")
	ip("link", "set", "outside", "netns", remote)
	ip("address", "add", "192.0.2.1/24", "dev", "wan")
	ip("-6", "address", "add", "fd02::1/64", "dev", "wan", "nodad")
	ip("link", "set", "wan", "up")
	ip("-n", remote, "address", "add", "192.0.2.2/24", "dev", "outside")
	ip("-n", remote, "-6", "address", "add", "fd02::2/64", "dev", "outside", "nodad")
	ip("-n", remote, "link", "set", "outside", "up")
	ip("route", "add", "default", "via", "192.0.2.2")
	ip("-6", "route", "add", "default", "via", "fd02::2")
	ip("-n", remote, "address", "add", "203.0.113.1/32", "dev", "lo")
	ip("-n", remote, "address", "add", "192.168.20.1/32", "dev", "lo")
	ip("-n", remote, "-6", "address", "add", "fd20::1/128", "dev", "lo", "nodad")
	ip("-n", remote, "route", "add", "192.168.10.0/24", "via", "192.0.2.1")
	ip("-n", remote, "-6", "route", "add", "fd10::/64", "via", "fd02::1")
	localPrivate, remotePrivate := run("", "wg", "genkey"), run("", "wg", "genkey")
	localPublic, remotePublic := run(localPrivate+"\n", "wg", "pubkey"), run(remotePrivate+"\n", "wg", "pubkey")
	ip("-n", remote, "link", "add", "wgpeer", "type", "wireguard")
	configureRemote := func(allowed string) {
		t.Helper()
		config := "[Interface]\nPrivateKey = " + remotePrivate + "\nListenPort = 51820\n[Peer]\nPublicKey = " + localPublic + "\nAllowedIPs = " + allowed + "\n"
		run(config, "ip", "netns", "exec", remote, "/usr/bin/wg", "syncconf", "wgpeer", "/dev/stdin")
	}
	configureRemote("10.77.0.1/32, fd77::1/128")
	ip("-n", remote, "address", "add", "10.77.0.2/32", "dev", "wgpeer")
	ip("-n", remote, "-6", "address", "add", "fd77::2/128", "dev", "wgpeer", "nodad")
	ip("-n", remote, "link", "set", "wgpeer", "up")
	ip("-n", remote, "route", "add", "10.77.0.1/32", "dev", "wgpeer")
	ip("-n", remote, "-6", "route", "add", "fd77::1/128", "dev", "wgpeer")
	ip("netns", "exec", remote, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.wgpeer.rp_filter=2")
	if driver != "" {
		serverConfig := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "shadowsocks", "tag": "ss", "listen": "192.0.2.2", "listen_port": 8388, "method": "aes-128-gcm", "password": "veer-integration-only"}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
		data, _ := json.Marshal(serverConfig)
		path := filepath.Join(t.TempDir(), "server.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		server := exec.Command("ip", "netns", "exec", remote, os.Getenv("VEER_TEST_SING_BOX"), "run", "-c", path)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	}
	// Exercise the real daemon, plugin service calls, TC verifier and core NAT together.
	root, work := findRepoRoot(t), t.TempDir()
	for _, id := range []string{"wan_core", "vpn_core"} {
		copyDirForTest(t, filepath.Join(root, "plugins", id), filepath.Join(work, "plugins", id))
	}
	enabled, disabled := true, false
	cfg := Config{WebBind: "127.0.0.1", WebPort: freeTCPPort(t), WebToken: egressNATTestToken,
		PluginAdminToken: "wireguard-integration-admin", MaxWorkers: 1, DefaultEngine: ruleEngineKernel,
		KernelEngineOrder: []string{kernelEngineTC}, PluginsDir: filepath.Join(work, "plugins"),
		PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, PluginsIsolationSetting: &disabled,
		PluginsMinSandboxLevel: pluginSandboxLevelNone, PluginsRequireSigned: &disabled,
		Experimental: map[string]bool{experimentalFeatureKernelTCPreparedL2: true}}
	data, _ := json.Marshal(cfg)
	configPath := filepath.Join(work, "config.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(work, "veer.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	hotMarker := filepath.Join(work, "hot-restart")
	cmd := exec.Command(buildDataplanePerfBinary(t, root), "--config", configPath)
	cmd.Env = append(os.Environ(), "VEER_HOT_RESTART_MARKER="+hotMarker)
	cmd.Dir = work
	cmd.Stdout = logFile
	cmd.Stderr = logFile
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
	waitForEgressNATIntegrationPluginAction(t, base, cmd, logPath, "vpn_core", "apply")
	api := func(method, path string, payload any) []byte {
		t.Helper()
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+cfg.WebToken)
		req.Header.Set(pluginAdminTokenHeader, cfg.PluginAdminToken)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {

			check, _ := http.NewRequest("GET", base+"/api/plugins", nil)
			check.Header.Set("Authorization", "Bearer "+cfg.WebToken)
			if response, e := client.Do(check); e == nil {
				var catalog struct {
					Plugins []struct {
						ID      string          `json:"id"`
						Runtime json.RawMessage `json:"runtime"`
					}
				}
				_ = json.NewDecoder(response.Body).Decode(&catalog)
				response.Body.Close()
				for _, p := range catalog.Plugins {
					if p.ID == "vpn_core" {
						t.Logf("WG runtime: %s", p.Runtime)
					}
				}
			}
			if strings.Contains(path, "set_key") {
				t.Fatalf("set key HTTP %d", resp.StatusCode)
			}
			t.Fatalf("%s %s HTTP %d: %s", method, path, resp.StatusCode, body)
		}
		return body
	}
	action := func(id string) {
		api("POST", "/api/plugins/vpn_core/actions/"+id, map[string]any{"payload": map[string]any{"key": "default"}})

		if driver != "" && id == "apply" {
			end := time.Now().Add(15 * time.Second)
			for {
				var records struct {
					Records []struct {
						Key  string `json:"key"`
						Data struct {
							Phase  string `json:"phase"`
							Source string `json:"egress_nat_source_ip"`
						} `json:"data"`
					} `json:"records"`
				}
				data := api("GET", "/api/plugins/vpn_core/resources/status", nil)
				_ = json.Unmarshal(data, &records)
				ready := false
				for _, record := range records.Records {
					if record.Key == "default" && record.Data.Phase == "applied" {
						if net.ParseIP(record.Data.Source).To4() == nil {
							t.Fatalf("VPN did not publish its automatic WAN IPv4: %s", data)
						}
						if natSource != "10.77.0.1" && natSource != record.Data.Source {
							t.Fatalf("VPN changed its applied WAN address: %s -> %s", natSource, record.Data.Source)
						}
						natSource = record.Data.Source
						ready = true
					}
				}
				if ready {
					break
				}
				if time.Now().After(end) {
					t.Fatalf("VPN core did not become ready: %s", data)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	// A parent default remains on the ordinary uplink; the child overrides it with the WG WAN.
	create := func(child, out, source string) int64 {
		t.Helper()
		body := api("POST", "/api/egress-nats", map[string]any{"parent_interface": "br-lan", "child_interface": child, "out_interface": out, "out_source_ip": source, "redirect_mode": egressNATRedirectModePreparedL2, "protocol": "tcp+udp+icmp"})
		var r struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(body, &r)
		return r.ID
	}
	waitNAT := func(id int64, source string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			var entries []EgressNATStatus
			if err := json.Unmarshal(api("GET", "/api/egress-nats", nil), &entries); err != nil {
				t.Fatal(err)
			}
			ready := false
			for _, entry := range entries {
				if entry.ID == id {
					ready = entry.Status == "running" && entry.EffectiveEngine == ruleEngineKernel && entry.EffectiveKernelEngine == kernelEngineTC && entry.OutSourceIP == source
				}
			}
			if ready {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("NAT %d did not enter TC: %+v", id, entries)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	probe := func(ns, source string) {
		t.Helper()
		for _, protocol := range []string{"tcp", "udp"} {
			observed := filepath.Join(t.TempDir(), "observed")
			backend, logs := startEgressNATBackendHelperInNamespace(t, remote, protocol, "203.0.113.1:24001", observed)
			client := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestEgressNATIntegrationHelperProcess$")
			client.Env = append(os.Environ(), egressNATHelperEnv+"=1", egressNATHelperRoleEnv+"="+egressNATHelperRoleClient, egressNATHelperProtocolEnv+"="+protocol, egressNATHelperTargetAddrEnv+"=203.0.113.1:24001")
			out, err := client.CombinedOutput()
			if err != nil {
				stopDataplanePerfHelper(t, backend)
				t.Fatalf("%s probe: %v: %s backend: %s", protocol, err, out, logs.String())
			}
			waitForEgressNATHelperExit(t, backend, protocol, logs.String())
			b, _ := os.ReadFile(observed)
			if strings.TrimSpace(string(b)) != source {
				t.Fatalf("%s observed %q, want %s", protocol, b, source)
			}
		}
		if driver == "" || ns == direct {
			ip("netns", "exec", ns, "ping", "-n", "-c", "2", "-W", "2", "203.0.113.1")
		}
	}
	// A freshly enabled VPN plugin has no hook_bindings record. Ordinary TC
	// TCP/UDP must work before any apply/teardown can initialize that resource.
	var ordinary struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(api("POST", "/api/egress-nats", map[string]any{"parent_interface": "br-lan", "out_interface": "wan", "out_source_ip": "192.0.2.1", "protocol": "tcp+udp+icmp"}), &ordinary); err != nil {
		t.Fatal(err)
	}
	waitNAT(ordinary.ID, "192.0.2.1")
	probe(selected, "192.0.2.1")
	probe(direct, "192.0.2.1")
	t.Log("fresh VPN plugin without bindings: ordinary TC TCP/UDP/ICMP passed")
	api("POST", "/api/plugins/vpn_core/actions/set_key", map[string]any{"payload": map[string]any{"key": "default", "value": localPrivate}})
	profile := map[string]any{"slot": 1, "listen_port": 51821, "addresses": []string{"10.77.0.1/32"},
		"peers": []any{map[string]any{"public_key": remotePublic, "endpoint": "192.0.2.2:51820", "allowed_ips": []string{"0.0.0.0/0"}}}}
	if driver != "" {
		core := os.Getenv("VEER_TEST_MIHOMO")
		if driver == "sing_box" {
			core = os.Getenv("VEER_TEST_SING_BOX")
		}
		// Seed through the verified installer, then exercise the daemon's default
		// core resolution and restart recovery using its persistent directory.
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, core) }))
		defer server.Close()
		binaries, err := newPluginBinaryStore(&cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer binaries.cancelOwner("", true)
		binaries.client = server.Client()
		digest, err := sha256File(core)
		if err != nil {
			t.Fatal(err)
		}
		executable, check := "mihomo", []string{"-v"}
		if driver == "sing_box" {
			executable, check = "sing-box", []string{"version"}
		}
		if _, err = binaries.Install("vpn_core", pluginBinaryRequest{ID: driver, Version: "vtest", URL: server.URL, SHA256: digest, Executable: executable, Format: "raw", CheckArgs: check}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-binaries.jobs["vpn_core/"+driver].done:
		case <-time.After(30 * time.Second):
			t.Fatal("managed core installation did not finish")
		}
		installed, err := binaries.Status("vpn_core", driver)
		if err != nil || installed.Install.State != "ready" {
			t.Fatalf("core install: %+v %v", installed, err)
		}
		var managed struct {
			Result pluginBinaryStatus `json:"result"`
		}
		body := api("POST", "/api/plugins/vpn_core/actions/core_status", map[string]any{"payload": map[string]any{"driver": driver}})
		if err = json.Unmarshal(body, &managed); err != nil || managed.Result.Path != installed.Path {
			t.Fatalf("daemon did not discover persistent core: %s %v", body, err)
		}
		profile = map[string]any{"driver": driver, "upstream_interface": "wan", "slot": 1}
		// Exercise the ordinary form with no internal address and an occupied
		// preferred pool subnet, using the real netlink and route inventories.
		ip("addr", "add", "10.78.1.254/24", "dev", "lo")
		var config map[string]any
		if driver == "mihomo" {
			config = map[string]any{"proxies": []any{map[string]any{"name": "test", "type": "ss", "server": "192.0.2.2", "port": 8388, "cipher": "aes-128-gcm", "password": "veer-integration-only", "udp": true}}, "rules": []string{"MATCH,test"}}
		} else {
			config = map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "test", "server": "192.0.2.2", "server_port": 8388, "method": "aes-128-gcm", "password": "veer-integration-only"}}, "route": map[string]any{"final": "test"}}
		}
		data, _ := json.Marshal(config)
		api("POST", "/api/plugins/vpn_core/actions/set_core_config", map[string]any{"payload": map[string]any{"key": "default", "value": string(data)}})
	}
	api("POST", "/api/plugins/vpn_core/resources/profiles", map[string]any{"key": "default", "data": profile, "enabled": true})
	action("apply")
	if driver != "" && strings.HasPrefix(natSource, "10.78.1.") {
		t.Fatalf("automatic WAN address overlaps the host subnet: %s", natSource)
	}
	checkTUNBoundary := func() {
		t.Helper()
		if driver == "" {
			return
		}
		// Compare the plugin's decision with independent ip/ethtool observations
		// of the real core, rather than a mocked driver name or capability bit.
		var links []struct {
			LinkInfo struct {
				InfoData struct {
					VNetHeader bool `json:"vnet_hdr"`
				} `json:"info_data"`
			} `json:"linkinfo"`
		}
		if err := json.Unmarshal([]byte(ip("-j", "-d", "link", "show", "dev", tunnelInterface)), &links); err != nil || len(links) != 1 {
			t.Fatalf("cannot read real TUN capabilities: %v", err)
		}
		features := parsePluginControlOffloadFeatures(run("", "ethtool", "-k", tunnelInterface))
		want := driver == "sing_box" && links[0].LinkInfo.InfoData.VNetHeader && features["tx"] && features["sg"] && features["tso"] && features["gso"]
		var response struct {
			Result struct {
				TUNGSO bool `json:"tun_gso"`
			} `json:"result"`
		}
		body := api("POST", "/api/plugins/vpn_core/actions/inspect", map[string]any{"payload": map[string]any{"key": "default"}})
		if err := json.Unmarshal(body, &response); err != nil || response.Result.TUNGSO != want {
			t.Fatalf("TUN GSO decision = %s, want %t: %v", body, want, err)
		}
		boundary, err := newPluginControlNetAdmin().LinkGet(wanInterface)
		if err != nil || (boundary.GSOMaxSegs > 1) != want {
			t.Fatalf("WAN boundary GSO does not match TUN: %+v want=%t err=%v", boundary, want, err)
		}
	}
	checkTUNBoundary()
	if got := ip("route", "get", "192.0.2.2"); !strings.Contains(got, "dev wan") {
		t.Fatal("recursive outer route: " + got)
	}
	if got := ip("route", "show", "default"); strings.Contains(got, "veerwg") || strings.Contains(got, "vwg") {
		t.Fatal("host default route changed: " + got)
	}
	childID := create("port0", wanInterface, natSource)
	waitNAT(childID, natSource)
	probe(selected, selectedSource)
	probe(direct, "192.0.2.1")
	if driver != "" {
		// Kill the real proxy leader, not the daemon, and require a new supervised
		// generation before probing the encrypted path again.
		readProcess := func() pluginProcessStatus {
			var response struct {
				Result struct {
					Process pluginProcessStatus `json:"process"`
				} `json:"result"`
			}
			body := api("POST", "/api/plugins/vpn_core/actions/inspect", map[string]any{"payload": map[string]any{"key": "default"}})
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatal(err)
			}
			return response.Result.Process
		}
		before := readProcess()
		if before.PID == 0 {
			t.Fatal("missing managed core status", before)
		}
		if err := syscall.Kill(before.PID, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		end := time.Now().Add(15 * time.Second)
		for {
			next := readProcess()
			if next.State == "running" && next.Starts > before.Starts {
				break
			}
			if time.Now().After(end) {
				t.Fatal("managed core did not restart", next)
			}
			time.Sleep(100 * time.Millisecond)
		}
		probe(selected, selectedSource)
		probe(direct, "192.0.2.1")
		checkTUNBoundary()
	}
	// A 2 MiB echo in each direction crosses the tunnel MTU many times.
	ready := filepath.Join(t.TempDir(), "bulk-ready")
	bulk := exec.Command("ip", "netns", "exec", remote, os.Args[0], "-test.run=^TestWireGuardMeshLinuxIntegration$")
	bulk.Env = append(os.Environ(), "VEER_WG_BULK=server", "VEER_WG_BULK_READY="+ready)
	var bulkLogs bytes.Buffer
	bulk.Stdout = &bulkLogs
	bulk.Stderr = &bulkLogs
	if err := bulk.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if bulk.ProcessState == nil {
			_ = bulk.Process.Kill()
			_ = bulk.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bulk server not ready: %s", bulkLogs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	client := exec.Command("ip", "netns", "exec", selected, os.Args[0], "-test.run=^TestWireGuardMeshLinuxIntegration$")
	client.Env = append(os.Environ(), "VEER_WG_BULK=client")
	if out, err := client.CombinedOutput(); err != nil {
		t.Fatalf("bulk client: %v: %s", err, out)
	}
	if err := bulk.Wait(); err != nil {
		t.Fatalf("bulk server: %v: %s", err, bulkLogs.String())
	}

	// Both directions must remain on the real core TC engine.
	workers := api("GET", "/api/workers", nil)
	if !bytes.Contains(workers, []byte(`"tc"`)) {
		t.Fatal("TC core missing from worker status")
	}
	var view KernelRuntimeResponse
	if err := json.Unmarshal(api("GET", "/api/kernel/runtime", nil), &view); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, engine := range view.Engines {
		if engine.Name == kernelEngineTC && engine.FlowsMapEntries > 0 {
			found = true
			t.Logf("TC core flow entries after WG probes: %d", engine.FlowsMapEntries)
		}
	}
	if !found {
		t.Fatal("WG probes did not create core flow entries")
	}

	if os.Getenv("VEER_RUN_KFUNCS_TESTS") == "1" {
		before, err := os.ReadFile("/sys/module/veer_kfuncs/parameters/instance")
		if err != nil {
			t.Fatal(err)
		}
		serverReady, connected := filepath.Join(work, "stream-ready"), filepath.Join(work, "stream-connected")
		release := filepath.Join(work, "stream-release")
		startStream := func(ns, role string) *exec.Cmd {
			p := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestWireGuardMeshLinuxIntegration$")
			p.Env = append(os.Environ(), "VEER_WG_BULK=stream-"+role, "VEER_WG_BULK_READY="+serverReady, "VEER_WG_STREAM_CONNECTED="+connected, "VEER_WG_STREAM_RELEASE="+release)
			p.Stdout = logFile
			p.Stderr = logFile
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if p.ProcessState == nil {
					_ = p.Process.Kill()
					_ = p.Wait()
				}
			})
			return p
		}
		waitFile := func(path string) {
			t.Helper()
			end := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(path); err == nil {
					return
				}
				if time.Now().After(end) {
					t.Fatal("stream did not become ready")
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		streamServer := startStream(remote, "server")
		waitFile(serverReady)
		streamClient := startStream(selected, "client")
		waitFile(connected)
		if err := os.WriteFile(hotMarker, []byte("1"), 0600); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("hot restart shutdown: %v", err)
		}
		cmd = exec.Command(buildDataplanePerfBinary(t, root), "--config", configPath)
		cmd.Env = append(os.Environ(), "VEER_HOT_RESTART_MARKER="+hotMarker)
		cmd.Dir = work
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waitForEgressNATIntegrationAPIWithTimeout(t, base, cmd, logPath, 45*time.Second)
		waitForEgressNATIntegrationPluginAction(t, base, cmd, logPath, "vpn_core", "apply")
		if err := os.Remove(hotMarker); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(release, []byte("1"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := streamClient.Wait(); err != nil {
			t.Fatalf("live TCP stream lost during hot restart: %v", err)
		}
		if err := streamServer.Wait(); err != nil {
			t.Fatalf("stream server: %v", err)
		}
		after, err := os.ReadFile("/sys/module/veer_kfuncs/parameters/instance")
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("hot restart replaced the kernel module: %v", err)
		}
		t.Log("live TCP stream and module load identity survived daemon hot restart")
	}

	// Abrupt daemon loss preserves applied intent and the next startup rebuilds the adapter.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	cmd = exec.Command(buildDataplanePerfBinary(t, root), "--config", configPath)
	cmd.Env = append(os.Environ(), "VEER_HOT_RESTART_MARKER="+hotMarker)
	cmd.Dir = work
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForEgressNATIntegrationAPIWithTimeout(t, base, cmd, logPath, 45*time.Second)
	waitForEgressNATIntegrationPluginAction(t, base, cmd, logPath, "vpn_core", "apply")
	probe(selected, selectedSource)
	probe(direct, "192.0.2.1")
	ip("link", "set", tunnelInterface, "down")
	action("apply")
	probe(selected, selectedSource)
	// Pause userspace to observe the failure before the repair timer can hide it.
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Signal(syscall.SIGCONT) })
	ip("link", "del", tunnelInterface)
	leakReady := filepath.Join(t.TempDir(), "leak-ready")
	leakServer := exec.Command("ip", "netns", "exec", remote, os.Args[0], "-test.run=^TestWireGuardMeshLinuxIntegration$")
	leakServer.Env = append(os.Environ(), "VEER_WG_BULK=leak-server", "VEER_WG_BULK_READY="+leakReady)
	var leakLogs bytes.Buffer
	leakServer.Stdout = &leakLogs
	leakServer.Stderr = &leakLogs
	if err := leakServer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if leakServer.ProcessState == nil {
			_ = leakServer.Process.Kill()
			_ = leakServer.Wait()
		}
	})
	leakDeadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(leakReady); err == nil {
			break
		}
		if time.Now().After(leakDeadline) {
			t.Fatal("leak listener not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// TCP must fail even when the parent has a healthy ordinary WAN. ICMP
	// alone would be a weak leak test for a proxy that cannot carry ICMP.
	check := exec.Command("ip", "netns", "exec", selected, os.Args[0], "-test.run=^TestWireGuardMeshLinuxIntegration$")
	check.Env = append(os.Environ(), "VEER_WG_BULK=leak-client")
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("missing tunnel TCP isolation: %v: %s", err, out)
	}
	if err := leakServer.Wait(); err != nil {
		t.Fatalf("missing tunnel leaked selected traffic: %v: %s", err, leakLogs.String())
	}
	if out, err := exec.Command("ip", "netns", "exec", selected, "ping", "-n", "-c", "1", "-W", "1", "203.0.113.1").CombinedOutput(); err == nil {
		t.Fatalf("missing WG leaked selected traffic: %s", out)
	}
	ip("netns", "exec", direct, "ping", "-n", "-c", "1", "-W", "1", "203.0.113.1")
	_ = cmd.Process.Signal(syscall.SIGCONT)
	deadline = time.Now().Add(15 * time.Second)
	for {
		if exec.Command("ip", "link", "show", tunnelInterface).Run() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("repair timer did not recreate WG")
		}
		time.Sleep(100 * time.Millisecond)
	}
	probe(selected, selectedSource)
	// Deleting a child override restores the parent's ordinary WAN.
	api("DELETE", fmt.Sprintf("/api/egress-nats?id=%d", childID), nil)
	probe(selected, "192.0.2.1")
	action("teardown")
	probe(selected, "192.0.2.1")
	probe(direct, "192.0.2.1")
	action("apply")
	probe(direct, "192.0.2.1")
	action("teardown")
	probe(selected, "192.0.2.1")
	probe(direct, "192.0.2.1")
	if got := ip("-j", "link", "show"); strings.Contains(got, tunnelInterface) || strings.Contains(got, wanInterface) {
		t.Fatal("WG WAN links remain: " + got)
	}
	t.Log("TCP/UDP/ICMP: selected child used WG SNAT, sibling used ordinary WAN; interface rebuild and teardown/reapply passed")
}

// Subprocess helper: ordinary TCP sockets exercise GSO/checksums and MSS through the whole path.
func runWireGuardBulkHelper(t *testing.T, role string) {
	t.Helper()
	if role == "leak-client" {
		conn, err := net.DialTimeout("tcp4", "203.0.113.1:24004", time.Second)
		if err == nil {
			_ = conn.Close()
			t.Fatal("missing tunnel leaked TCP onto the direct WAN")
		}
		return
	}
	if role == "leak-server" {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 24004})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
		if err := os.WriteFile(os.Getenv("VEER_WG_BULK_READY"), []byte("1"), 0600); err != nil {
			t.Fatal(err)
		}
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
			t.Fatal("selected TCP reached direct WAN while tunnel was absent")
		}
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatal(err)
		}
		return
	}
	if strings.HasPrefix(role, "stream-") {
		runWireGuardStreamHelper(t, role)
		return
	}
	payload := bytes.Repeat([]byte("wireguard-bulk-check"), 110377)
	var conn net.Conn
	if role == "server" {
		listener, err := net.Listen("tcp4", "203.0.113.1:24002")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := os.WriteFile(os.Getenv("VEER_WG_BULK_READY"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		conn, err = listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		expected := "10.77.0.1"
		if os.Getenv("VEER_TEST_VPN_DRIVER") != "" {
			expected = "203.0.113.1"
		}
		if host, _, _ := net.SplitHostPort(conn.RemoteAddr().String()); host != expected {
			t.Fatalf("bulk bypassed WG: %s", host)
		}
	} else {
		var err error
		conn, err = net.DialTimeout("tcp4", "203.0.113.1:24002", 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if role == "client" {
		if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("bulk payload corrupted")
	}
	if role == "server" {
		if _, err := io.Copy(conn, bytes.NewReader(received)); err != nil {
			t.Fatal(err)
		}
	}
}

// A single connection exchanges data across the daemon transition. A reconnect
// would hide a flow reset, so neither endpoint retries a failed socket.
func runWireGuardStreamHelper(t *testing.T, role string) {
	t.Helper()
	var conn net.Conn
	var err error
	if role == "stream-server" {
		listener, e := net.Listen("tcp4", "203.0.113.1:24003")
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		if err = os.WriteFile(os.Getenv("VEER_WG_BULK_READY"), []byte("1"), 0600); err != nil {
			t.Fatal(err)
		}
		conn, err = listener.Accept()
	} else {
		conn, err = net.DialTimeout("tcp4", "203.0.113.1:24003", 5*time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(90 * time.Second))
	payload := bytes.Repeat([]byte("stream"), 700)
	finalPayload := bytes.Repeat([]byte("finish"), 700)
	buf := make([]byte, len(payload))
	for i := 0; ; i++ {
		if role == "stream-client" {
			if i >= 100 {
				if _, err := os.Stat(os.Getenv("VEER_WG_STREAM_RELEASE")); err == nil {
					payload = finalPayload
				}
			}
			if _, err = io.Copy(conn, bytes.NewReader(payload)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		finished := bytes.Equal(buf, finalPayload)
		if !bytes.Equal(buf, payload) && !(role == "stream-server" && finished) {
			t.Fatal("stream payload corrupted")
		}
		if role == "stream-server" {
			if _, err = io.Copy(conn, bytes.NewReader(buf)); err != nil {
				t.Fatal(err)
			}
			if finished {
				return
			}
		} else {
			if finished {
				return
			}
			if i == 0 {
				if err = os.WriteFile(os.Getenv("VEER_WG_STREAM_CONNECTED"), []byte("1"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
