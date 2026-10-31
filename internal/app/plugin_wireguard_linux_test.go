package app

import (
	"bytes"
	"context"
	"encoding/json"
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

func runWireGuardMeshTopology(t *testing.T) {
	t.Helper()
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
	// Exercise the real daemon, plugin service calls, TC verifier and core NAT together.
	root, work := findRepoRoot(t), t.TempDir()
	for _, id := range []string{"wan_core", "wireguard_mesh"} {
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
	cmd := exec.Command(buildDataplanePerfBinary(t, root), "--config", configPath)
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
	waitForEgressNATIntegrationAPI(t, base, cmd, logPath)
	waitForEgressNATIntegrationPluginAction(t, base, cmd, logPath, "wireguard_mesh", "apply")
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
					if p.ID == "wireguard_mesh" {
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
		api("POST", "/api/plugins/wireguard_mesh/actions/"+id, map[string]any{"payload": map[string]any{"key": "default"}})
	}
	api("POST", "/api/plugins/wireguard_mesh/actions/set_key", map[string]any{"payload": map[string]any{"key": "default", "value": localPrivate}})
	profile := map[string]any{"slot": 1, "listen_port": 51821, "addresses": []string{"10.77.0.1/32"},
		"peers": []any{map[string]any{"public_key": remotePublic, "endpoint": "192.0.2.2:51820", "allowed_ips": []string{"0.0.0.0/0"}}}}
	api("POST", "/api/plugins/wireguard_mesh/resources/profiles", map[string]any{"key": "default", "data": profile, "enabled": true})
	action("apply")
	if got := ip("route", "get", "192.0.2.2"); !strings.Contains(got, "dev wan") {
		t.Fatal("recursive outer route: " + got)
	}
	if got := ip("route", "show", "default"); strings.Contains(got, "veerwg") || strings.Contains(got, "vwg") {
		t.Fatal("host default route changed: " + got)
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
	// Ordinary WAN uses route/neighbour resolution rather than prepared L2.
	api("POST", "/api/egress-nats", map[string]any{"parent_interface": "br-lan", "out_interface": "wan", "out_source_ip": "192.0.2.1", "protocol": "tcp+udp+icmp"})
	childID := create("port0", "veerwg1", "10.77.0.1")
	deadline := time.Now().Add(15 * time.Second)
	for {
		var entries []EgressNATStatus
		if err := json.Unmarshal(api("GET", "/api/egress-nats", nil), &entries); err != nil {
			t.Fatal(err)
		}
		ready := false
		for _, entry := range entries {
			if entry.ID == childID {
				ready = entry.Status == "running" && entry.EffectiveEngine == ruleEngineKernel && entry.EffectiveKernelEngine == kernelEngineTC && entry.OutSourceIP == "10.77.0.1"
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("WG NAT did not enter TC: %+v", entries)
		}
		time.Sleep(100 * time.Millisecond)
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
		ip("netns", "exec", ns, "ping", "-n", "-c", "2", "-W", "2", "203.0.113.1")
	}
	probe(selected, "10.77.0.1")
	probe(direct, "192.0.2.1")
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
	deadline = time.Now().Add(5 * time.Second)
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

	// Abrupt daemon loss preserves applied intent and the next startup rebuilds the adapter.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	cmd = exec.Command(buildDataplanePerfBinary(t, root), "--config", configPath)
	cmd.Dir = work
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForEgressNATIntegrationAPI(t, base, cmd, logPath)
	waitForEgressNATIntegrationPluginAction(t, base, cmd, logPath, "wireguard_mesh", "apply")
	probe(selected, "10.77.0.1")
	probe(direct, "192.0.2.1")
	ip("link", "set", "vwgdefault", "down")
	action("apply")
	probe(selected, "10.77.0.1")
	// Pause userspace to observe the failure before the repair timer can hide it.
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Signal(syscall.SIGCONT) })
	ip("link", "del", "vwgdefault")
	if out, err := exec.Command("ip", "netns", "exec", selected, "ping", "-n", "-c", "1", "-W", "1", "203.0.113.1").CombinedOutput(); err == nil {
		t.Fatalf("missing WG leaked selected traffic: %s", out)
	}
	ip("netns", "exec", direct, "ping", "-n", "-c", "1", "-W", "1", "203.0.113.1")
	_ = cmd.Process.Signal(syscall.SIGCONT)
	deadline = time.Now().Add(15 * time.Second)
	for {
		if exec.Command("ip", "link", "show", "vwgdefault").Run() == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("repair timer did not recreate WG")
		}
		time.Sleep(100 * time.Millisecond)
	}
	probe(selected, "10.77.0.1")
	// Deleting a child override restores the parent's ordinary WAN.
	api("DELETE", fmt.Sprintf("/api/egress-nats?id=%d", childID), nil)
	probe(selected, "192.0.2.1")
	action("teardown")
	action("apply")
	action("teardown")
	if got := ip("-j", "link", "show"); strings.Contains(got, "vwgdefault") || strings.Contains(got, "veerwg1") {
		t.Fatal("WG WAN links remain: " + got)
	}
	t.Log("TCP/UDP/ICMP: selected child used WG SNAT, sibling used ordinary WAN; interface rebuild and teardown/reapply passed")
}

// Subprocess helper: ordinary TCP sockets exercise GSO/checksums and MSS through the whole path.
func runWireGuardBulkHelper(t *testing.T, role string) {
	t.Helper()
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
		if host, _, _ := net.SplitHostPort(conn.RemoteAddr().String()); host != "10.77.0.1" {
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
