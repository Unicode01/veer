package app

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
)

const vpnMultiTarget = "203.0.113.1:24010"

func TestVPNMultiExitTCAttachmentRollback(t *testing.T) {
	if os.Getenv("VEER_RUN_VPN_CORE_TESTS") != "1" {
		t.Skip("requires privileged VPN integration environment")
	}
	if os.Getenv("VEER_VPN_ROLLBACK_CHILD") != "1" {
		cmd := exec.Command("unshare", "--net", "--", os.Args[0], "-test.run=^TestVPNMultiExitTCAttachmentRollback$", "-test.v", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "VEER_VPN_ROLLBACK_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated attachment rollback: %v: %s", err, output)
		}
		return
	}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "rollback0"}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	program := func(name string, action int32) *ebpf.Program {
		t.Helper()
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, action), asm.Return()}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		return p
	}
	old, candidate, foreign := program("old", 0), program("candidate", 2), program("foreign", 0)
	rt := &linuxKernelRuleRuntime{}
	attach := func(dst *[]kernelAttachment, handle uint16, prog *ebpf.Program) {
		t.Helper()
		if err := rt.attachProgramLocked(dst, link.Attrs().Index, netlink.HANDLE_MIN_INGRESS, 49100, handle, "rollback", prog); err != nil {
			t.Fatal(err)
		}
	}
	attach(&rt.attachments, 1, old)
	attach(&rt.attachments, 3, old)
	var installed []kernelAttachment
	attach(&installed, 1, candidate)
	attach(&installed, 2, candidate)
	attach(&installed, 3, candidate)
	var external []kernelAttachment
	attach(&external, 3, foreign)
	if err := rt.attachProgramLocked(&installed, 1<<30, netlink.HANDLE_MIN_INGRESS, 49100, 1, "rollback", candidate); err == nil {
		t.Fatal("missing target interface did not fail")
	}
	rt.discardAttachmentsLocked(installed)
	if !pluginTCFilterExists(rt.attachments[0].filter) || pluginTCFilterExists(installed[0].filter) {
		t.Fatal("rollback lost the original live program")
	}
	if pluginTCFilterExists(installed[1].filter) {
		t.Fatal("rollback leaked a new candidate slot")
	}
	if !pluginTCFilterExists(external[0].filter) {
		t.Fatal("rollback removed an external replacement")
	}
}

// All three VPN drivers share one live daemon and plugin object. Each has its
// own physical uplink; a fourth uplink carries the ordinary WAN. Healthy
// clients retain their original TCP and UDP sockets across every foreign fault.
func TestVPNMultiExitLinuxIntegration(t *testing.T) {
	if role := os.Getenv("VEER_VPN_MULTI_ROLE"); role != "" {
		runVPNMultiHelper(t, role)
		return
	}
	if os.Getenv("VEER_RUN_VPN_CORE_TESTS") != "1" {
		t.Skip("set VEER_RUN_VPN_CORE_TESTS=1 with real Mihomo and sing-box binaries")
	}
	if os.Geteuid() != 0 {
		t.Fatal("VPN multi-exit integration requires root")
	}
	for _, tool := range []string{"ip", "wg", "tc", "sysctl", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"VEER_TEST_MIHOMO", "VEER_TEST_SING_BOX"} {
		if _, err := os.Stat(os.Getenv(name)); err != nil {
			t.Fatalf("%s must name a real core: %v", name, err)
		}
	}
	if os.Getenv("VEER_VPN_MULTI_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--", os.Args[0], "-test.run=^TestVPNMultiExitLinuxIntegration$", "-test.v", "-test.timeout=8m")
		cmd.Env = append(os.Environ(), "VEER_VPN_MULTI_CHILD=1")
		var output vpnMultiLog
		writer := io.MultiWriter(&output, os.Stdout)
		cmd.Stdout, cmd.Stderr = writer, writer
		err := cmd.Run()
		if err != nil {
			t.Fatalf("isolated multi-exit test: %v\n%s", err, output.String())
		}
		return
	}
	runVPNMultiTopology(t)
}

type vpnMultiProgress struct {
	Exchanges uint64
	TCP       string
	UDP       string
	Error     string
}

type vpnMultiClient struct {
	cmd            *exec.Cmd
	log            vpnMultiLog
	progress, stop string
	done           chan error
}

type vpnMultiLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *vpnMultiLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *vpnMultiLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

type vpnMultiExit struct {
	key, driver, ns, tunnel, local, pipeline, source, natSource string
	client                                                      *vpnMultiClient
	exchanges                                                   uint64
}

func runVPNMultiTopology(t *testing.T) {
	root, work := findRepoRoot(t), t.TempDir()
	run := func(input, command string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, command, args...)
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			if input != "" || command == "wg" {
				t.Fatalf("%s failed: %v", command, err)
			}
			t.Fatalf("%s %v: %v: %s", command, args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	ip := func(args ...string) string { t.Helper(); return run("", "ip", args...) }
	remote := fmt.Sprintf("vmr-%d", os.Getpid())
	exits := []*vpnMultiExit{
		{key: "wg1", driver: "wireguard", tunnel: "vwgwg1", local: "veerwg1", pipeline: "veerwgp1", source: "10.77.0.1", natSource: "10.77.0.1"},
		{key: "mh1", driver: "mihomo", tunnel: "vtunmh1", local: "veervpn2", pipeline: "veervpnp2", source: "198.51.100.11"},
		{key: "sb1", driver: "sing_box", tunnel: "vtunsb1", local: "veervpn3", pipeline: "veervpnp3", source: "198.51.100.12"},
		{key: "direct", driver: "direct", local: "wan3", source: "192.0.5.1", natSource: "192.0.5.1"},
	}
	for i, exit := range exits {
		exit.ns = fmt.Sprintf("vmc%d-%d", i, os.Getpid())
	}
	for _, ns := range []string{remote, exits[0].ns, exits[1].ns, exits[2].ns, exits[3].ns} {
		ip("netns", "add", ns)
		ns := ns
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		ip("-n", ns, "link", "set", "lo", "up")
	}
	ip("link", "set", "lo", "up")
	run("", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2")
	ip("link", "add", "br-lan", "type", "bridge")
	ip("addr", "add", "192.168.10.1/24", "dev", "br-lan")
	ip("link", "set", "br-lan", "up")
	for i, exit := range exits {
		host, peer := fmt.Sprintf("port%d", i), fmt.Sprintf("client%d", i)
		ip("link", "add", host, "type", "veth", "peer", "name", peer)
		ip("link", "set", host, "master", "br-lan")
		ip("link", "set", host, "up")
		ip("link", "set", peer, "netns", exit.ns)
		ip("-n", exit.ns, "addr", "add", fmt.Sprintf("192.168.10.%d/24", 20+i), "dev", peer)
		ip("-n", exit.ns, "link", "set", peer, "up")
		ip("-n", exit.ns, "route", "add", "default", "via", "192.168.10.1")
	}
	createUplink := func(i int) {
		t.Helper()
		wan, outside := fmt.Sprintf("wan%d", i), fmt.Sprintf("outside%d", i)
		ip("link", "add", wan, "type", "veth", "peer", "name", outside)
		ip("link", "set", outside, "netns", remote)
		ip("addr", "add", fmt.Sprintf("192.0.%d.1/24", i+2), "dev", wan)
		ip("link", "set", wan, "up")
		// A removed uplink must not reach this test ISP through the ordinary
		// default WAN just because all peers share the disposable backend netns.
		ip("route", "replace", "blackhole", fmt.Sprintf("192.0.%d.2/32", i+2), "metric", "32760")
		ip("route", "add", fmt.Sprintf("192.0.%d.2/32", i+2), "dev", wan, "metric", "10")
		ip("-n", remote, "addr", "add", fmt.Sprintf("192.0.%d.2/24", i+2), "dev", outside)
		ip("-n", remote, "link", "set", outside, "up")
	}
	for i := range exits {
		createUplink(i)
	}
	ip("route", "add", "default", "via", "192.0.5.2")
	ip("-n", remote, "route", "add", "192.168.10.0/24", "via", "192.0.5.1")
	for _, address := range []string{"203.0.113.1/32", "198.51.100.11/32", "198.51.100.12/32"} {
		ip("-n", remote, "addr", "add", address, "dev", "lo")
	}
	localPrivate, peerPrivate := run("", "wg", "genkey"), run("", "wg", "genkey")
	localPublic, peerPublic := run(localPrivate+"\n", "wg", "pubkey"), run(peerPrivate+"\n", "wg", "pubkey")
	ip("-n", remote, "link", "add", "wgpeer", "type", "wireguard")
	run("[Interface]\nPrivateKey = "+peerPrivate+"\nListenPort = 51820\n[Peer]\nPublicKey = "+localPublic+"\nAllowedIPs = 10.77.0.1/32\n", "ip", "netns", "exec", remote, "/usr/bin/wg", "syncconf", "wgpeer", "/dev/stdin")
	ip("-n", remote, "addr", "add", "10.77.0.2/32", "dev", "wgpeer")
	ip("-n", remote, "link", "set", "wgpeer", "up")
	ip("-n", remote, "route", "add", "10.77.0.1/32", "dev", "wgpeer")

	startProcess := func(cmd *exec.Cmd) {
		t.Helper()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Signal(syscall.SIGCONT)
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
	serverConfig := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{}, "outbounds": []any{}, "route": map[string]any{"rules": []any{}}}
	for i, source := range []string{"198.51.100.11", "198.51.100.12"} {
		tag := fmt.Sprintf("peer%d", i)
		serverConfig["inbounds"] = append(serverConfig["inbounds"].([]any), map[string]any{"type": "shadowsocks", "tag": tag, "listen": fmt.Sprintf("192.0.%d.2", i+3), "listen_port": 8388, "method": "aes-128-gcm", "password": "multi-exit-test-only"})
		serverConfig["outbounds"] = append(serverConfig["outbounds"].([]any), map[string]any{"type": "direct", "tag": tag, "inet4_bind_address": source})
		routes := serverConfig["route"].(map[string]any)
		routes["rules"] = append(routes["rules"].([]any), map[string]any{"inbound": []string{tag}, "action": "route", "outbound": tag})
	}
	configJSON, _ := json.Marshal(serverConfig)
	peerConfig := filepath.Join(work, "peer.json")
	if err := os.WriteFile(peerConfig, configJSON, 0600); err != nil {
		t.Fatal(err)
	}
	startProcess(exec.Command("ip", "netns", "exec", remote, os.Getenv("VEER_TEST_SING_BOX"), "run", "-c", peerConfig))
	ready := filepath.Join(work, "echo-ready")
	leakLog := filepath.Join(work, "leaked-probes")
	server := exec.Command("ip", "netns", "exec", remote, os.Args[0], "-test.run=^TestVPNMultiExitLinuxIntegration$")
	server.Env = append(os.Environ(), "VEER_VPN_MULTI_ROLE=server", "VEER_VPN_MULTI_READY="+ready, "VEER_VPN_MULTI_LEAK_LOG="+leakLog)
	startProcess(server)
	if tcpdump, err := exec.LookPath("tcpdump"); err == nil {
		for _, ns := range []string{"", remote} {
			var captured vpnMultiLog
			args := []string{"-i", "any", "-nn", "-e", "-l", "-tttt", "tcp and (port 24010 or port 8388) and (tcp[tcpflags] & tcp-rst != 0)"}
			cmd := exec.Command(tcpdump, args...)
			if ns != "" {
				cmd = exec.Command("ip", append([]string{"netns", "exec", ns, tcpdump}, args...)...)
			}
			cmd.Stdout, cmd.Stderr = &captured, &captured
			startProcess(cmd)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("RST capture namespace %q:\n%s", ns, captured.String())
				}
			})
		}
	}
	for end := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatal("multi-exit echo server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, id := range []string{"wan_core", "vpn_core"} {
		copyDirForTest(t, filepath.Join(root, "plugins", id), filepath.Join(work, "plugins", id))
	}
	enabled, disabled := true, false
	cfg := Config{WebBind: "127.0.0.1", WebPort: freeTCPPort(t), WebToken: egressNATTestToken,
		PluginAdminToken: "vpn-multi-integration-admin", MaxWorkers: 1, DefaultEngine: ruleEngineKernel,
		KernelEngineOrder: []string{kernelEngineTC}, PluginsDir: filepath.Join(work, "plugins"),
		PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled, PluginsIsolationSetting: &disabled,
		PluginsMinSandboxLevel: pluginSandboxLevelNone, PluginsRequireSigned: &disabled,
		Experimental: map[string]bool{experimentalFeatureKernelTCPreparedL2: true}}
	data, _ := json.Marshal(cfg)
	configPath, logPath := filepath.Join(work, "config.json"), filepath.Join(work, "veer.log")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	daemon := exec.Command(buildDataplanePerfBinary(t, root), "--config", configPath)
	daemon.Env = append(os.Environ(), "VEER_HOT_RESTART_MARKER="+filepath.Join(work, "hot-restart"))
	daemon.Dir, daemon.Stdout, daemon.Stderr = work, logFile, logFile
	startProcess(daemon)
	t.Cleanup(func() {
		_ = daemon.Process.Signal(syscall.SIGCONT)
		if t.Failed() {
			logs, _ := os.ReadFile(logPath)
			t.Logf("multi-exit daemon log:\n%s", logs)
		}
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.WebPort)
	waitForEgressNATIntegrationAPIWithTimeout(t, base, daemon, logPath, 45*time.Second)
	waitForEgressNATIntegrationPluginAction(t, base, daemon, logPath, "vpn_core", "apply")
	api := func(method, path string, payload any, allowFailure bool) []byte {
		t.Helper()
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+cfg.WebToken)
		req.Header.Set(pluginAdminTokenHeader, cfg.PluginAdminToken)
		req.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
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
	action := func(exit *vpnMultiExit, name string, failed bool) []byte {
		t.Helper()
		return api("POST", "/api/plugins/vpn_core/actions/"+name, map[string]any{"payload": map[string]any{"key": exit.key}}, failed)
	}
	status := func(exit *vpnMultiExit) (string, string) {
		t.Helper()
		var response struct {
			Records []struct {
				Key  string `json:"key"`
				Data struct {
					Phase  string
					Source string `json:"egress_nat_source_ip"`
				} `json:"data"`
			} `json:"records"`
		}
		if err := json.Unmarshal(api("GET", "/api/plugins/vpn_core/resources/status", nil, false), &response); err != nil {
			t.Fatal(err)
		}
		for _, record := range response.Records {
			if record.Key == exit.key {
				return record.Data.Phase, record.Data.Source
			}
		}
		return "missing", ""
	}
	waitApplied := func(exit *vpnMultiExit) {
		t.Helper()
		for end := time.Now().Add(25 * time.Second); ; {
			phase, source := status(exit)
			if phase == "applied" {
				if exit.natSource != "" && source != exit.natSource {
					t.Fatalf("%s changed WAN source %s -> %s", exit.key, exit.natSource, source)
				}
				exit.natSource = source
				return
			}
			if time.Now().After(end) {
				t.Fatalf("%s did not recover, phase=%s", exit.key, phase)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	for i, exit := range exits[:3] {
		profile := map[string]any{"driver": exit.driver, "slot": i + 1}
		if i == 0 {
			profile["listen_port"], profile["addresses"] = 51821, []string{"10.77.0.1/32"}
			profile["peers"] = []any{map[string]any{"public_key": peerPublic, "endpoint": "192.0.2.2:51820", "allowed_ips": []string{"0.0.0.0/0"}, "keepalive": 1}}
			api("POST", "/api/plugins/vpn_core/actions/set_key", map[string]any{"payload": map[string]any{"key": exit.key, "value": localPrivate}}, false)
		} else {
			profile["upstream_interface"] = fmt.Sprintf("wan%d", i)
			profile["core_path"] = os.Getenv("VEER_TEST_MIHOMO")
			if i == 2 {
				profile["core_path"] = os.Getenv("VEER_TEST_SING_BOX")
			}
			share := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:multi-exit-test-only")) + fmt.Sprintf("@192.0.%d.2:8388#multi", i+2)
			api("POST", "/api/plugins/vpn_core/actions/set_core_config", map[string]any{"payload": map[string]any{"key": exit.key, "driver": exit.driver, "format": "links", "value": share}}, false)
		}
		api("POST", "/api/plugins/vpn_core/resources/profiles", map[string]any{"key": exit.key, "data": profile, "enabled": true}, false)
		action(exit, "apply", false)
		waitApplied(exit)
	}
	for i, exit := range exits {
		payload := map[string]any{"parent_interface": "br-lan", "out_interface": exit.local, "out_source_ip": exit.natSource, "protocol": "tcp+udp+icmp"}
		if i != 3 {
			payload["child_interface"], payload["redirect_mode"] = fmt.Sprintf("port%d", i), egressNATRedirectModePreparedL2
		}
		api("POST", "/api/egress-nats", payload, false)
	}
	for end := time.Now().Add(20 * time.Second); ; {
		var entries []EgressNATStatus
		if err := json.Unmarshal(api("GET", "/api/egress-nats", nil, false), &entries); err != nil {
			t.Fatal(err)
		}
		ready := len(entries) == len(exits)
		for _, entry := range entries {
			ready = ready && entry.Status == "running" && entry.EffectiveEngine == ruleEngineKernel && entry.EffectiveKernelEngine == kernelEngineTC
		}
		if ready {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("multi-exit NATs did not enter TC: %+v", entries)
		}
		time.Sleep(100 * time.Millisecond)
	}
	readProgress := func(client *vpnMultiClient) vpnMultiProgress {
		t.Helper()
		var value vpnMultiProgress
		data, err := os.ReadFile(client.progress)
		if err != nil || json.Unmarshal(data, &value) != nil {
			return value
		}
		if value.Error != "" {
			t.Fatalf("long connection failed: %s\n%s", value.Error, client.log.String())
		}
		return value
	}
	stopClient := func(exit *vpnMultiExit) {
		t.Helper()
		client := exit.client
		if client == nil {
			return
		}
		exit.client = nil
		_ = os.WriteFile(client.stop, nil, 0600)
		select {
		case err := <-client.done:
			if err != nil {
				t.Fatalf("%s client: %v: %s", exit.key, err, client.log.String())
			}
		case <-time.After(5 * time.Second):
			_ = client.cmd.Process.Kill()
			<-client.done
			t.Fatalf("%s client did not stop", exit.key)
		}
		exit.exchanges += readProgress(client).Exchanges
	}
	startClient := func(exit *vpnMultiExit) {
		t.Helper()
		dir := t.TempDir()
		client := &vpnMultiClient{progress: filepath.Join(dir, "progress.json"), stop: filepath.Join(dir, "stop"), done: make(chan error, 1)}
		client.cmd = exec.Command("ip", "netns", "exec", exit.ns, os.Args[0], "-test.run=^TestVPNMultiExitLinuxIntegration$")
		client.cmd.Env = append(os.Environ(), "VEER_VPN_MULTI_ROLE=client", "VEER_VPN_MULTI_SOURCE="+exit.source, "VEER_VPN_MULTI_PROGRESS="+client.progress, "VEER_VPN_MULTI_STOP="+client.stop)
		client.cmd.Stdout, client.cmd.Stderr = &client.log, &client.log
		if err := client.cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { client.done <- client.cmd.Wait() }()
		exit.client = client
		t.Cleanup(func() {
			_ = os.WriteFile(client.stop, nil, 0600)
			if exit.client == client {
				select {
				case <-client.done:
				case <-time.After(3 * time.Second):
					_ = client.cmd.Process.Kill()
					<-client.done
				}
			}
		})
		for end := time.Now().Add(8 * time.Second); ; {
			if readProgress(client).Exchanges >= 3 {
				return
			}
			select {
			case err := <-client.done:
				exit.client = nil
				t.Fatalf("%s client startup: %v: %s", exit.key, err, client.log.String())
			default:
			}
			if time.Now().After(end) {
				t.Fatalf("%s client made no progress: %s", exit.key, client.log.String())
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	waitTraffic := func(exit *vpnMultiExit) {
		t.Helper()
		for end := time.Now().Add(25 * time.Second); ; {
			cmd := exec.Command("ip", "netns", "exec", exit.ns, os.Args[0], "-test.run=^TestVPNMultiExitLinuxIntegration$")
			cmd.Env = append(os.Environ(), "VEER_VPN_MULTI_ROLE=probe", "VEER_VPN_MULTI_SOURCE="+exit.source)
			output, err := cmd.CombinedOutput()
			if err == nil {
				return
			}
			if time.Now().After(end) {
				t.Fatalf("%s traffic did not recover: %v: %s", exit.key, err, output)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	for _, exit := range exits {
		startClient(exit)
	}
	assertHealthy := func() {
		t.Helper()
		for _, exit := range exits {
			if exit.client == nil {
				continue
			}
			before := readProgress(exit.client)
			for end := time.Now().Add(3 * time.Second); ; {
				after := readProgress(exit.client)
				if after.Exchanges > before.Exchanges {
					if after.TCP != before.TCP || after.UDP != before.UDP {
						t.Fatalf("%s silently reconnected", exit.key)
					}
					break
				}
				if time.Now().After(end) {
					t.Fatalf("%s healthy flow stopped", exit.key)
				}
				time.Sleep(25 * time.Millisecond)
			}
		}
	}
	assertBlocked := func(exit *vpnMultiExit) {
		t.Helper()
		probe := fmt.Sprintf("leak-probe-%s-%d", exit.key, time.Now().UnixNano())
		cmd := exec.Command("ip", "netns", "exec", exit.ns, os.Args[0], "-test.run=^TestVPNMultiExitLinuxIntegration$")
		cmd.Env = append(os.Environ(), "VEER_VPN_MULTI_ROLE=blocked", "VEER_VPN_MULTI_PROBE="+probe)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed closed test: %v: %s", exit.key, err, output)
		}
		leaked, _ := os.ReadFile(leakLog)
		for _, line := range strings.Split(strings.TrimSpace(string(leaked)), "\n") {
			// A reply-side failure can still deliver encrypted outbound traffic.
			// Only reaching the backend through another WAN violates isolation.
			if strings.Contains(line, probe) && !strings.HasPrefix(line, exit.source+"|") {
				t.Fatalf("unavailable VPN leaked traffic to backend: %s", leaked)
			}
		}
		assertHealthy()
	}
	linkIndex := func(name string) int {
		t.Helper()
		info, err := newPluginControlNetAdmin().LinkGet(name)
		if err != nil {
			t.Fatal(err)
		}
		return info.IfIndex
	}
	processPID := func(exit *vpnMultiExit) int {
		t.Helper()
		if exit.driver == "wireguard" || exit.driver == "direct" {
			return 0
		}
		var response struct {
			Result struct {
				Process pluginProcessStatus `json:"process"`
			} `json:"result"`
		}
		if err := json.Unmarshal(action(exit, "inspect", false), &response); err != nil {
			t.Fatal(err)
		}
		return response.Result.Process.PID
	}
	assertMaps := func() {
		t.Helper()
		for _, m := range vpnMultiAdapterMaps(t, daemon.Process.Pid) {
			expected := map[uint32]bool{}
			for _, exit := range exits[:3] {
				expected[uint32(linkIndex(exit.tunnel))] = true
				expected[uint32(linkIndex(exit.pipeline))] = true
			}
			iter := m.Iterate()
			var key uint32
			var value [24]byte
			for iter.Next(&key, &value) {
				if !expected[key] {
					m.Close()
					t.Fatalf("stale VPN mapping leaked for ifindex %d", key)
				}
				delete(expected, key)
			}
			m.Close()
			if err := iter.Err(); err != nil || len(expected) != 0 {
				t.Fatalf("active VPN mappings missing: %v: %v", expected, err)
			}
		}
	}
	diagnostics := func(label string) {
		t.Logf("diagnostic %s NATs: %s", label, api("GET", "/api/egress-nats", nil, false))
		for _, exit := range exits {
			links := []string{exit.local}
			if exit.driver != "direct" {
				links = append(links, exit.tunnel, exit.pipeline)
			}
			for _, name := range links {
				info, err := newPluginControlNetAdmin().LinkGet(name)
				t.Logf("diagnostic %s %s: ifindex=%d addresses=%v err=%v", label, name, info.IfIndex, info.Addresses, err)
			}
			t.Logf("diagnostic %s %s: core_pid=%d", label, exit.key, processPID(exit))
		}
		for _, m := range vpnMultiAdapterMaps(t, daemon.Process.Pid) {
			info, _ := m.Info()
			id, _ := info.ID()
			entries := map[uint32][24]byte{}
			iter := m.Iterate()
			var key uint32
			var value [24]byte
			for iter.Next(&key, &value) {
				entries[key] = value
			}
			t.Logf("diagnostic %s adapter map=%d entries=%v err=%v", label, id, entries, iter.Err())
			m.Close()
		}
	}
	diagnostics("initial")
	t.Cleanup(func() {
		_ = daemon.Process.Signal(syscall.SIGCONT)
		if t.Failed() {
			diagnostics("failure")
		}
	})
	db, err := sql.Open("sqlite", filepath.Join(work, "forward.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	setBoundaryOwner := func(exit *vpnMultiExit, owner string) {
		t.Helper()
		result, err := db.Exec("UPDATE plugin_owned_resources SET plugin_id = ? WHERE resource_type = ? AND resource_key = ?", owner, pluginOwnedResourceTypeLink, exit.local)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			t.Fatalf("boundary ownership injection affected %d rows: %v", n, err)
		}
	}
	for i, target := range exits[:3] {
		for _, fault := range []string{"map_forward_loss", "map_reply_loss", "map_corrupt", "tunnel_down_mtu", "tunnel_deleted", "tunnel_replaced", "boundary_deleted", "uplink_down", "uplink_recreated", "core_killed", "cleanup_conflict", "teardown_reapply"} {
			if filter := os.Getenv("VEER_VPN_MULTI_FAULTS"); filter != "" && !strings.Contains(","+filter+",", ","+target.driver+"/"+fault+",") {
				continue
			}
			if fault == "core_killed" && i == 0 {
				continue
			}
			t.Logf("injecting %s/%s", target.driver, fault)
			func() {
				assertHealthy()
				stopClient(target)
				targetPID := processPID(target)
				healthyIndices, healthyPIDs := map[string]int{}, map[string]int{}
				for _, other := range exits {
					if other == target {
						continue
					}
					healthyIndices[other.local] = linkIndex(other.local)
					if other.driver != "direct" {
						healthyIndices[other.tunnel] = linkIndex(other.tunnel)
						healthyIndices[other.pipeline] = linkIndex(other.pipeline)
					}
					healthyPIDs[other.key] = processPID(other)
				}
				if fault == "cleanup_conflict" || fault == "teardown_reapply" {
					if fault == "cleanup_conflict" {
						// Keep the conflicting owner active, so inactive-plugin cleanup
						// cannot erase this deliberately injected ledger conflict.
						setBoundaryOwner(target, "vpn_core")
					}
					action(target, "teardown", fault == "cleanup_conflict")
					assertBlocked(target)
					if fault == "cleanup_conflict" {
						setBoundaryOwner(target, "wan_core")
						action(target, "teardown", false)
					}
					action(target, "apply", false)
				} else {
					if err := daemon.Process.Signal(syscall.SIGSTOP); err != nil {
						t.Fatal(err)
					}
					resume := func() { _ = daemon.Process.Signal(syscall.SIGCONT) }
					defer resume()
					switch fault {
					case "map_forward_loss", "map_reply_loss", "map_corrupt":
						maps := vpnMultiAdapterMaps(t, daemon.Process.Pid)
						for _, m := range maps {
							key := uint32(linkIndex(target.pipeline))
							if fault == "map_reply_loss" {
								key = uint32(linkIndex(target.tunnel))
							}
							var err error
							if fault == "map_corrupt" {
								err = m.Update(key, [24]byte{}, ebpf.UpdateExist)
							} else {
								err = m.Delete(key)
							}
							if err != nil {
								t.Fatal(err)
							}
							m.Close()
						}
					case "tunnel_down_mtu":
						ip("link", "set", target.tunnel, "mtu", "1300", "down")
					case "tunnel_replaced":
						ip("link", "del", target.tunnel)
						ip("link", "add", target.tunnel, "type", "dummy")
						ip("link", "set", target.tunnel, "alias", "foreign-multi-test", "up")
					case "tunnel_deleted":
						ip("link", "del", target.tunnel)
					case "boundary_deleted":
						ip("link", "del", target.local)
					case "uplink_down":
						ip("link", "set", fmt.Sprintf("wan%d", i), "down")
					case "uplink_recreated":
						ip("link", "del", fmt.Sprintf("wan%d", i))
					case "core_killed":
						if targetPID <= 0 {
							t.Fatal("managed core has no PID")
						}
						if err := syscall.Kill(targetPID, syscall.SIGKILL); err != nil {
							t.Fatal(err)
						}
					}
					assertBlocked(target)
					resume()
					if fault == "tunnel_replaced" {
						time.Sleep(1500 * time.Millisecond)
						assertBlocked(target)
						if got := ip("-j", "link", "show", target.tunnel); !strings.Contains(got, "foreign-multi-test") {
							t.Fatal("foreign interface was modified")
						}
						ip("link", "del", target.tunnel)
						// The supervisor may exhaust its bounded budget while the
						// foreign device blocks TUN creation. Retry explicitly only
						// after that external ownership conflict has been removed.
						action(target, "apply", false)
					}
					if fault == "uplink_down" {
						ip("link", "set", fmt.Sprintf("wan%d", i), "up")
						// Administrative DOWN removes this fixture's static host
						// route. Restore the ISP route along with the physical link;
						// otherwise its deliberate blackhole guard still wins.
						ip("route", "replace", fmt.Sprintf("192.0.%d.2/32", i+2), "dev", fmt.Sprintf("wan%d", i), "metric", "10")
					}
					if fault == "uplink_recreated" {
						createUplink(i)
					}
				}
				waitApplied(target)
				waitTraffic(target)
				startClient(target)
				assertHealthy()
				assertMaps()
				for name, index := range healthyIndices {
					if linkIndex(name) != index {
						t.Fatalf("%s fault replaced healthy interface %s", target.key, name)
					}
				}
				for _, other := range exits {
					if other == target {
						continue
					}
					if linkIndex(other.local) != healthyIndices[other.local] || processPID(other) != healthyPIDs[other.key] {
						t.Fatalf("%s fault changed healthy %s generation", target.key, other.key)
					}
				}
				t.Logf("PASS %s/%s: healthy TCP/UDP sockets retained their original tuples and verified exit source", target.driver, fault)
			}()
		}
	}
	for _, exit := range exits {
		value := readProgress(exit.client)
		t.Logf("%s final persistent sockets: tcp=%s udp=%s total_paired_exchanges=%d", exit.key, value.TCP, value.UDP, exit.exchanges+value.Exchanges)
		stopClient(exit)
	}
	for _, exit := range exits[:3] {
		action(exit, "delete_profile", false)
	}
	for _, path := range []string{"vpn_core/resources/profiles", "vpn_core/resources/status", "wan_core/resources/profiles", "wan_core/resources/sessions", "wan_core/resources/status"} {
		var response struct {
			Records []json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(api("GET", "/api/plugins/"+path, nil, false), &response); err != nil || len(response.Records) != 0 {
			t.Fatalf("resources leaked after multi-exit deletion: %s", path)
		}
	}
	for _, exit := range exits[:3] {
		for _, name := range []string{exit.tunnel, exit.local, exit.pipeline} {
			if exec.Command("ip", "link", "show", name).Run() == nil {
				t.Fatalf("interface leaked after multi-exit deletion: %s", name)
			}
		}
	}
	var owned int
	if err := db.QueryRow("SELECT COUNT(*) FROM plugin_owned_resources WHERE plugin_id IN ('vpn_core', 'wan_core')").Scan(&owned); err != nil || owned != 0 {
		rows, queryErr := db.Query("SELECT plugin_id, resource_type, resource_key FROM plugin_owned_resources WHERE plugin_id IN ('vpn_core', 'wan_core')")
		if queryErr == nil {
			defer rows.Close()
			for rows.Next() {
				var plugin, kind, key string
				if err := rows.Scan(&plugin, &kind, &key); err == nil {
					t.Logf("diagnostic leaked owner: %s %s %s", plugin, kind, key)
				}
			}
		}
		t.Fatalf("VPN/WAN ownership ledger leaked %d resources: %v", owned, err)
	}
}

func vpnMultiAdapterMaps(t *testing.T, pid int) []*ebpf.Map {
	t.Helper()
	files, err := os.ReadDir(fmt.Sprintf("/proc/%d/fdinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[ebpf.MapID]bool{}
	var maps []*ebpf.Map
	for _, file := range files {
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, file.Name()))
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[0] != "map_id:" {
				continue
			}
			id, _ := strconv.ParseUint(fields[1], 10, 32)
			if seen[ebpf.MapID(id)] {
				continue
			}
			seen[ebpf.MapID(id)] = true
			m, err := ebpf.NewMapFromID(ebpf.MapID(id))
			if err != nil {
				continue
			}
			info, err := m.Info()
			if err != nil || info.Name != "wg_links" {
				m.Close()
				continue
			}
			maps = append(maps, m)
		}
	}
	if len(maps) == 0 {
		t.Fatal("test daemon has no VPN adapter maps")
	}
	return maps
}

func runVPNMultiHelper(t *testing.T, role string) {
	t.Helper()
	if role == "server" {
		var leakMu sync.Mutex
		recordLeak := func(host, payload string) {
			if !strings.HasPrefix(payload, "leak-probe") {
				return
			}
			leakMu.Lock()
			defer leakMu.Unlock()
			file, err := os.OpenFile(os.Getenv("VEER_VPN_MULTI_LEAK_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = fmt.Fprintf(file, "%s|%s\n", host, payload)
			file.Close()
		}
		listener, err := net.Listen("tcp4", vpnMultiTarget)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		udp, err := net.ListenPacket("udp4", vpnMultiTarget)
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		go func() {
			buf := make([]byte, 4096)
			for {
				n, addr, err := udp.ReadFrom(buf)
				if err != nil {
					return
				}
				host, _, _ := net.SplitHostPort(addr.String())
				recordLeak(host, string(buf[:n]))
				_, _ = udp.WriteTo(append([]byte(host+"|"), buf[:n]...), addr)
			}
		}()
		if err := os.WriteFile(os.Getenv("VEER_VPN_MULTI_READY"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				defer conn.Close()
				host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					recordLeak(host, line)
					if _, err := io.WriteString(conn, host+"|"+line); err != nil {
						return
					}
				}
			}()
		}
	}
	if role == "blocked" || role == "probe" {
		for _, protocol := range []string{"tcp4", "udp4"} {
			conn, err := net.DialTimeout(protocol, vpnMultiTarget, time.Second)
			if err != nil {
				if role == "probe" {
					t.Fatal(err)
				}
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			payload := os.Getenv("VEER_VPN_MULTI_PROBE") + "\n"
			if role == "probe" {
				payload = "recovery-probe\n"
			}
			_, _ = io.WriteString(conn, payload)
			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			conn.Close()
			if role == "probe" {
				if err != nil || string(buf[:n]) != os.Getenv("VEER_VPN_MULTI_SOURCE")+"|"+payload {
					t.Fatalf("recovery probe %s: %v: %q", protocol, err, buf[:n])
				}
			} else if n > 0 {
				t.Fatalf("unavailable VPN leaked %s traffic: %s", protocol, buf[:n])
			}
		}
		return
	}
	progress := vpnMultiProgress{}
	publish := func() {
		data, _ := json.Marshal(progress)
		path := os.Getenv("VEER_VPN_MULTI_PROGRESS")
		_ = os.WriteFile(path+".tmp", data, 0600)
		_ = os.Rename(path+".tmp", path)
	}
	fail := func(err error) { progress.Error = err.Error(); publish(); t.Fatal(err) }
	tcp, err := net.DialTimeout("tcp4", vpnMultiTarget, 3*time.Second)
	if err != nil {
		fail(err)
	}
	defer tcp.Close()
	udp, err := net.DialTimeout("udp4", vpnMultiTarget, 3*time.Second)
	if err != nil {
		fail(err)
	}
	defer udp.Close()
	progress.TCP, progress.UDP = tcp.LocalAddr().String(), udp.LocalAddr().String()
	reader := bufio.NewReader(tcp)
	source := os.Getenv("VEER_VPN_MULTI_SOURCE")
	for {
		if _, err := os.Stat(os.Getenv("VEER_VPN_MULTI_STOP")); err == nil {
			publish()
			return
		}
		for i, conn := range []net.Conn{tcp, udp} {
			payload := fmt.Sprintf("%d/%d/", i, progress.Exchanges) + strings.Repeat("x", []int{8192, 1100}[i]) + "\n"
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.WriteString(conn, payload); err != nil {
				fail(err)
			}
			var got string
			if i == 0 {
				got, err = reader.ReadString('\n')
			} else {
				buf := make([]byte, 4096)
				var n int
				n, err = conn.Read(buf)
				got = string(buf[:n])
			}
			if err != nil {
				fail(err)
			}
			if got != source+"|"+payload {
				fail(fmt.Errorf("%s reply changed exit source or payload: got prefix %.60q, want source %s", conn.LocalAddr(), got, source))
			}
		}
		progress.Exchanges++
		publish()
		time.Sleep(25 * time.Millisecond)
	}
}
