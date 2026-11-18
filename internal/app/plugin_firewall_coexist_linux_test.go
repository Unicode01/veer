//go:build linux

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
)

// The firewall plugin next to other bundled plugins, in a real daemon (see
// plugin_firewall_system_linux_test.go for the helpers):
//
//	FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 go test ./internal/app -run '^TestFirewallCoexist' -v
//
// TestFirewallCoexistPPPoE needs pppoe-server and pppd (Debian: pppoe, ppp)
// and a built plugins/pppoe_client; TestFirewallCoexistVPNCore needs wg
// (wireguard-tools) and unshare.

const (
	fwcPPPoEServer  = "10.233.0.1" // the server's PPP address, allowed
	fwcPPPoEClient  = "10.233.0.2" // the address IPCP gives Veer
	fwcPPPoEBlocked = "10.233.1.1" // a second source behind the server
	fwcLANHost      = "10.234.0.1"
	fwcLANClient    = "10.234.0.2"
)

var fwcPPPInterface = regexp.MustCompile(`^\d+: (ppp\d+)[:@]`)

// TestFirewallCoexistPPPoE binds the firewall to the Ethernet interface a
// pppoe_client session runs over, with a TCP policy for a port of the host,
// before dialing. Discovery, LCP (keepalives both ways) and IPCP pass the
// XDP hook; the policy filters TCP inside the PPPoE session frames (allowed
// source passes, another one is dropped); LAN traffic forwarded over the
// session through lan_core's egress NAT works; and a redial goes through
// discovery again with the firewall bound.
func TestFirewallCoexistPPPoE(t *testing.T) {
	root := fwsRequire(t)
	for _, tool := range []string{"pppoe-server", "pppd", "ethtool"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required (Debian packages pppoe and ppp): %v", tool, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "plugins", "pppoe_client", "pppoe_tunnel.o")); err != nil {
		t.Fatalf("build plugins/pppoe_client first (plugins/pppoe_client/build.sh): %v", err)
	}
	// The server's pppd needs the kernel's PPP driver (pppoe_client itself
	// does not).
	for _, module := range []string{"ppp_generic", "ppp_async", "ppp_synctty"} {
		_ = exec.Command("modprobe", module).Run()
	}
	if _, err := os.Stat("/dev/ppp"); err != nil {
		t.Fatalf("pppoe-server's pppd needs kernel PPP support (CONFIG_PPP: ppp_generic, ppp_async), which kernel %s lacks: %v", kernelRelease(), err)
	}
	suffix := fwsSuffix()
	serverNS, clientNS := "fwcs"+suffix, "fwcc"+suffix
	// The plugins' net_access patterns: pppoe_client uses wan*, wan_core
	// creates veer*, lan_core bridges br* and takes lan* ports.
	wanHost, wanPeer := truncateIfName("wanfc"+suffix), truncateIfName("wanfd"+suffix)
	localIf, pipelineIf := truncateIfName("veerfl"+suffix), truncateIfName("veerfq"+suffix)
	lanHost, lanPeer, lanBridge := truncateIfName("lanfc"+suffix), truncateIfName("lanfd"+suffix), truncateIfName("brfc"+suffix)
	work := t.TempDir()
	pidFile := filepath.Join(work, "pppoe-server.pid")
	cleanup := func() {
		if data, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				_ = exec.Command("kill", strconv.Itoa(pid)).Run()
			}
		}
		for _, ns := range []string{serverNS, clientNS} {
			if out, err := exec.Command("ip", "netns", "pids", ns).Output(); err == nil {
				for _, pid := range strings.Fields(string(out)) {
					_ = exec.Command("kill", pid).Run()
				}
			}
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
		for _, link := range []string{localIf, pipelineIf, lanBridge, lanHost, wanHost} {
			_ = exec.Command("ip", "link", "del", link).Run()
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	fwsEnableIPv4Forwarding(t)
	run := func(args ...string) string { t.Helper(); return fwsRun(t, args...) }
	offloadsOff := func(ns, dev string) {
		args := []string{"ethtool", "-K", dev, "rx", "off", "tx", "off", "sg", "off", "tso", "off", "gso", "off", "gro", "off", "lro", "off"}
		if ns != "" {
			args = append([]string{"ip", "netns", "exec", ns}, args...)
		}
		_ = exec.Command(args[0], args[1:]...).Run()
	}
	run("ip", "netns", "add", serverNS)
	run("ip", "link", "add", wanHost, "type", "veth", "peer", "name", wanPeer)
	run("ip", "link", "set", wanPeer, "netns", serverNS)
	run("ip", "link", "set", wanHost, "up")
	run("ip", "-n", serverNS, "link", "set", "lo", "up")
	run("ip", "-n", serverNS, "link", "set", wanPeer, "up")
	run("ip", "-n", serverNS, "address", "add", fwcPPPoEBlocked+"/32", "dev", "lo")
	offloadsOff("", wanHost)
	offloadsOff(serverNS, wanPeer)

	// The server's LCP echo settings follow the pppoe_client black-box test:
	// pppoe_client answers the server's echoes only while it exchanges
	// control frames (its own keepalive, the post-session window), so a
	// server that gave up after three unanswered echoes a second apart would
	// end the session with or without a firewall. What the firewall could
	// break, Veer's own LCP keepalive through the bound hook, is checked below.
	options := filepath.Join(work, "pppoe-server-options")
	pppdLog := filepath.Join(work, "pppd.log")
	if err := os.WriteFile(options, []byte("noauth\nmtu 1492\nmru 1492\nlcp-echo-interval 2\nlcp-echo-failure 30\nnodefaultroute\nnoipdefault\ndebug\nlogfile "+pppdLog+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			data, _ := os.ReadFile(pppdLog)
			t.Logf("pppd log (server side):\n%s", fwcTail(data, 6000))
		}
	})
	if out, err := exec.Command("ip", "netns", "exec", serverNS, "pppoe-server", "-I", wanPeer, "-L", fwcPPPoEServer, "-R", fwcPPPoEClient,
		"-N", "1", "-C", "veer-fw-test", "-O", options, "-T", "0", "-X", pidFile).CombinedOutput(); err != nil {
		t.Fatalf("pppoe-server: %v: %s", err, out)
	}
	fwcWaitFile(t, pidFile, 5*time.Second)
	const serverPort = 33301
	fwsStartListener(t, serverNS, fmt.Sprintf("0.0.0.0:%d", serverPort))
	hostPort := fwsHostListener(t)

	d := fwsStartDaemon(t, fwsDaemonOptions{Plugins: []string{"pppoe_client", "wan_core", "lan_core"}})
	for _, wait := range [][2]string{{"firewall", "apply"}, {"pppoe_client", "traffic_probe"}, {"wan_core", "prepare_handoff"}, {"lan_core", "apply_network"}} {
		d.waitPluginAction(wait[0], wait[1])
	}
	action := func(plugin, id string, payload map[string]any) []byte {
		t.Helper()
		return d.api("POST", "/api/plugins/"+plugin+"/actions/"+id, map[string]any{"payload": payload})
	}

	// The firewall goes first, with its policy, as on a router that dials
	// after boot.
	// VEER_FWC_PPPOE_UNBOUND=1 leaves the firewall off the WAN link, to tell
	// a firewall problem from one of the PPPoE setup: the session checks
	// still mean something, the filtering checks then fail by design.
	unbound := os.Getenv("VEER_FWC_PPPOE_UNBOUND") == "1"
	if unbound {
		d.fwSettings()
	} else {
		d.fwSettings(wanHost)
	}
	d.fwPolicy("host", []int{hostPort}, fwcPPPoEServer+"/32")
	d.fwApplyConfirm()
	if attached, mode, _ := fwsXDP(t, wanHost); !unbound && (!attached || mode != nl.XDP_ATTACHED_DRV) {
		t.Fatalf("%s: XDP attached=%t mode=%d, want native", wanHost, attached, mode)
	}

	action("wan_core", "prepare_handoff", map[string]any{
		"wan_id": "fwc", "profile_key": "fwc", "driver": "pppoe", "driver_plugin": "pppoe_client",
		"state": "prepared", "usable": false, "real_interface": wanHost, "local_interface": localIf,
		"pipeline_interface": pipelineIf, "handoff_mode": "segmented_veth", "mtu": 1492,
		"addresses": []string{fwcPPPoEClient + "/32"},
		"routes":    []map[string]string{{"dst": fwcPPPoEServer + "/32", "dev": localIf, "src": fwcPPPoEClient}},
	})
	probe := map[string]any{
		"interface": wanHost, "wan_interface": wanHost, "local_interface": localIf, "pipeline_interface": pipelineIf,
		"wan_id": "fwc", "profile_key": "fwc", "timeout_ms": 1000, "control_ack_timeout_ms": 100,
		"control_idle_timeout_ms": 10, "max_frames": 8, "negotiate_ipv4": true, "negotiate_ipv6": false,
		"request_ipv6_address": false, "request_ipv6_router": false, "request_pd": false,
		"prepare_interfaces": true, "sync_hook_bindings": true, "apply_hook_bindings": true,
		"send_padt": false, "post_session_control_ms": 5000,
		// Veer's own LCP echoes, whose replies come back through the hook.
		"keepalive_interval_ms": 500, "keepalive_failure_threshold": 2, "keepalive_failure_grace_ms": 0,
		"keepalive_confirm_timeout_ms": 250, "auto_redial": false,
		"decap_mode": "auto", "wan_core_sync": true, "wan_core_required": true, "wan_core_apply": true,
	}
	serverPPP := func() string {
		out, _ := exec.Command("ip", "-n", serverNS, "-o", "link", "show").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if m := fwcPPPInterface.FindStringSubmatch(line); m != nil {
				return m[1]
			}
		}
		return ""
	}
	waitServerRelease := func() {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for serverPPP() != "" {
			if time.Now().After(deadline) {
				t.Fatalf("the PPPoE server kept its session: %s", serverPPP())
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	type session struct {
		raw        string
		up         bool
		generation string
		phase      string
	}
	readSession := func(key string) session {
		t.Helper()
		code, out := d.request("GET", "/api/plugins/pppoe_client/resources/sessions/"+key, nil)
		if code != 200 {
			return session{raw: fmt.Sprintf("HTTP %d: %s", code, out)}
		}
		var record struct {
			Data struct {
				Phase      string `json:"phase"`
				Generation string `json:"session_generation"`
				UpdatedAt  string `json:"updated_at"`
			} `json:"data"`
		}
		_ = json.Unmarshal(out, &record)
		raw := string(out)
		return session{raw: raw, generation: record.Data.Generation, phase: record.Data.Phase + "@" + record.Data.UpdatedAt,
			up: strings.Contains(raw, `"tunnel_installed":true`) && strings.Contains(raw, `"up":true`)}
	}
	// dial runs the traffic probe (discovery, LCP, IPCP) and waits for the
	// session; one probe gets only timeout_ms, so it retries like the
	// pppoe_client black-box test.
	tryDial := func(step string) (session, string) {
		t.Helper()
		var last string
		for attempt := 1; attempt <= 5; attempt++ {
			code, out := d.request("POST", "/api/plugins/pppoe_client/actions/traffic_probe", map[string]any{"payload": probe})
			if code >= 200 && code < 300 {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					if s := readSession("last"); s.up {
						t.Logf("%s: session up after %d probe(s) on server %s", step, attempt, serverPPP())
						return s, ""
					}
					time.Sleep(200 * time.Millisecond)
				}
				last = readSession("last").raw
			} else {
				last = fmt.Sprintf("HTTP %d: %.600s", code, out)
			}
			waitServerRelease()
			time.Sleep(time.Second)
		}
		return session{}, last
	}
	dial := func(step string) session {
		t.Helper()
		s, failure := tryDial(step)
		if failure != "" {
			t.Fatalf("%s: the PPPoE session did not come up through the bound firewall: %s", step, failure)
		}
		return s
	}
	// Frames on both ends of the WAN link during the first dial: XDP drops
	// before the host's capture taps, the server's capture shows what was
	// sent.
	stopCaptures := fwcCapture(t, work, map[string]string{"host": wanHost}, map[string][2]string{"server": {serverNS, wanPeer}})
	first, failure := tryDial("first dial")
	captures := stopCaptures()
	if failure != "" {
		t.Errorf("first dial: the PPPoE session did not come up through the bound firewall: %s", failure)
		t.Logf("captures during the first dial:\n%s", captures)
		// Is it the firewall? Unbind it and dial once more.
		d.fwSettings()
		d.fwApplyConfirm()
		fwsWaitXDP(t, wanHost, false, 10*time.Second)
		if _, failure := tryDial("dial with the firewall unbound"); failure != "" {
			t.Fatalf("the PPPoE session does not come up without the firewall either (test environment): %s", failure)
		}
		t.Fatalf("the PPPoE session comes up with the firewall unbound but not with it bound to %s", wanHost)
	}
	run("ip", "route", "replace", fwcPPPoEBlocked+"/32", "dev", localIf, "src", fwcPPPoEClient)

	hostTarget := net.JoinHostPort(fwcPPPoEClient, strconv.Itoa(hostPort))
	probes := []fwsProbe{
		{"allowed", fwcPPPoEServer, hostTarget, fwcPPPoEServer},
		{"blocked", fwcPPPoEBlocked, hostTarget, fwcPPPoEBlocked},
	}
	filtered := map[string]bool{"allowed": true, "blocked": false}
	fwsExpect(t, serverNS, "TCP over PPPoE, firewall bound", probes, filtered)
	// The blocked source does get through once the policy allows it.
	d.fwPolicy("host", []int{hostPort}, fwcPPPoEServer+"/32", fwcPPPoEBlocked+"/32")
	d.fwApplyConfirm()
	fwsExpect(t, serverNS, "TCP over PPPoE, both sources allowed", probes, map[string]bool{"allowed": true, "blocked": true})
	d.fwPolicy("host", []int{hostPort}, fwcPPPoEServer+"/32")
	d.fwApplyConfirm()
	fwsExpect(t, serverNS, "TCP over PPPoE, filtered again", probes, filtered)

	// LAN traffic forwarded over the session.
	run("ip", "link", "add", lanHost, "type", "veth", "peer", "name", lanPeer)
	run("ip", "link", "set", lanHost, "up")
	action("lan_core", "apply_network", map[string]any{
		"lan_id": "fwc", "bridge": lanBridge, "ports": []string{lanHost}, "addresses": []string{fwcLANHost + "/24"},
		"mtu": 1500, "wan_ref": "fwc", "wan_egress_interface": localIf, "protocol": "tcp+udp+icmp",
		"auto_egress_nat": true, "dhcpv4_enabled": false,
	})
	t.Cleanup(func() {
		_, _ = d.request("POST", "/api/plugins/lan_core/actions/teardown", map[string]any{"payload": map[string]any{"key": "fwc"}})
	})
	run("ip", "netns", "add", clientNS)
	run("ip", "link", "set", lanPeer, "netns", clientNS)
	run("ip", "-n", clientNS, "link", "set", "lo", "up")
	run("ip", "-n", clientNS, "address", "add", fwcLANClient+"/24", "dev", lanPeer)
	run("ip", "-n", clientNS, "link", "set", lanPeer, "up")
	run("ip", "-n", clientNS, "route", "add", "default", "via", fwcLANHost)
	serverTarget := net.JoinHostPort(fwcPPPoEServer, strconv.Itoa(serverPort))
	var peer string
	var ok bool
	for attempt := 0; attempt < 10; attempt++ {
		if peer, ok = fwsTransfer(t, clientNS, "", serverTarget, 1<<20, 4<<20, 3*time.Second); ok {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ok || peer != fwcPPPoEClient {
		t.Fatalf("LAN TCP over PPPoE with the firewall bound: ok=%t server saw %q, want %s", ok, peer, fwcPPPoEClient)
	}
	t.Logf("LAN TCP over PPPoE: 4 MiB down, 1 MiB up, server saw %s", peer)

	// Keepalives both ways over a few seconds: Veer's echoes get answers, the
	// server's echoes get answered, and the session stays the same one.
	kaBefore := readSession("keepalive")
	time.Sleep(6 * time.Second)
	now := readSession("last")
	kaAfter := readSession("keepalive")
	if !now.up || now.generation != first.generation || serverPPP() == "" {
		t.Fatalf("the session did not stay up with the firewall bound: generation %q -> %q, server PPP %q: %s", first.generation, now.generation, serverPPP(), now.raw)
	}
	if !strings.HasPrefix(kaAfter.phase, "keepalive_ok@") || kaAfter.phase == kaBefore.phase {
		t.Fatalf("Veer's LCP keepalive: before %q, after %q (%s)", kaBefore.phase, kaAfter.phase, kaAfter.raw)
	}
	t.Logf("keepalive %s -> %s, session generation %s kept", kaBefore.phase, kaAfter.phase, now.generation)

	// Hang up and dial again: discovery once more through the firewall.
	action("pppoe_client", "disconnect", map[string]any{"profile_key": "fwc", "interface": wanHost})
	waitServerRelease()
	time.Sleep(time.Second)
	second := dial("redial")
	if second.generation == first.generation {
		t.Fatalf("the redial kept session generation %s", second.generation)
	}
	run("ip", "route", "replace", fwcPPPoEBlocked+"/32", "dev", localIf, "src", fwcPPPoEClient)
	fwsExpect(t, serverNS, "TCP over PPPoE after the redial", probes, filtered)

	pass, drop := d.fwCounters()
	if pass == 0 || drop == 0 {
		t.Fatalf("firewall counters pass=%v drop=%v, want both", pass, drop)
	}
	t.Logf("firewall counters: pass=%v drop=%v", pass, drop)
	action("pppoe_client", "disconnect", map[string]any{"profile_key": "fwc", "interface": wanHost})
	action("wan_core", "teardown", map[string]any{"wan_id": "fwc", "profile_key": "fwc", "local_interface": localIf,
		"pipeline_interface": pipelineIf, "handoff_mode": "segmented_veth"})
}

// fwcCapture runs tcpdump (when installed) on host interfaces and on
// interfaces inside namespaces ({ns, dev}); the returned function stops
// the captures and returns what they printed.
func fwcCapture(t *testing.T, dir string, host map[string]string, inNS map[string][2]string) func() string {
	t.Helper()
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return func() string { return "(tcpdump not installed)" }
	}
	type capture struct {
		label string
		cmd   *exec.Cmd
		path  string
	}
	var captures []capture
	start := func(label string, args ...string) {
		path := filepath.Join(dir, "capture-"+label+".txt")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout, cmd.Stderr = file, file
		if err := cmd.Start(); err != nil {
			file.Close()
			t.Logf("capture %s: %v", label, err)
			return
		}
		go func() { _ = cmd.Wait(); file.Close() }()
		captures = append(captures, capture{label, cmd, path})
	}
	for label, dev := range host {
		start(label, "tcpdump", "-i", dev, "-nn", "-e", "-l", "-c", "400")
	}
	for label, target := range inNS {
		start(label, "ip", "netns", "exec", target[0], "tcpdump", "-i", target[1], "-nn", "-e", "-l", "-c", "400")
	}
	time.Sleep(300 * time.Millisecond)
	stopped := false
	stop := func() string {
		var out strings.Builder
		for _, c := range captures {
			if !stopped {
				_ = c.cmd.Process.Signal(os.Interrupt)
			}
		}
		stopped = true
		time.Sleep(300 * time.Millisecond)
		for _, c := range captures {
			data, _ := os.ReadFile(c.path)
			fmt.Fprintf(&out, "--- %s ---\n%s\n", c.label, fwcTail(data, 5000))
		}
		return out.String()
	}
	t.Cleanup(func() { stop() })
	return stop
}

func fwcTail(data []byte, n int) string {
	if len(data) > n {
		data = data[len(data)-n:]
	}
	return string(data)
}

func fwcWaitFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within %s", path, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestFirewallCoexistVPNCore binds the firewall to the WAN interface of a
// host whose LAN client leaves through a vpn_core WireGuard exit. The
// firewall's policies allow only the WireGuard peer to the WireGuard port
// and to a TCP port of the host. The tunnel comes up through the hook and
// carries the client's traffic; the TCP policy drops another source on the
// same interface. It runs in a network namespace of its own (unshare), as
// TestVPNWireGuardLinuxIntegration does, because it routes by default
// through the uplink.
func TestFirewallCoexistVPNCore(t *testing.T) {
	fwsRequire(t)
	for _, tool := range []string{"wg", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}
	if os.Getenv("FORWARD_FWC_VPN_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", "--", fwsSelf(t), "-test.run=^TestFirewallCoexistVPNCore$", "-test.v", "-test.timeout=230s")
		cmd.Env = append(os.Environ(), "FORWARD_FWC_VPN_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Logf("isolated run:\n%s", out)
		if err != nil {
			t.Fatalf("isolated vpn_core coexistence test: %v", err)
		}
		return
	}
	suffix := fwsSuffix()
	remote, lan := "fwcvr"+suffix, "fwcvl"+suffix
	for _, ns := range []string{remote, lan} {
		ns := ns
		_ = exec.Command("ip", "netns", "del", ns).Run()
		fwsRun(t, "ip", "netns", "add", ns)
		t.Cleanup(func() {
			if out, err := exec.Command("ip", "netns", "pids", ns).Output(); err == nil {
				for _, pid := range strings.Fields(string(out)) {
					_ = exec.Command("kill", pid).Run()
				}
			}
			_ = exec.Command("ip", "netns", "del", ns).Run()
		})
		fwsRun(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	run := func(args ...string) string { t.Helper(); return fwsRun(t, args...) }
	// This namespace is the router: its own sysctls, so nothing to restore.
	run("ip", "link", "set", "lo", "up")
	run("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=2")
	run("ip", "link", "add", "br-lan", "type", "bridge")
	run("ip", "address", "add", "192.168.10.1/24", "dev", "br-lan")
	run("ip", "link", "set", "br-lan", "up")
	run("ip", "link", "add", "port0", "type", "veth", "peer", "name", "client0")
	run("ip", "link", "set", "port0", "master", "br-lan")
	run("ip", "link", "set", "port0", "up")
	run("ip", "link", "set", "client0", "netns", lan)
	run("ip", "-n", lan, "address", "add", "192.168.10.20/24", "dev", "client0")
	run("ip", "-n", lan, "link", "set", "client0", "up")
	run("ip", "-n", lan, "route", "add", "default", "via", "192.168.10.1")
	run("ip", "link", "add", "wan", "type", "veth", "peer", "name", "outside")
	run("ip", "link", "set", "outside", "netns", remote)
	run("ip", "address", "add", "192.0.2.1/24", "dev", "wan")
	run("ip", "link", "set", "wan", "up")
	run("ip", "-n", remote, "address", "add", "192.0.2.2/24", "dev", "outside")
	run("ip", "-n", remote, "link", "set", "outside", "up")
	run("ip", "route", "add", "default", "via", "192.0.2.2")
	run("ip", "-n", remote, "address", "add", "203.0.113.1/32", "dev", "lo")
	run("ip", "-n", remote, "address", "add", "198.51.100.1/32", "dev", "lo")
	run("ip", "-n", remote, "route", "add", "192.168.10.0/24", "via", "192.0.2.1")

	// The WireGuard peer in the remote namespace; Veer's end gets 10.77.0.1.
	genKey := func(input string, args ...string) string {
		t.Helper()
		cmd := exec.Command("wg", args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("wg %s failed: %v", args[0], err) // keys stay out of the log
		}
		return strings.TrimSpace(string(out))
	}
	localPrivate, remotePrivate := genKey("", "genkey"), genKey("", "genkey")
	localPublic, remotePublic := genKey(localPrivate+"\n", "pubkey"), genKey(remotePrivate+"\n", "pubkey")
	run("ip", "-n", remote, "link", "add", "wgpeer", "type", "wireguard")
	syncconf := exec.Command("ip", "netns", "exec", remote, "wg", "syncconf", "wgpeer", "/dev/stdin")
	syncconf.Stdin = strings.NewReader("[Interface]\nPrivateKey = " + remotePrivate + "\nListenPort = 51820\n[Peer]\nPublicKey = " + localPublic + "\nAllowedIPs = 10.77.0.1/32\n")
	if err := syncconf.Run(); err != nil {
		t.Fatalf("configure the remote WireGuard peer: %v", err)
	}
	run("ip", "-n", remote, "address", "add", "10.77.0.2/32", "dev", "wgpeer")
	run("ip", "-n", remote, "link", "set", "wgpeer", "up")
	run("ip", "-n", remote, "route", "add", "10.77.0.1/32", "dev", "wgpeer")
	run("ip", "netns", "exec", remote, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=2", "net.ipv4.conf.wgpeer.rp_filter=2")
	const exitPort = 24001
	fwsStartListener(t, remote, fmt.Sprintf("0.0.0.0:%d", exitPort))
	hostPort := fwsHostListener(t)

	d := fwsStartDaemon(t, fwsDaemonOptions{Plugins: []string{"wan_core", "vpn_core"},
		Experimental: map[string]bool{experimentalFeatureKernelTCPreparedL2: true}})
	d.waitPluginAction("firewall", "apply")
	d.waitPluginAction("vpn_core", "apply")

	// The firewall first: only the WireGuard peer reaches the WireGuard
	// port and the host's TCP port.
	d.fwSettings("wan")
	d.fwPolicyProto("wireguard", "udp", []int{51821}, "192.0.2.2/32")
	d.fwPolicy("host", []int{hostPort}, "192.0.2.2/32")
	d.fwApplyConfirm()
	fwsWaitXDP(t, "wan", true, 10*time.Second)
	hostTarget := net.JoinHostPort("192.0.2.1", strconv.Itoa(hostPort))
	hostProbes := []fwsProbe{
		{"peer", "192.0.2.2", hostTarget, "192.0.2.2"},
		{"other", "198.51.100.1", hostTarget, "198.51.100.1"},
	}
	filtered := map[string]bool{"peer": true, "other": false}
	fwsExpect(t, remote, "host port, firewall bound", hostProbes, filtered)

	// The VPN exit, set up behind the bound firewall.
	d.api("POST", "/api/plugins/vpn_core/actions/set_key", map[string]any{"payload": map[string]any{"key": "default", "value": localPrivate}})
	d.api("POST", "/api/plugins/vpn_core/resources/profiles", map[string]any{"key": "default", "enabled": true, "data": map[string]any{
		"slot": 1, "listen_port": 51821, "addresses": []string{"10.77.0.1/32"},
		"peers": []any{map[string]any{"public_key": remotePublic, "endpoint": "192.0.2.2:51820", "allowed_ips": []string{"0.0.0.0/0"}}},
	}})
	d.api("POST", "/api/plugins/vpn_core/actions/apply", map[string]any{"payload": map[string]any{"key": "default"}})
	createNAT := func(payload map[string]any) int64 {
		t.Helper()
		var created struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(d.api("POST", "/api/egress-nats", payload), &created); err != nil || created.ID == 0 {
			t.Fatalf("create egress NAT %v: %v", payload, err)
		}
		return created.ID
	}
	waitNAT := func(id int64, source string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			var entries []EgressNATStatus
			if err := json.Unmarshal(d.api("GET", "/api/egress-nats", nil), &entries); err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.ID == id && entry.Status == "running" && entry.EffectiveEngine == ruleEngineKernel &&
					entry.EffectiveKernelEngine == kernelEngineTC && entry.OutSourceIP == source {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("egress NAT %d did not run on TC with source %s: %+v", id, source, entries)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	waitNAT(createNAT(map[string]any{"parent_interface": "br-lan", "out_interface": "wan", "out_source_ip": "192.0.2.1", "protocol": "tcp+udp+icmp"}), "192.0.2.1")
	waitNAT(createNAT(map[string]any{"parent_interface": "br-lan", "child_interface": "port0", "out_interface": "veerwg1",
		"out_source_ip": "10.77.0.1", "protocol": "tcp+udp+icmp"}), "10.77.0.1")

	exitTarget := net.JoinHostPort("203.0.113.1", strconv.Itoa(exitPort))
	var peer string
	var ok bool
	for attempt := 0; attempt < 20; attempt++ {
		if peer, ok = fwsTransfer(t, lan, "", exitTarget, 1<<20, 4<<20, 3*time.Second); ok && peer == "10.77.0.1" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ok || peer != "10.77.0.1" {
		out, _ := exec.Command("ip", "netns", "exec", remote, "wg", "show", "wgpeer", "latest-handshakes").CombinedOutput()
		t.Fatalf("LAN traffic through the WireGuard exit with the firewall bound: ok=%t remote saw %q, want 10.77.0.1; remote handshakes: %s", ok, peer, out)
	}
	t.Logf("LAN TCP through the WireGuard exit: 4 MiB down, 1 MiB up, remote saw %s", peer)
	fwsExpect(t, remote, "host port with the VPN up", hostProbes, filtered)

	status := d.fwAction("status")
	policies, _ := status["policies"].([]any)
	counters := map[string]map[string]any{}
	for _, p := range policies {
		item, _ := p.(map[string]any)
		key, _ := item["key"].(string)
		counters[key], _ = item["counters"].(map[string]any)
	}
	if wgPass, _ := counters["wireguard"]["pass"].(float64); wgPass == 0 {
		t.Fatalf("the WireGuard policy passed nothing: %v", counters)
	}
	if hostDrop, _ := counters["host"]["drop"].(float64); hostDrop == 0 {
		t.Fatalf("the host policy dropped nothing: %v", counters)
	}
	t.Logf("firewall counters: %v", counters)
	_, _ = d.request("POST", "/api/plugins/vpn_core/actions/teardown", map[string]any{"payload": map[string]any{"key": "default"}})
}
