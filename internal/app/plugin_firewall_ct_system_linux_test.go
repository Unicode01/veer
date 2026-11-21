//go:build linux

package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// TestFirewallSystemConnectionTracking runs the firewall with connection
// tracking as a stateful "deny inbound" firewall on the WAN veth of the
// system-test topology (the host routes between the client namespace on the
// WAN side and the backend namespace on the LAN side):
//
//   - a catch-all policy drops everything no other policy takes; tcp 8101,
//     a Veer port forward to the backend, is open to everyone;
//
//   - connections the host opens, and those the backend opens through an
//     egress NAT, get their replies back; ping from the host works, to it
//     does not;
//
//   - without connection tracking the same rules cut those replies;
//
//   - a connection open across a Veer hot restart keeps working (fw_ct is
//     handed over);
//
//   - set_add on a blocklist cuts a tracked peer off, set_del lets it back;
//
//   - strict reverse-path checks drop a LAN source arriving on the WAN.
//
//     FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 go test ./internal/app -run '^TestFirewallSystemConnectionTracking$' -v
func TestFirewallSystemConnectionTracking(t *testing.T) {
	fwsRequire(t)
	topo := fwsSetupTopology(t, "fct")
	marker := filepath.Join(t.TempDir(), "hot-restart")
	d := fwsStartDaemon(t, fwsDaemonOptions{HotRestartMarker: marker})
	d.waitPluginAction("firewall", "set_add")

	const serverPort = 7001
	fwsStartListener(t, topo.ClientNS, net.JoinHostPort(fwsAllowed4, strconv.Itoa(serverPort)), net.JoinHostPort(fwsAllowed6, strconv.Itoa(serverPort)))
	fwsStartListener(t, topo.BackendNS, net.JoinHostPort(fwsBackend4, "7002"))
	hostPort := fwsHostListener(t)

	rule := d.addRule(topo, fwsWANHost4, 8101, fwsBackend4, 7002, false, fwsBackendHost4)
	d.requireRuleEngine(rule, kernelEngineTC, 20*time.Second)
	var nat struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(d.api("POST", "/api/egress-nats", map[string]any{"parent_interface": topo.Backend, "out_interface": topo.WAN,
		"out_source_ip": fwsWANHost4, "protocol": "tcp+udp+icmp"}), &nat); err != nil || nat.ID == 0 {
		t.Fatalf("create egress NAT: %v", err)
	}
	fwsWaitEgressNAT(t, d, nat.ID)

	settings := func(tracking bool) {
		d.upsert("firewall", "settings", "default", map[string]any{
			"interfaces": []string{topo.WAN}, "confirm_timeout_seconds": 60, "connection_tracking": tracking,
			"blocklists": []string{"deny"},
			"baseline":   map[string]any{"invalid_tcp_flags": true, "bogon_sources": "reserved", "urpf": "strict"},
		})
	}
	d.upsert("firewall", "sets", "deny", map[string]any{"elements": []string{}})
	d.upsert("firewall", "policies", "inbound", map[string]any{"name": "inbound", "protocol": "any", "default_action": "drop"})
	d.upsert("firewall", "policies", "forward", map[string]any{"name": "forward", "protocol": "tcp", "ports": []string{"8101"}, "default_action": "allow"})
	settings(true)
	d.fwApplyConfirm()
	fwsWaitEgressAttached(t, d, topo.WAN, true)

	server4 := net.JoinHostPort(fwsAllowed4, strconv.Itoa(serverPort))
	server6 := net.JoinHostPort(fwsAllowed6, strconv.Itoa(serverPort))
	expectDial := func(step, ns, target, wantPeer string, want bool) {
		t.Helper()
		timeout := 3 * time.Second
		if !want {
			timeout = 1500 * time.Millisecond
		}
		peer, ok := fwsDial(t, ns, "", target, 4096, timeout)
		if ok != want || (ok && wantPeer != "" && peer != wantPeer) {
			t.Fatalf("%s: reachable=%t (%s), want %t (peer %s)", step, ok, peer, want, wantPeer)
		}
	}
	expectPing := func(step, ns, target string, want bool) {
		t.Helper()
		args := []string{"ping", "-c", "1", "-W", "1", target}
		if ns != "" {
			args = append([]string{"ip", "netns", "exec", ns}, args...)
		}
		err := exec.Command(args[0], args[1:]...).Run()
		if (err == nil) != want {
			t.Fatalf("%s: ping %s answered=%t, want %t", step, target, err == nil, want)
		}
	}
	tracked := func(step string) {
		t.Helper()
		expectDial(step+": host to the internet", "", server4, fwsWANHost4, true)
		expectDial(step+": host to the internet over IPv6", "", server6, fwsWANHost6, true)
		expectDial(step+": LAN through the egress NAT", topo.BackendNS, server4, fwsWANHost4, true)
		expectPing(step+": host pings the internet", "", fwsAllowed4, true)
		expectPing(step+": LAN pings the internet", topo.BackendNS, fwsAllowed4, true)
	}
	tracked("tracking on")
	expectDial("inbound to a host port", topo.ClientNS, net.JoinHostPort(fwsWANHost4, strconv.Itoa(hostPort)), "", false)
	expectDial("inbound to the open port forward", topo.ClientNS, net.JoinHostPort(fwsWANHost4, "8101"), "", true)
	expectPing("ping to the host", topo.ClientNS, fwsWANHost4, false)

	// The same rules without tracking: replies are just inbound packets.
	settings(false)
	d.fwApplyConfirm()
	fwsWaitEgressAttached(t, d, topo.WAN, false)
	expectDial("tracking off: host to the internet", "", server4, "", false)
	expectDial("tracking off: LAN through the egress NAT", topo.BackendNS, server4, "", false)
	settings(true)
	d.fwApplyConfirm()
	fwsWaitEgressAttached(t, d, topo.WAN, true)
	tracked("tracking on again")

	// A connection open across a hot restart: its tracking entry is handed
	// over with the rest of the maps, so the server's last reply still
	// comes back.
	conn, err := net.DialTimeout("tcp", server4, 3*time.Second)
	if err != nil {
		t.Fatalf("open the long connection: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("long connection: %v", err)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d.stop()
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	d.start()
	d.waitPluginAction("firewall", "set_add")
	fwsWaitEgressAttached(t, d, topo.WAN, true)
	if _, err := fmt.Fprintf(conn, "0\n%s", strings.Repeat("x", 1000)); err != nil {
		t.Fatalf("write after the hot restart: %v", err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if count, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(count) != "1000" {
		t.Fatalf("reply after the hot restart: %q %v", count, err)
	}
	tracked("after the hot restart")

	// A blocklist cuts a tracked peer off at once, and set_del lets it back.
	d.api("POST", "/api/plugins/firewall/actions/set_add", map[string]any{"payload": map[string]any{"set": "deny", "elements": []string{fwsAllowed4}, "timeout_seconds": 600}})
	expectDial("blocklisted peer", "", server4, "", false)
	d.api("POST", "/api/plugins/firewall/actions/set_del", map[string]any{"payload": map[string]any{"set": "deny", "elements": []string{fwsAllowed4}}})
	expectDial("peer back off the blocklist", "", server4, fwsWANHost4, true)

	// A LAN source on the WAN fails the strict reverse-path check.
	before := fwsGlobalCounter(t, d, "urpf")
	fwsRun(t, "ip", "-n", topo.ClientNS, "address", "add", "10.232.0.99/32", "dev", "eth0")
	_, _ = fwsDial(t, topo.ClientNS, "10.232.0.99", net.JoinHostPort(fwsWANHost4, "8101"), 16, time.Second)
	if after := fwsGlobalCounter(t, d, "urpf"); after <= before {
		t.Fatalf("urpf drops went from %v to %v after a spoofed LAN source", before, after)
	}
	expectDial("open port forward after the spoofed source", topo.ClientNS, net.JoinHostPort(fwsWANHost4, "8101"), "", true)

	global, _ := d.fwAction("status")["global"].(map[string]any)
	for _, name := range []string{"established", "ct_new", "blocklist"} {
		if v, _ := global[name].(float64); v == 0 {
			t.Fatalf("global counter %s is 0: %v", name, global)
		}
	}
	t.Logf("global counters: %v", global)
}

func fwsGlobalCounter(t *testing.T, d *fwsDaemon, name string) float64 {
	t.Helper()
	global, _ := d.fwAction("status")["global"].(map[string]any)
	v, _ := global[name].(float64)
	return v
}

// fwsWaitEgressAttached waits until the firewall's tc_egress program runs at
// TC egress of name, or until it is gone.
func fwsWaitEgressAttached(t *testing.T, d *fwsDaemon, name string, want bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		got := fwsEgressProgram(t, name) != 0
		if got == want {
			status := d.fwAction("status")
			attachments, _ := status["attachments"].(map[string]any)
			interfaces, _ := attachments["interfaces"].([]any)
			if len(interfaces) == 1 {
				if egress, _ := interfaces[0].(map[string]any)["egress"].(bool); egress == want {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("egress program on %s: attached=%t, want %t; status %v", name, got, want, d.fwAction("status")["attachments"])
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// fwsEgressProgram is the ID of the firewall's program at TC egress of name,
// on either attach API, or 0.
func fwsEgressProgram(t *testing.T, name string) uint32 {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := link.QueryPrograms(link.QueryOptions{Target: l.Attrs().Index, Attach: ebpf.AttachTCXEgress}); err == nil {
		for _, prog := range result.Programs {
			if info, err := fwsProgramInfo(prog.ID); err == nil && strings.HasPrefix(info, "tc_firewall_egr") {
				return uint32(prog.ID)
			}
		}
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return 0
	}
	for _, filter := range filters {
		if bpf, ok := filter.(*netlink.BpfFilter); ok && strings.HasPrefix(bpf.Name, "veer_xdp_egress:firewall/") {
			return uint32(bpf.Id)
		}
	}
	return 0
}

func fwsProgramInfo(id ebpf.ProgramID) (string, error) {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "", err
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		return "", err
	}
	return info.Name, nil
}

func fwsWaitEgressNAT(t *testing.T, d *fwsDaemon, id int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var entries []EgressNATStatus
		if err := json.Unmarshal(d.api("GET", "/api/egress-nats", nil), &entries); err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.ID == id && entry.Status == "running" && entry.EffectiveEngine == ruleEngineKernel && entry.EffectiveKernelEngine == kernelEngineTC {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("egress NAT %d did not run on TC: %+v", id, entries)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
