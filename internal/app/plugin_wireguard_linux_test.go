package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

// The complete topology runs in a disposable network namespace. No route,
// firewall rule, sysctl or WireGuard device is installed in the runner's netns.
func TestWireGuardMeshLinuxIntegration(t *testing.T) {
	if os.Getenv("VEER_RUN_WIREGUARD_TESTS") != "1" {
		t.Skip("set VEER_RUN_WIREGUARD_TESTS=1 to test real WireGuard routing")
	}
	if os.Geteuid() != 0 {
		t.Fatal("WireGuard integration requires root")
	}
	for _, tool := range []string{"ip", "wg", "nft", "tc", "sysctl", "ping", "unshare"} {
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--net", "--", binary, "-test.run=^TestWireGuardMeshLinuxIntegration$", "-test.v", "-test.timeout=110s")
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
	plugin, db, runtime := loadPluginIntegrationControlRuntimeForTest(t, "wireguard_mesh")
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(runtime.cfg, db)
	applyPluginRuntimeSnapshot(&catalog, runtime.Reconcile(catalog))
	plugin = pluginByIDForTest(t, catalog, "wireguard_mesh")
	action := func(id string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, id), data); err != nil {
			t.Fatalf("WireGuard action %s: %v", id, err)
		}
	}
	action("set_key", map[string]any{"key": "default", "value": localPrivate})
	profile := map[string]any{
		"slot": 1, "listen_port": 51821, "addresses": []string{"10.77.0.1/32", "fd77::1/128"}, "masquerade": true,
		"peers": []any{map[string]any{"public_key": remotePublic, "endpoint": "192.0.2.2:51820", "allowed_ips": []string{"0.0.0.0/0", "::/0"}}},
		"bindings": []any{
			map[string]any{"lan_interface": "br-lan", "source": "192.168.10.20/32", "destination": "0.0.0.0/0"},
			map[string]any{"lan_interface": "br-lan", "source": "fd10::20/128", "destination": "::/0"},
		},
	}
	storeProfile := func() {
		t.Helper()
		data, _ := json.Marshal(profile)
		if err := store.DeletePluginRecord(db, "wireguard_mesh", "profiles", "default"); err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		addPluginIntegrationRecord(t, db, "wireguard_mesh", "profiles", "default", string(data), true)
	}
	storeProfile()
	action("apply", map[string]any{"key": "default"})
	ping := func(ns, target string) {
		t.Helper()
		ip("netns", "exec", ns, "ping", "-n", "-c", "2", "-W", "2", target)
	}
	ping(selected, "203.0.113.1") // Only the tunnel address is allowed by the remote peer: this proves SNAT.
	ping(selected, "fd20::1")
	ping(direct, "203.0.113.1")
	if got := ip("route", "get", "203.0.113.1", "from", "192.168.10.20", "iif", "br-lan"); !strings.Contains(got, "dev vwgdefault") {
		t.Fatal("selected device did not choose WireGuard: " + got)
	}
	if got := ip("route", "get", "203.0.113.1", "from", "192.168.10.30", "iif", "br-lan"); !strings.Contains(got, "dev wan") {
		t.Fatal("unselected device routing changed: " + got)
	}
	if got := ip("route", "get", "192.0.2.2"); !strings.Contains(got, "dev wan") {
		t.Fatal("outer endpoint recursively enters WireGuard: " + got)
	}
	ip("link", "del", "vwgdefault")
	if out, err := exec.Command("ip", "route", "get", "203.0.113.1", "from", "192.168.10.20", "iif", "br-lan").CombinedOutput(); err == nil {
		t.Fatalf("missing tunnel fell through to cleartext routing: %s", out)
	}
	ping(direct, "203.0.113.1")
	action("apply", map[string]any{"key": "default"})
	ping(selected, "203.0.113.1")
	// Change to routed site-to-site mode, including the whole LAN and IPv6.
	configureRemote("192.168.10.0/24, fd10::/64, 10.77.0.1/32, fd77::1/128")
	ip("-n", remote, "route", "replace", "192.168.10.0/24", "dev", "wgpeer")
	ip("-n", remote, "-6", "route", "replace", "fd10::/64", "dev", "wgpeer")
	profile["masquerade"] = false
	profile["peers"] = []any{map[string]any{"public_key": remotePublic, "endpoint": "192.0.2.2:51820", "allowed_ips": []string{"192.168.20.0/24", "fd20::/64"}}}
	profile["bindings"] = []any{map[string]any{"lan_interface": "br-lan", "source": "192.168.10.0/24", "destination": "192.168.20.0/24"}, map[string]any{"lan_interface": "br-lan", "source": "fd10::/64", "destination": "fd20::/64"}}
	storeProfile()
	action("apply", map[string]any{"key": "default"})
	ping(selected, "192.168.20.1")
	ping(direct, "192.168.20.1")
	ping(selected, "fd20::1")
	ip("netns", "exec", remote, "ping", "-I", "192.168.20.1", "-n", "-c", "2", "-W", "2", "192.168.10.20")
	ip("netns", "exec", remote, "ping", "-I", "fd20::1", "-n", "-c", "2", "-W", "2", "fd10::20")
	action("teardown", map[string]any{"key": "default"})
	if out := ip("-j", "link", "show"); bytes.Contains([]byte(out), []byte("vwgdefault")) {
		t.Fatal("owned WireGuard link remains")
	}
	for _, family := range []string{"-4", "-6"} {
		if out := ip("-j", family, "rule", "show"); strings.Contains(out, "52001") {
			t.Fatal("owned policy rules remain: " + out)
		}
	}
	if exec.Command("nft", "list", "table", "inet", "veer_wg_1").Run() == nil {
		t.Fatal("owned firewall table remains")
	}
}
