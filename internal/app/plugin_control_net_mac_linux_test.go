//go:build linux

package app

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginControlNetOwnedLinkMACLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	admin := linuxPluginControlNetAdmin{}
	host, peer := pluginIntegrationLinkName("fwm"), pluginIntegrationLinkName("fwp")
	defer deletePluginIntegrationLinkQuietly(t, host)
	pair, err := admin.LinkEnsureVeth(pluginControlNetVethRequest{Host: host, Peer: peer, MTU: 1492, Up: true})
	if err != nil {
		t.Fatal(err)
	}
	assertPluginOwnedLinkMACStable(t, admin, pair.Host)
	assertPluginOwnedLinkMACStable(t, admin, pair.Peer)

	kinds := []string{"dummy", "bridge"}
	if os.Getenv("VEER_RUN_KFUNCS_TESTS") == "1" {
		kinds = append(kinds, "veerwan")
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			name := pluginIntegrationLinkName("fwm")
			defer deletePluginIntegrationLinkQuietly(t, name)
			var info pluginControlNetLinkInfo
			var err error
			switch kind {
			case "dummy", "veerwan":
				var result pluginControlNetDummyResult
				result, err = admin.linkEnsureSingle(pluginControlNetDummyRequest{Name: name, MTU: 1492, Up: true}, kind)
				info = result.Link
			case "bridge":
				info, err = admin.LinkEnsureBridge(pluginControlNetBridgeRequest{Name: name, MTU: 1492, Up: true})
			}
			if err != nil {
				t.Fatal(err)
			}
			assertPluginOwnedLinkMACStable(t, admin, info)
			if kind == "bridge" {
				if _, err := admin.LinkSetMaster(pluginControlNetMasterRequest{Link: host, Master: name, Up: true}); err != nil {
					t.Fatal(err)
				}
				defer admin.LinkClearMaster(host)
				assertPluginOwnedLinkMACStable(t, admin, info)
			}
		})
	}
}

func assertPluginOwnedLinkMACStable(t *testing.T, admin linuxPluginControlNetAdmin, initial pluginControlNetLinkInfo) {
	t.Helper()
	mac, err := net.ParseMAC(initial.MAC)
	if err != nil || len(mac) != 6 || mac[0]&3 != 2 {
		t.Fatalf("%s MAC = %q, want a local unicast address", initial.Name, initial.MAC)
	}
	path := filepath.Join("/sys/class/net", initial.Name)
	assigned, err := os.ReadFile(filepath.Join(path, "addr_assign_type"))
	if err != nil || strings.TrimSpace(string(assigned)) != "3" {
		t.Fatalf("%s addr_assign_type = %q, %v; want NET_ADDR_SET", initial.Name, assigned, err)
	}
	udev, udevErr := exec.LookPath("udevadm")
	if _, controlErr := os.Stat("/run/udev/control"); udevErr == nil && controlErr == nil {
		if output, err := exec.Command(udev, "trigger", "--action=add", "--settle", path).CombinedOutput(); err != nil {
			t.Fatalf("trigger udev for %s: %v: %s", initial.Name, err, output)
		}
	}
	current, err := admin.LinkGet(initial.Name)
	if err != nil || current.IfIndex != initial.IfIndex || current.MAC != initial.MAC {
		t.Fatalf("owned link changed after udev/bridge attachment: initial=%+v current=%+v err=%v", initial, current, err)
	}
}
