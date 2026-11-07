//go:build linux && veer_kfuncs

package app

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/Unicode01/veer/internal/store"
	"github.com/vishvananda/netlink"
)

func TestOptionalKernelModuleWANRecovery(t *testing.T) {
	if os.Getenv("VEER_RUN_KFUNCS_TESTS") != "1" {
		t.Skip("requires matching optional module on an isolated test host")
	}
	if runPluginIntegrationInIsolatedNetNS(t) {
		return
	}
	plugin, db, rt := loadPluginIntegrationControlRuntimeForTest(t, "wan_core")
	defer rt.Close()
	apply := pluginActionByIDForTest(t, plugin, "apply_session")
	for i := 0; i < 2; i++ {
		payload := fmt.Sprintf(`{"key":"wan%d","driver":"pppoe","state":"up","usable":true,"handoff_mode":"direct_gro","local_interface":"veerwan%d","ipv4":"169.254.241.%d","mtu":1492,"interface_preparation":{"local_gso":{"max_size":65536,"max_segs":65535},"local_offloads":{"gro":true,"sg":true,"gso":true,"tso":true}}}`, i, i, i+1)
		if err := rt.ApplyPluginAction(plugin, apply, json.RawMessage(payload)); err != nil {
			t.Fatal(err)
		}
	}
	other, err := rt.netAdmin.LinkGet("veerwan1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		previous, err := rt.netAdmin.LinkGet("veerwan0")
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.netAdmin.LinkDelete("veerwan0"); err != nil {
			t.Fatal(err)
		}
		// A same-name foreign device must be preserved, never adopted as a
		// usable WAN or deleted by this profile's failed reconciliation.
		foreign, err := rt.netAdmin.LinkEnsureDummy(pluginControlNetDummyRequest{Name: "veerwan0", MTU: 1400, Up: true})
		if err != nil {
			t.Fatal(err)
		}
		firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
		current, err := rt.netAdmin.LinkGet("veerwan0")
		if err != nil || current.Kind != "dummy" || current.IfIndex != foreign.Link.IfIndex || current.MTU != 1400 {
			t.Fatalf("foreign device changed: %+v, %v", current, err)
		}
		status, err := store.GetPluginRecord(db, "wan_core", "status", "wan0")
		if err != nil || status.Enabled {
			t.Fatalf("foreign boundary published usable: %+v, %v", status, err)
		}
		if err := rt.netAdmin.LinkDelete("veerwan0"); err != nil {
			t.Fatal(err)
		}
		firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
		current, err = rt.netAdmin.LinkGet("veerwan0")
		if err != nil || current.Kind != "veerwan" || current.IfIndex == previous.IfIndex {
			t.Fatalf("repair failed: %+v, %v", current, err)
		}
		assertPluginIntegrationLinkHasCIDR(t, "veerwan0", "169.254.241.1/32")
		link, err := netlink.LinkByName("veerwan0")
		if err != nil {
			t.Fatal(err)
		}
		src, dst, err := resolveKernelEgressNATPreparedL2Redirect(link)
		if err != nil || src != dst || src == [6]byte{} {
			t.Fatalf("prepared L2: %x %x %v", src, dst, err)
		}
		owned, err := store.PluginOwnedResourceOrNil(db, pluginOwnedResourceTypeLink, "veerwan0")
		if err != nil || owned == nil {
			t.Fatalf("ownership: %+v %v", owned, err)
		}
		var claim pluginOwnedLinkClaim
		if err := json.Unmarshal([]byte(owned.MetadataJSON), &claim); err != nil {
			t.Fatal(err)
		}
		if !pluginOwnedLinkIdentityMatches(current, claim.IfIndex, claim.Kind, claim.MAC) {
			t.Fatalf("stale ownership: %+v %+v", current, claim)
		}
		stable, err := rt.netAdmin.LinkGet("veerwan1")
		if err != nil || stable.IfIndex != other.IfIndex || stable.MAC != other.MAC {
			t.Fatalf("unrelated WAN changed: %+v %v", stable, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "teardown"), json.RawMessage(fmt.Sprintf(`{"key":"wan%d","forget":true}`, i))); err != nil {
			t.Fatal(err)
		}
		assertPluginIntegrationLinkAbsent(t, fmt.Sprintf("veerwan%d", i))
	}
}
