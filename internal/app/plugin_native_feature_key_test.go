package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeRegistrationFollowsChangingHostFeatures(t *testing.T) {
	t.Parallel()

	registration := func(when string) *PluginNativeRegistration {
		return &PluginNativeRegistration{Objects: []json.RawMessage{json.RawMessage(`{"id":"obj","path":"obj.o"` + when + `}`)}}
	}
	for _, tc := range []struct {
		name string
		reg  *PluginNativeRegistration
		want bool
	}{
		{"none", nil, false},
		{"unconditioned", registration(``), false},
		{"stable feature", registration(`,"when":{"feature":"dataplane.xdp_tc_egress.v1"}`), false},
		{"kernel module", registration(`,"when":{"feature":"dataplane.kfuncs.handoff.v1"}`), true},
		{"without kernel module", registration(`,"when":{"not_feature":"dataplane.kfuncs.handoff_ingress.v1"}`), true},
	} {
		if got := pluginNativeRegistrationFollowsChangingFeatures(tc.reg); got != tc.want {
			t.Errorf("%s: follows = %t, want %t", tc.name, got, tc.want)
		}
	}

	// The bundled plugins that pick a tunnel object by the kernel module.
	for id, want := range map[string]bool{"pppoe_client": true, "vpn_core": true, "firewall": false, "wan_core": false, "lan_core": false} {
		data, err := os.ReadFile(filepath.Join("..", "..", "plugins", id, "plugin.json"))
		if err != nil {
			t.Fatalf("read %s manifest: %v", id, err)
		}
		var manifest PluginManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatalf("decode %s manifest: %v", id, err)
		}
		if manifest.Control == nil {
			t.Fatalf("%s manifest has no control section", id)
		}
		if got := pluginNativeRegistrationFollowsChangingFeatures(manifest.Control.Register); got != want {
			t.Errorf("%s follows changing host features = %t, want %t", id, got, want)
		}
	}
}

func TestPluginControlVMKeyNamesTheKernelModuleFeaturesItWasRegisteredFor(t *testing.T) {
	t.Parallel()

	plugin := LoadedPlugin{
		PluginManifest:  PluginManifest{ID: "pppoe_client", Control: &PluginControl{ResolvedSHA256: "abc"}},
		controlMainPath: "plugin.json",
		controlDigest:   "digest",
	}
	plain, err := pluginControlVMKey(plugin, "control", "")
	if err != nil {
		t.Fatalf("pluginControlVMKey() error = %v", err)
	}
	if strings.Contains(plain, "kfuncs=") {
		t.Fatalf("key %q names kernel module features for a plugin that does not depend on them", plain)
	}
	plugin.nativeFollowsHostFeatures = true
	following, err := pluginControlVMKey(plugin, "control", "")
	if err != nil {
		t.Fatalf("pluginControlVMKey() error = %v", err)
	}
	if !strings.HasSuffix(following, "\x00"+pluginChangingHostFeaturesKey()) || !strings.HasPrefix(following, plain) {
		t.Fatalf("key %q, want %q plus the current kernel module features", following, plain)
	}
}
