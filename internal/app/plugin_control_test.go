package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginInterfacePatternMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		iface   string
		want    bool
	}{
		{pattern: "*", iface: "eth0", want: true},
		{pattern: "eth0", iface: "eth0", want: true},
		{pattern: "eth0", iface: "eth1", want: false},
		{pattern: "eth*", iface: "eth0", want: true},
		{pattern: "eth*", iface: "xeth0", want: false},
		{pattern: "*0", iface: "eth0", want: true},
		{pattern: "*0", iface: "eth0x", want: false},
		{pattern: "veth*wan", iface: "veth123wan", want: true},
		{pattern: "veth*wan", iface: "veth123wan0", want: false},
		{pattern: "veth*wan", iface: "xveth123wan", want: false},
		{pattern: "fwd*wan*", iface: "fwd0wan1", want: true},
		{pattern: "fwd*wan*", iface: "wanfwd0", want: false},
		{pattern: "br*lan*", iface: "br0lan1", want: true},
		{pattern: "br*lan*", iface: "br0", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.pattern+"/"+tt.iface, func(t *testing.T) {
			t.Parallel()
			if got := pluginInterfacePatternMatches(tt.pattern, tt.iface); got != tt.want {
				t.Fatalf("pluginInterfacePatternMatches(%q, %q) = %v, want %v", tt.pattern, tt.iface, got, tt.want)
			}
		})
	}
}

func TestPluginControlHasNetAccessRequiresOperationAndPattern(t *testing.T) {
	t.Parallel()

	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			Control: &PluginControl{
				NetAccess: []PluginNetAccess{
					{Interfaces: []string{"fwd*", "wan*"}, Operations: []string{"link.create", "addr.write"}},
					{Interfaces: []string{"eth*"}, Operations: []string{"link.read"}},
				},
			},
		},
	}

	if !pluginControlHasNetAccess(plugin, "link.create", "fwdwan0") {
		t.Fatal("pluginControlHasNetAccess(link.create, fwdwan0) = false, want true")
	}
	if !pluginControlHasNetAccess(plugin, "addr.write", "wan0") {
		t.Fatal("pluginControlHasNetAccess(addr.write, wan0) = false, want true")
	}
	if pluginControlHasNetAccess(plugin, "link.delete", "fwdwan0") {
		t.Fatal("pluginControlHasNetAccess(link.delete, fwdwan0) = true, want false")
	}
	if pluginControlHasNetAccess(plugin, "link.create", "eth0") {
		t.Fatal("pluginControlHasNetAccess(link.create, eth0) = true, want false")
	}
	if !pluginControlHasAnyNetAccess(plugin, "link.read") {
		t.Fatal("pluginControlHasAnyNetAccess(link.read) = false, want true")
	}
	if pluginControlHasAnyNetAccess(plugin, "route.write") {
		t.Fatal("pluginControlHasAnyNetAccess(route.write) = true, want false")
	}
}

func TestPluginControlStabilityGateAllowsSafeLabControl(t *testing.T) {
	t.Parallel()

	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "safe_lab",
			Stability: pluginStabilityLab,
			Control: &PluginControl{
				Permissions: []string{"kv"},
			},
		},
	}

	ok, reason := pluginControlStabilityAllowed(plugin, &Config{})
	if !ok || reason != "" {
		t.Fatalf("pluginControlStabilityAllowed(safe lab) = %t/%q, want allowed", ok, reason)
	}
}

func TestPluginControlStabilityGateAllowsPrivilegedLabByDefault(t *testing.T) {
	t.Parallel()

	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "privileged_lab",
			Stability: pluginStabilityLab,
			Control: &PluginControl{
				Permissions: []string{"net.l2"},
			},
		},
	}

	ok, reason := pluginControlStabilityAllowed(plugin, &Config{})
	if !ok || reason != "" {
		t.Fatalf("pluginControlStabilityAllowed(privileged lab default) = %t/%q, want allowed", ok, reason)
	}
}

func TestPluginControlStabilityGateBlocksDeprecated(t *testing.T) {
	t.Parallel()

	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "old_control",
			Stability: pluginStabilityDeprecated,
			Control: &PluginControl{
				Permissions: []string{"kv"},
			},
		},
	}

	ok, reason := pluginControlStabilityAllowed(plugin, &Config{})
	if ok || reason == "" {
		t.Fatalf("pluginControlStabilityAllowed(deprecated) = %t/%q, want blocked", ok, reason)
	}
}

func TestPluginControlReconcileAllowsPrivilegedLabByDefault(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{}, nil).(*gojaPluginControlRuntime)
	controlPath := filepath.Join(t.TempDir(), "control.js")
	if err := os.WriteFile(controlPath, []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile(control.js) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "privileged_l2_lab",
			Name:      "Privileged L2 Lab",
			Version:   "0.1.0",
			Stability: pluginStabilityLab,
			Control: &PluginControl{
				Permissions: []string{"net.l2"},
			},
		},
		Status:          pluginStatusActive,
		controlMainPath: controlPath,
	}

	snapshot := rt.Reconcile(PluginCatalog{Plugins: []LoadedPlugin{plugin}})
	state, ok := snapshot.stateFor("privileged_l2_lab")
	if !ok {
		t.Fatalf("snapshot = %+v, want privileged_l2_lab state", snapshot)
	}
	if state.Mode != pluginRuntimeModeControl || state.Attachable || state.Attached || state.Reason != "control script loaded" {
		t.Fatalf("state = %+v, want control runtime for privileged lab", state)
	}
	if _, loaded := rt.plugins["privileged_l2_lab"]; !loaded {
		t.Fatal("privileged lab plugin was not registered for control events")
	}
}

func TestPluginRuntimeApplyAllowsPrivilegedLabControlByDefault(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "privileged_l2_lab",
			Name:      "Privileged L2 Lab",
			Version:   "0.1.0",
			Stability: pluginStabilityLab,
			Control: &PluginControl{
				Permissions: []string{"net.l2"},
			},
		},
		Status:          pluginStatusActive,
		controlMainPath: "control.js",
	}
	action := PluginAction{ID: "dial", RuntimeUpdate: "runtime_apply"}

	err := applyPluginActionRuntimeUpdate(db, nil, plugin, action, json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "plugin runtime data applier is unavailable") {
		t.Fatalf("applyPluginActionRuntimeUpdate(privileged lab) error = %v, want applier unavailable after stability gate passes", err)
	}
}
