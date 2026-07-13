package app

import (
	"encoding/json"
	"net"
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
		{pattern: "veer*wan*", iface: "veer0wan1", want: true},
		{pattern: "veer*wan*", iface: "wanveer0", want: false},
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
					{Interfaces: []string{"veer*", "wan*"}, Operations: []string{"link.create", "addr.write"}},
					{Interfaces: []string{"eth*"}, Operations: []string{"link.read"}},
				},
			},
		},
	}

	if !pluginControlHasNetAccess(plugin, "link.create", "veerwan0") {
		t.Fatal("pluginControlHasNetAccess(link.create, veerwan0) = false, want true")
	}
	if !pluginControlHasNetAccess(plugin, "addr.write", "wan0") {
		t.Fatal("pluginControlHasNetAccess(addr.write, wan0) = false, want true")
	}
	if pluginControlHasNetAccess(plugin, "link.delete", "veerwan0") {
		t.Fatal("pluginControlHasNetAccess(link.delete, veerwan0) = true, want false")
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

func TestPluginControlUDPAPIUsesNetAccess(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "udp_probe"), 0o755); err != nil {
		t.Fatalf("MkdirAll(udp_probe) error = %v", err)
	}
	writePluginControlScript(t, dir, "udp_probe", `
exports.onAction = function () {
  net.udp.exchange({
    interface: "eth0",
    remote_ip: "198.51.100.10",
    port: 51820,
    payload_hex: "010203",
    timeout_ms: 50
  });
};
`)
	transport := &pluginControlUDPTestTransport{}
	rt := newPluginControlRuntime(db, &Config{}, nil).(*gojaPluginControlRuntime)
	rt.udpTransport = transport
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "udp_probe",
			Name:      "UDP Probe",
			Version:   "0.1.0",
			Stability: pluginStabilityStable,
			Control: &PluginControl{
				Main:        "control.js",
				Permissions: []string{"net.udp"},
				NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth*"}, Operations: []string{"udp"}}},
			},
		},
		Status:          pluginStatusActive,
		controlMainPath: filepath.Join(dir, "udp_probe", "control.js"),
	}

	if err := rt.ApplyPluginAction(plugin, PluginAction{ID: "probe"}, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction udp exchange error = %v", err)
	}
	if len(transport.exchanges) != 1 {
		t.Fatalf("udp exchanges = %d, want 1", len(transport.exchanges))
	}
	req := transport.exchanges[0]
	if req.Send.Interface != "eth0" || !req.Send.RemoteIP.Equal(net.ParseIP("198.51.100.10")) || req.Send.RemotePort != 51820 || string(req.Send.Payload) != "\x01\x02\x03" {
		t.Fatalf("udp exchange request = %+v, want eth0 -> 198.51.100.10:51820 payload 010203", req.Send)
	}
	if req.Recv.LocalPort != 0 || !req.Recv.HasRemoteFilter || req.Recv.RemotePort != 51820 {
		t.Fatalf("udp exchange recv request = %+v, want ephemeral local port and remote port filter 51820", req.Recv)
	}
}

func TestPluginControlUDPAPIRejectsMissingNetAccess(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "udp_probe_denied"), 0o755); err != nil {
		t.Fatalf("MkdirAll(udp_probe_denied) error = %v", err)
	}
	writePluginControlScript(t, dir, "udp_probe_denied", `
exports.onAction = function () {
  net.udp.send({
    interface: "eth0",
    remote_ip: "198.51.100.10",
    remote_port: 51820,
    payload: "01"
  });
};
`)
	rt := newPluginControlRuntime(db, &Config{}, nil).(*gojaPluginControlRuntime)
	rt.udpTransport = &pluginControlUDPTestTransport{}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "udp_probe_denied",
			Name:      "UDP Probe Denied",
			Version:   "0.1.0",
			Stability: pluginStabilityStable,
			Control: &PluginControl{
				Main:        "control.js",
				Permissions: []string{"net.udp"},
				NetAccess:   []PluginNetAccess{{Interfaces: []string{"eth*"}, Operations: []string{"link.read"}}},
			},
		},
		Status:          pluginStatusActive,
		controlMainPath: filepath.Join(dir, "udp_probe_denied", "control.js"),
	}

	err := rt.ApplyPluginAction(plugin, PluginAction{ID: "probe"}, json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "net_access operation udp on interface eth0 is not declared") {
		t.Fatalf("ApplyPluginAction missing udp net_access error = %v, want net_access denial", err)
	}
}

type pluginControlUDPTestTransport struct {
	sends     []pluginControlUDPSendRequest
	recvs     []pluginControlUDPRecvRequest
	exchanges []pluginControlUDPExchangeRequest
}

func (t *pluginControlUDPTestTransport) Send(req pluginControlUDPSendRequest) (pluginControlUDPResult, error) {
	t.sends = append(t.sends, req)
	return pluginControlUDPResult{
		Interface:  req.Interface,
		LocalAddr:  &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000},
		RemoteAddr: &net.UDPAddr{IP: req.RemoteIP, Port: req.RemotePort},
		Bytes:      len(req.Payload),
	}, nil
}

func (t *pluginControlUDPTestTransport) Recv(req pluginControlUDPRecvRequest) (pluginControlUDPDatagram, error) {
	t.recvs = append(t.recvs, req)
	return pluginControlUDPDatagram{
		Interface:  req.Interface,
		LocalAddr:  &net.UDPAddr{IP: req.LocalIP, Port: req.LocalPort},
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 51820},
		Payload:    []byte{0xaa},
	}, nil
}

func (t *pluginControlUDPTestTransport) Exchange(req pluginControlUDPExchangeRequest) (pluginControlUDPDatagram, error) {
	t.exchanges = append(t.exchanges, req)
	return pluginControlUDPDatagram{
		Interface:  req.Send.Interface,
		LocalAddr:  &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000},
		RemoteAddr: &net.UDPAddr{IP: req.Send.RemoteIP, Port: req.Send.RemotePort},
		Payload:    []byte{0xaa},
	}, nil
}
