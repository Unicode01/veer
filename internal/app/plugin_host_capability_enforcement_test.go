package app

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// pluginHostCapabilityProbeArgs gives the probe calls arguments that pass the
// first argument checks, so a missing phase or permission gate is not hidden
// behind an argument error.
var pluginHostCapabilityProbeArgs = map[string]string{
	"kv.get": `"k"`, "kv.set": `"k", 1`, "kv.delete": `"k"`, "kv.list": ``,
	"resources.get": `"r", "k"`, "resources.list": `"r"`, "resources.set": `"r", "k", {}`, "resources.delete": `"r", "k"`,
	"resources.transaction": `[]`,
	"secret.get":            `"k"`, "secret.set": `"k", "v"`, "secret.delete": `"k"`,
	"timer.setTimeout": `"t", 1000`, "timer.setInterval": `"t", 1000`, "timer.clear": `"t"`, "timer.list": ``,
	"events.publish": `"plugin.probe.x", {}`, "events.deadLetters": ``, "events.stats": ``,
	"events.retry": `"00000000000000000000000000000000"`, "events.discard": `"00000000000000000000000000000000"`,
	"worker.list": ``, "worker.stats": ``, "worker.call": `"w", "h", {}`, "worker.dispatch": `"w", "h", {}`,
	"metrics.counter": `"m", 1`, "metrics.gauge": `"m", 1`, "metrics.list": ``, "metrics.delete": `"m"`, "metrics.clear": ``,
	"crypto.md5": `"x"`, "crypto.randomBytes": `4`, "crypto.sha256File": `"control.js"`,
	"ebpf.monotonicMs": ``, "plugin.host": ``, "plugin.attachments": ``,
	"log.debug": `"x"`, "log.info": `"x"`, "log.warn": `"x"`, "log.error": `"x"`,
	"net.link.setARP": `"veer0", true`, "net.link.setPromiscuous": `"veer0", true`, "net.link.setMTU": `"veer0", 1500`,
	"net.link.setGSO": `"veer0", {"max_size": 65536, "max_segs": 64}`, "net.link.setOffloads": `"veer0", {"gro": true}`,
	"net.rule.replace": `{"family": "ipv4", "priority": 100, "table": 100}`, "net.rule.delete": `{"family": "ipv4", "priority": 100, "table": 100}`,
}

type pluginHostCapabilityProbeResult struct {
	message string
	panic   bool
}

func probePluginHostCapability(t *testing.T, db *sql.DB, permissions []string, registration bool, method string) pluginHostCapabilityProbeResult {
	t.Helper()
	vm := goja.New()
	host := &pluginControlHost{vm: vm, plugin: LoadedPlugin{
		PluginManifest: PluginManifest{ID: "probe", Control: &PluginControl{
			Main: "control.js", Permissions: permissions,
			// Every net_access operation is granted, so only the phase and
			// permission gates can turn a call down.
			NetAccess: []PluginNetAccess{{Interfaces: []string{"*"}, Operations: []string{
				"addr.write", "bridge.fdb.read", "dns", "http", "l2", "link.create", "link.delete", "link.master", "link.offload",
				"link.read", "link.state", "neigh.read", "neigh.write", "route.write", "rule.write", "tcp", "tuntap", "udp",
			}, RemoteCIDRs: []string{"0.0.0.0/0", "::/0"}}},
		}},
	}}
	if err := host.install(); err != nil {
		t.Fatalf("install host: %v", err)
	}
	host.db = db
	host.registrationPhase = registration
	args, ok := pluginHostCapabilityProbeArgs[method]
	if !ok {
		args = "{}"
		switch {
		case strings.HasPrefix(method, "net.link."):
			args = `"veer0"`
		case strings.HasPrefix(method, "net.addr."):
			args = `{"interface": "veer0", "cidr": "192.0.2.1/24"}`
		case strings.HasPrefix(method, "net.route.") && !strings.HasSuffix(method, ".transaction"):
			args = `{"dst": "192.0.2.0/24", "dev": "veer0"}`
		case strings.HasPrefix(method, "net.rule.") && !strings.HasSuffix(method, ".transaction"):
			args = `{"priority": 100, "table": 100}`
		case strings.HasPrefix(method, "net.neigh.") && !strings.HasSuffix(method, ".transaction"):
			args = `{"interface": "veer0", "ip": "192.0.2.2", "mac": "02:00:00:00:00:01"}`
		case strings.HasSuffix(method, ".transaction") && strings.HasPrefix(method, "net."):
			args = `[{"op": "replace", "request": {"interface": "veer0", "ip": "192.0.2.2", "mac": "02:00:00:00:00:01", "dst": "192.0.2.0/24", "dev": "veer0", "priority": 100, "table": 100}}]`
		case strings.HasPrefix(method, "net."):
			args = `{"interface": "veer0", "name": "veer0"}`
		}
	}
	parts := strings.Split(method, ".")
	owner := strings.Join(parts[:len(parts)-1], ".")
	script := fmt.Sprintf(`(function(){ try { %s.%s.call(%s%s); return "ok"; } catch (error) { return String(error && error.message || error); } })()`,
		owner, parts[len(parts)-1], owner, map[bool]string{true: ", " + args, false: ""}[args != ""])
	var result pluginHostCapabilityProbeResult
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				result = pluginHostCapabilityProbeResult{message: fmt.Sprint(recovered), panic: true}
			}
		}()
		value, err := vm.RunString(script)
		if err != nil {
			result = pluginHostCapabilityProbeResult{message: err.Error()}
			return
		}
		result = pluginHostCapabilityProbeResult{message: value.String()}
	}()
	return result
}

// pluginHostCapabilityProbeUnavailable reports results that depend on a
// runtime the probe does not build, so they say nothing about the gates.
func pluginHostCapabilityProbeUnavailable(result pluginHostCapabilityProbeResult) bool {
	if result.panic {
		return true
	}
	for _, missing := range []string{"registry is unavailable", "store is unavailable", "controller is unavailable"} {
		if strings.Contains(result.message, missing) {
			return true
		}
	}
	return false
}

func pluginHostCapabilityProbePhaseDenied(message string) bool {
	return strings.Contains(message, "registration")
}

func pluginHostCapabilityProbePermissionDenied(message string) bool {
	return strings.Contains(message, "permission") || strings.Contains(message, "requires one of")
}

// TestPluginHostCapabilityTableMatchesGojaEnforcement keeps the declared
// capability table (published as sdk/plugin/api-contract.json and enforced by
// the SDK test host) in line with the checks the goja host really performs.
func TestPluginHostCapabilityTableMatchesGojaEnforcement(t *testing.T) {
	all := []string{
		"blob", "crypto", "ebpf.load", "ebpf.map_read", "ebpf.map_write", "event", "exec", "hook.attach", "kv",
		"metrics", "net.admin", "net.dns", "net.http", "net.l2", "net.namespace", "net.tcp", "net.tuntap", "net.udp",
		"operation", "plugin.action", "plugin.event", "plugin.register", "plugin.resource", "resource", "secret",
		"timer", "ui", "worker",
	}
	db := openTestDB(t)
	var inconclusive []string
	note := func(method string, got pluginHostCapabilityProbeResult) {
		if pluginHostCapabilityProbeUnavailable(got) {
			inconclusive = append(inconclusive, method+": "+got.message)
		}
	}
	for _, capability := range pluginHostControlCapabilities {
		capability := capability
		t.Run(capability.Method, func(t *testing.T) {
			registrationAllowed := false
			runtimeAllowed := false
			for _, phase := range capability.Phases {
				registrationAllowed = registrationAllowed || phase == pluginHostPhaseRegistration
				runtimeAllowed = runtimeAllowed || phase == pluginHostPhaseRuntime
			}
			if !registrationAllowed {
				got := probePluginHostCapability(t, db, all, true, capability.Method)
				note(capability.Method, got)
				if !pluginHostCapabilityProbeUnavailable(got) && !pluginHostCapabilityProbePhaseDenied(got.message) {
					t.Errorf("registration phase: contract forbids it, host returned %q", got.message)
				}
			}
			needsPermission := len(capability.Permissions) > 0 || len(capability.AnyPermissions) > 0
			phaseRegistration := !runtimeAllowed
			if needsPermission {
				got := probePluginHostCapability(t, db, nil, phaseRegistration, capability.Method)
				note(capability.Method, got)
				if !pluginHostCapabilityProbeUnavailable(got) && !pluginHostCapabilityProbePermissionDenied(got.message) {
					t.Errorf("no permissions: contract needs %v%v, host returned %q", capability.Permissions, capability.AnyPermissions, got.message)
				}
			}
		})
	}
	// Calls that need a database or runtime the probe does not build cannot
	// show their gates. Keep them few, so the probe keeps covering the table.
	if len(inconclusive) > 24 {
		t.Fatalf("%d probe calls were inconclusive: %s", len(inconclusive), strings.Join(inconclusive, "; "))
	}
	t.Logf("%d inconclusive probe calls: %s", len(inconclusive), strings.Join(inconclusive, "; "))
}
