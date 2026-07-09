package app

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"forward/internal/store"

	"github.com/dop251/goja"
)

func TestLoadPluginCatalogIncludesBuiltinFVTap(t *testing.T) {
	t.Parallel()

	catalog := loadPluginCatalog(&Config{PluginsDir: filepath.Join(t.TempDir(), "missing")})
	if !catalog.ExternalPluginsEnabled {
		t.Fatal("ExternalPluginsEnabled = false, want true by default")
	}
	if catalog.Runtime.BuiltinPipelineID != "fvtap" || catalog.Runtime.ExternalDataplaneAttach {
		t.Fatalf("catalog runtime = %+v, want builtin fvtap with external attach disabled", catalog.Runtime)
	}
	if catalog.Runtime.CorePriority != pluginPipelineCorePriority {
		t.Fatalf("catalog runtime core priority = %d, want %d", catalog.Runtime.CorePriority, pluginPipelineCorePriority)
	}
	if got := strings.Join(catalog.Runtime.ExternalDataplaneEngines, ","); got != "tc" {
		t.Fatalf("catalog runtime external dataplane engines = %q, want tc", got)
	}
	if got := strings.Join(catalog.Runtime.RegistrationOnlyEngines, ","); got != "xdp" {
		t.Fatalf("catalog runtime registration-only engines = %q, want xdp", got)
	}
	if got := strings.Join(catalog.Runtime.StabilityLevels, ","); got != "lab,preview,stable,deprecated" {
		t.Fatalf("catalog runtime stability levels = %q, want lab,preview,stable,deprecated", got)
	}
	if len(catalog.Plugins) != 1 {
		t.Fatalf("plugin count = %d, want builtin only", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[0]
	if plugin.ID != "fvtap" || plugin.Status != pluginStatusBuiltin || !plugin.Builtin {
		t.Fatalf("builtin plugin = %+v, want fvtap builtin", plugin)
	}
	if plugin.Stability != pluginStabilityStable {
		t.Fatalf("builtin plugin stability = %q, want stable", plugin.Stability)
	}
	if plugin.Runtime.Mode != pluginRuntimeModeBuiltin || !plugin.Runtime.Attached || !plugin.Runtime.Attachable {
		t.Fatalf("builtin runtime = %+v, want attached builtin runtime", plugin.Runtime)
	}
	if len(plugin.Hooks) == 0 {
		t.Fatal("builtin fvtap hooks are empty")
	}
	if plugin.Hooks[0].Priority != pluginPipelineCorePriority {
		t.Fatalf("builtin fvtap tc priority = %d, want %d", plugin.Hooks[0].Priority, pluginPipelineCorePriority)
	}
}

func TestLoadPluginCatalogLoadsExternalPlugin(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "packet_observer", `{
  "api_version": "v1",
  "id": "packet_observer",
  "name": "Packet Observer",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "ui"]
  }
}`)
	writePluginControlScript(t, dir, "packet_observer", `
plugin.capabilities(['observe', 'observe']);
plugin.virtualInterface({id: 'vtap0', type: 'logical'});
ui.register({static_dir: 'ui', entry: 'index.html'});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + external", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.ID != "packet_observer" || plugin.Status != pluginStatusActive {
		t.Fatalf("external plugin = %+v, want active packet_observer", plugin)
	}
	if plugin.Stability != pluginStabilityLab {
		t.Fatalf("external plugin stability = %q, want default lab", plugin.Stability)
	}
	if plugin.Runtime.Mode != pluginRuntimeModeRegistered || plugin.Runtime.Attachable || plugin.Runtime.Attached {
		t.Fatalf("external runtime = %+v, want registered non-attachable runtime", plugin.Runtime)
	}
	if got := plugin.AssetBasePath; got != "/api/plugins/packet_observer/assets/" {
		t.Fatalf("AssetBasePath = %q, want packet_observer assets path", got)
	}
	if len(plugin.Capabilities) != 1 || plugin.Capabilities[0] != "observe" {
		t.Fatalf("Capabilities = %#v, want deduplicated observe", plugin.Capabilities)
	}
}

func TestLoadPluginCatalogReportsInvalidPlugin(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "bad")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(`{"id":"fvtap","name":"bad","version":"0.1.0"}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + invalid", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "reserved") {
		t.Fatalf("invalid plugin = %+v, want reserved id error", plugin)
	}
	if plugin.Runtime.Mode != pluginRuntimeModeInvalid {
		t.Fatalf("invalid plugin runtime = %+v, want invalid", plugin.Runtime)
	}
}

func TestNormalizePluginManifestKeepsSlimManifestOnly(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control:    &PluginControl{Main: "control.js"},
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest() error = %v", err)
	}
	if got := manifest.Stability; got != pluginStabilityLab {
		t.Fatalf("default stability = %q, want lab", got)
	}
	if manifest.Control == nil || manifest.Control.Main != "control.js" {
		t.Fatalf("control = %+v, want control.js", manifest.Control)
	}
}

func TestPluginManifestUnmarshalRejectsRuntimeOwnedFields(t *testing.T) {
	t.Parallel()

	fields := map[string]string{
		"actions":            `[{"id":"apply"}]`,
		"builtin":            `true`,
		"capabilities":       `["observe"]`,
		"hooks":              `[{"id":"observe","engine":"control","stage":"configure"}]`,
		"metadata":           `{"ui.page":"observe"}`,
		"objects":            `[{"id":"observer","path":"observer.o"}]`,
		"resources":          `[{"id":"settings"}]`,
		"ui":                 `{"static_dir":"ui"}`,
		"virtual_interfaces": `[{"id":"vtap0"}]`,
	}
	for field, value := range fields {
		field, value := field, value
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			var manifest PluginManifest
			raw := fmt.Sprintf(`{"api_version":"v1","id":"control_plugin","name":"Control Plugin","version":"0.1.0","kind":"control","%s":%s}`, field, value)
			if err := json.Unmarshal([]byte(raw), &manifest); err == nil || !strings.Contains(err.Error(), "runtime-owned") {
				t.Fatalf("json.Unmarshal() error = %v, want runtime-owned rejection", err)
			}
		})
	}
}

func TestNormalizePluginManifestRejectsInvalidStability(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "bad_stability",
		Name:       "Bad Stability",
		Version:    "0.1.0",
		Kind:       "control",
		Stability:  "production",
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "stability") {
		t.Fatalf("normalizePluginManifest() error = %v, want stability error", err)
	}
}

func TestNormalizePluginRuntimeResourceAndAction(t *testing.T) {
	t.Parallel()

	resource := PluginResource{
		ID:             "Bindings",
		Methods:        []string{"update", "list", "update"},
		ControlMethods: []string{"delete", "create", "delete"},
		MaxRecords:     2,
		MaxRecordBytes: 128,
		SecretFields:   []string{"Password"},
	}
	if err := normalizePluginResource(&resource); err != nil {
		t.Fatalf("normalizePluginResource() error = %v", err)
	}
	if got := resource.ID; got != "bindings" {
		t.Fatalf("resource id = %q, want bindings", got)
	}
	if got := strings.Join(resource.Methods, ","); got != "list,update" {
		t.Fatalf("resource methods = %q, want list,update", got)
	}
	if got := strings.Join(resource.ControlMethods, ","); got != "create,delete" {
		t.Fatalf("resource control methods = %q, want create,delete", got)
	}
	if got := strings.Join(resource.SecretFields, ","); got != "password" {
		t.Fatalf("secret fields = %q, want password", got)
	}
	if got := resource.RuntimeUpdate; got != "none" {
		t.Fatalf("resource runtime update = %q, want none", got)
	}

	action := PluginAction{ID: "Apply", RuntimeUpdate: "plugin_reconcile"}
	if err := normalizePluginAction(&action); err != nil {
		t.Fatalf("normalizePluginAction() error = %v", err)
	}
	if got := action.ID; got != "apply" {
		t.Fatalf("action id = %q, want apply", got)
	}
	if got := action.MaxPayloadBytes; got != pluginActionDefaultMaxPayloadBytes {
		t.Fatalf("action max payload = %d, want default %d", got, pluginActionDefaultMaxPayloadBytes)
	}
}

func TestNormalizePluginManifestControlMainAndPermissions(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "scripts/../control.js",
			Permissions: []string{"KV", "ebpf.map_write", "secret", "crypto", "Net.Admin", "plugin.resource"},
			ResourceAccess: []PluginResourceAccess{{
				Plugin:   "Target_Plugin",
				Resource: "Settings",
				Methods:  []string{"GET", "list", "get"},
			}},
			NetAccess: []PluginNetAccess{{
				Interfaces: []string{"Fwd*"},
				Operations: []string{"Link.Create", "addr.write", "link.create"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest() error = %v", err)
	}
	if manifest.Control == nil || manifest.Control.Main != "control.js" {
		t.Fatalf("control = %+v, want normalized control.js", manifest.Control)
	}
	if got := strings.Join(manifest.Control.Permissions, ","); got != "crypto,ebpf.map_write,kv,net.admin,plugin.resource,secret" {
		t.Fatalf("control permissions = %q, want crypto,ebpf.map_write,kv,net.admin,plugin.resource,secret", got)
	}
	if len(manifest.Control.ResourceAccess) != 1 {
		t.Fatalf("control resource access = %+v, want one entry", manifest.Control.ResourceAccess)
	}
	access := manifest.Control.ResourceAccess[0]
	if access.Plugin != "target_plugin" || access.Resource != "settings" || strings.Join(access.Methods, ",") != "get,list" {
		t.Fatalf("control resource access = %+v, want target_plugin/settings get,list", access)
	}
	if len(manifest.Control.NetAccess) != 1 || strings.Join(manifest.Control.NetAccess[0].Interfaces, ",") != "Fwd*" || strings.Join(manifest.Control.NetAccess[0].Operations, ",") != "addr.write,link.create" {
		t.Fatalf("control net access = %+v, want Fwd* addr.write,link.create", manifest.Control.NetAccess)
	}
}

func TestNormalizePluginManifestRejectsControlTraversal(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main: "../control.js",
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("normalizePluginManifest() error = %v, want control traversal error", err)
	}
}

func TestNormalizePluginResourceRejectsInvalidMethod(t *testing.T) {
	t.Parallel()

	resource := PluginResource{ID: "bindings", Methods: []string{"root"}}
	if err := normalizePluginResource(&resource); err == nil || !strings.Contains(err.Error(), "method") {
		t.Fatalf("normalizePluginResource() error = %v, want invalid method", err)
	}
}

func TestNormalizePluginResourceRejectsInvalidControlMethod(t *testing.T) {
	t.Parallel()

	resource := PluginResource{
		ID:             "status",
		Methods:        []string{"list", "get"},
		ControlMethods: []string{"create", "root"},
	}
	if err := normalizePluginResource(&resource); err == nil || !strings.Contains(err.Error(), "method") {
		t.Fatalf("normalizePluginResource() error = %v, want invalid control method", err)
	}
}

func TestNormalizePluginResourceRejectsReservedInternalResourceID(t *testing.T) {
	t.Parallel()

	resource := PluginResource{ID: pluginControlSecretResourceID, Methods: []string{"list", "get"}}
	if err := normalizePluginResource(&resource); err == nil || !strings.Contains(err.Error(), "reserved for plugin control internals") {
		t.Fatalf("normalizePluginResource() error = %v, want reserved internal resource error", err)
	}
}

func TestNormalizePluginManifestRejectsInvalidResourceAccess(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"plugin.resource"},
			ResourceAccess: []PluginResourceAccess{{
				Plugin:   "target_plugin",
				Resource: "settings",
				Methods:  []string{"execute"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "resource_access") {
		t.Fatalf("normalizePluginManifest() error = %v, want resource_access method error", err)
	}
}

func TestNormalizePluginManifestRejectsReservedInternalResourceAccess(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"plugin.resource"},
			ResourceAccess: []PluginResourceAccess{{
				Plugin:   "target_plugin",
				Resource: pluginControlKVResourceID,
				Methods:  []string{"get"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "reserved for plugin control internals") {
		t.Fatalf("normalizePluginManifest() error = %v, want reserved internal resource access error", err)
	}
}

func TestNormalizePluginManifestRejectsDuplicateResourceAccess(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"plugin.resource"},
			ResourceAccess: []PluginResourceAccess{{
				Plugin:   "target_plugin",
				Resource: "settings",
				Methods:  []string{"get"},
			}, {
				Plugin:   "target_plugin",
				Resource: "settings",
				Methods:  []string{"list"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "duplicate resource access") {
		t.Fatalf("normalizePluginManifest() error = %v, want duplicate resource_access error", err)
	}
}

func TestNormalizePluginManifestRejectsResourceAccessWithoutPermission(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main: "control.js",
			ResourceAccess: []PluginResourceAccess{{
				Plugin:   "target_plugin",
				Resource: "settings",
				Methods:  []string{"get"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "requires plugin.resource permission") {
		t.Fatalf("normalizePluginManifest() error = %v, want resource_access permission error", err)
	}
}

func TestNormalizePluginManifestActionAccess(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"plugin.action"},
			ActionAccess: []PluginActionAccess{{
				Plugin:  "Target_Plugin",
				Actions: []string{"Apply", "teardown", "apply"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest() error = %v", err)
	}
	if got := strings.Join(manifest.Control.Permissions, ","); got != "plugin.action" {
		t.Fatalf("control permissions = %q, want plugin.action", got)
	}
	if len(manifest.Control.ActionAccess) != 1 {
		t.Fatalf("control action access = %+v, want one entry", manifest.Control.ActionAccess)
	}
	access := manifest.Control.ActionAccess[0]
	if access.Plugin != "target_plugin" || strings.Join(access.Actions, ",") != "apply,teardown" {
		t.Fatalf("control action access = %+v, want target_plugin apply,teardown", access)
	}
}

func TestNormalizePluginManifestRejectsActionAccessWithoutPermission(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main: "control.js",
			ActionAccess: []PluginActionAccess{{
				Plugin:  "target_plugin",
				Actions: []string{"apply"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "requires plugin.action permission") {
		t.Fatalf("normalizePluginManifest() error = %v, want action_access permission error", err)
	}
}

func TestNormalizePluginManifestRejectsDuplicateActionAccess(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"plugin.action"},
			ActionAccess: []PluginActionAccess{{
				Plugin:  "target_plugin",
				Actions: []string{"apply"},
			}, {
				Plugin:  "target_plugin",
				Actions: []string{"apply"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "duplicate action access") {
		t.Fatalf("normalizePluginManifest() error = %v, want duplicate action_access error", err)
	}
}

func TestNormalizePluginManifestRejectsReservedActionAccessPlugin(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"plugin.action"},
			ActionAccess: []PluginActionAccess{{
				Plugin:  "fvtap",
				Actions: []string{"apply"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "reserved for the built-in pipeline") {
		t.Fatalf("normalizePluginManifest() error = %v, want reserved action_access plugin error", err)
	}
}

func TestNormalizePluginManifestRejectsNetPermissionWithoutAccess(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"net.admin"},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "net_access is required") {
		t.Fatalf("normalizePluginManifest() error = %v, want net_access required error", err)
	}
}

func TestNormalizePluginManifestRejectsNetAccessWithoutPermission(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main: "control.js",
			NetAccess: []PluginNetAccess{{
				Interfaces: []string{"eth*"},
				Operations: []string{"l2"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "requires net.l2 permission") {
		t.Fatalf("normalizePluginManifest() error = %v, want net_access permission error", err)
	}
}

func TestNormalizePluginManifestRejectsInvalidNetAccessOperation(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Control: &PluginControl{
			Main:        "control.js",
			Permissions: []string{"net.admin"},
			NetAccess: []PluginNetAccess{{
				Interfaces: []string{"eth*"},
				Operations: []string{"root"},
			}},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "net_access") {
		t.Fatalf("normalizePluginManifest() error = %v, want invalid net_access operation error", err)
	}
}

func TestNormalizePluginHookDefaultsControlHook(t *testing.T) {
	t.Parallel()

	hook := PluginHook{
		ID:     "configure",
		Engine: "control",
		Stage:  "configure",
	}
	if err := normalizePluginHook(&hook); err != nil {
		t.Fatalf("normalizePluginHook() error = %v", err)
	}
	if got := hook.Attach; got != "none" {
		t.Fatalf("control hook attach = %q, want none", got)
	}
	if got := hook.Mode; got != "control" {
		t.Fatalf("control hook mode = %q, want control", got)
	}
}

func TestNormalizePluginHookRejectsInvalidHookContext(t *testing.T) {
	t.Parallel()

	hook := PluginHook{
		ID:      "inspect",
		Engine:  "control",
		Stage:   "configure",
		Context: []string{"host_memory"},
	}
	if err := normalizePluginHook(&hook); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("normalizePluginHook() error = %v, want invalid context", err)
	}
}

func TestLoadPluginCatalogReportsObjectHashMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "bad_hash", `{
  "api_version": "v1",
  "id": "bad_hash",
  "name": "Bad Hash",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {"main": "control.js", "permissions": ["ebpf.load"]}
}`)
	writePluginControlScript(t, dir, "bad_hash", `
ebpf.loadObject({
  id: 'observer',
  path: 'observer.o',
  sha256: '`+testSHA256Hex("different object")+`'
});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + bad_hash", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "sha256 mismatch") {
		t.Fatalf("plugin = %+v, want sha256 mismatch error", plugin)
	}
	if plugin.AssetBasePath != "" {
		t.Fatalf("AssetBasePath = %q, want empty for errored plugin", plugin.AssetBasePath)
	}
}

func TestLoadPluginCatalogRejectsStableObjectWithoutSHA256(t *testing.T) {
	t.Parallel()

	for _, stability := range []string{pluginStabilityStable, pluginStabilityPreview} {
		stability := stability
		t.Run(stability, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			pluginDir := filepath.Join(dir, "trusted_pipe")
			if err := os.MkdirAll(pluginDir, 0o755); err != nil {
				t.Fatalf("MkdirAll() error = %v", err)
			}
			if err := os.WriteFile(filepath.Join(pluginDir, "observer.o"), []byte("not an elf; sha gate should fail first"), 0o644); err != nil {
				t.Fatalf("WriteFile(observer.o) error = %v", err)
			}
			manifest := `{
  "api_version": "v1",
  "id": "trusted_pipe",
  "name": "Trusted Pipe",
  "version": "1.0.0",
  "kind": "pipeline",
  "stability": "` + stability + `",
  "control": {"main": "control.js", "permissions": ["ebpf.load"]}
}`
			if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
				t.Fatalf("WriteFile(plugin.json) error = %v", err)
			}
			writePluginControlScript(t, dir, "trusted_pipe", `
ebpf.loadObject({id:'observer', path:'observer.o'});
`)
			setTestPluginControlSHA(t, dir, "trusted_pipe")

			catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
			if len(catalog.Plugins) != 2 {
				t.Fatalf("plugin count = %d, want builtin + trusted_pipe", len(catalog.Plugins))
			}
			plugin := catalog.Plugins[1]
			if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "sha256 is required") {
				t.Fatalf("plugin = %+v, want missing sha256 error", plugin)
			}
		})
	}
}

func TestLoadPluginCatalogAllowsLabObjectWithoutSHA256(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "lab_pipe")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	objectPath := compileTestBPFObject(t, pluginDir, "observer.o")
	sum, err := sha256File(objectPath)
	if err != nil {
		t.Fatalf("sha256File(observer.o) error = %v", err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "lab_pipe",
  "name": "Lab Pipe",
  "version": "0.1.0",
  "kind": "pipeline",
  "stability": "lab",
  "control": {"main": "control.js", "permissions": ["ebpf.load"]}
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(plugin.json) error = %v", err)
	}
	writePluginControlScript(t, dir, "lab_pipe", `
ebpf.loadObject({id:'observer', path:'observer.o'});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + lab_pipe", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusActive {
		t.Fatalf("plugin = %+v, want active lab plugin without declared sha256", plugin)
	}
	if len(plugin.Objects) != 1 || plugin.Objects[0].ResolvedSHA256 != sum {
		t.Fatalf("objects = %+v, want resolved sha256 %s", plugin.Objects, sum)
	}
}

func TestLoadPluginCatalogRejectsStableControlWithoutSHA256(t *testing.T) {
	t.Parallel()

	for _, stability := range []string{pluginStabilityStable, pluginStabilityPreview} {
		stability := stability
		t.Run(stability, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			writeTestPlugin(t, dir, "trusted_control", `{
  "api_version": "v1",
  "id": "trusted_control",
  "name": "Trusted Control",
  "version": "1.0.0",
  "kind": "control",
  "stability": "`+stability+`",
  "control": {"main": "control.js", "permissions": ["kv"]}
}`)
			writePluginControlScript(t, dir, "trusted_control", `function onAction() { return {ok: true}; }`)

			catalog := loadPluginCatalog(&Config{PluginsDir: dir})
			if len(catalog.Plugins) != 2 {
				t.Fatalf("plugin count = %d, want builtin + trusted_control", len(catalog.Plugins))
			}
			plugin := catalog.Plugins[1]
			if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "control.sha256 is required") {
				t.Fatalf("plugin = %+v, want missing control.sha256 error", plugin)
			}
		})
	}
}

func TestLoadPluginCatalogReportsControlHashMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "bad_control_hash", `{
  "api_version": "v1",
  "id": "bad_control_hash",
  "name": "Bad Control Hash",
  "version": "1.0.0",
  "kind": "control",
  "stability": "stable",
  "control": {
    "main": "control.js",
    "sha256": "`+testSHA256Hex("different control")+`",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "bad_control_hash", `function onAction() { return {ok: true}; }`)

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + bad_control_hash", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "control.sha256 mismatch") {
		t.Fatalf("plugin = %+v, want control sha256 mismatch error", plugin)
	}
}

func TestLoadPluginCatalogAllowsLabControlWithoutSHA256(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	source := `function onAction() { return {ok: true}; }`
	writeTestPlugin(t, dir, "lab_control", `{
  "api_version": "v1",
  "id": "lab_control",
  "name": "Lab Control",
  "version": "0.1.0",
  "kind": "control",
  "stability": "lab",
  "control": {"main": "control.js", "permissions": ["kv"]}
}`)
	writePluginControlScript(t, dir, "lab_control", source)

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + lab_control", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusActive {
		t.Fatalf("plugin = %+v, want active lab control without declared sha256", plugin)
	}
	if plugin.Control == nil || plugin.Control.ResolvedSHA256 != testSHA256Hex(source) {
		t.Fatalf("control = %+v, want resolved sha256 %s", plugin.Control, testSHA256Hex(source))
	}
}

func TestLoadPluginCatalogRejectsStableUIWithoutSHA256(t *testing.T) {
	t.Parallel()

	for _, stability := range []string{pluginStabilityStable, pluginStabilityPreview} {
		stability := stability
		t.Run(stability, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			writeTestPlugin(t, dir, "trusted_ui", `{
  "api_version": "v1",
  "id": "trusted_ui",
  "name": "Trusted UI",
  "version": "1.0.0",
  "kind": "ui",
  "stability": "`+stability+`",
  "control": {"main": "control.js", "permissions": ["ui"]}
}`)
			writePluginControlScript(t, dir, "trusted_ui", `
ui.register({static_dir: 'ui', entry: 'index.html'});
`)
			setTestPluginControlSHA(t, dir, "trusted_ui")

			catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
			if len(catalog.Plugins) != 2 {
				t.Fatalf("plugin count = %d, want builtin + trusted_ui", len(catalog.Plugins))
			}
			plugin := catalog.Plugins[1]
			if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "ui.sha256 is required") {
				t.Fatalf("plugin = %+v, want missing ui.sha256 error", plugin)
			}
		})
	}
}

func TestLoadPluginCatalogReportsUIHashMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "bad_ui_hash", `{
  "api_version": "v1",
  "id": "bad_ui_hash",
  "name": "Bad UI Hash",
  "version": "1.0.0",
  "kind": "ui",
  "stability": "stable",
  "control": {"main": "control.js", "permissions": ["ui"]}
}`)
	writePluginControlScript(t, dir, "bad_ui_hash", `
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: '`+testSHA256Hex("different ui")+`'
});
`)
	setTestPluginControlSHA(t, dir, "bad_ui_hash")

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + bad_ui_hash", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "ui.sha256 mismatch") {
		t.Fatalf("plugin = %+v, want ui sha256 mismatch error", plugin)
	}
}

func TestLoadPluginCatalogAllowsLabUIWithoutSHA256(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "lab_ui", `{
  "api_version": "v1",
  "id": "lab_ui",
  "name": "Lab UI",
  "version": "0.1.0",
  "kind": "ui",
  "stability": "lab",
  "control": {"main": "control.js", "permissions": ["ui"]}
}`)
	writePluginControlScript(t, dir, "lab_ui", `
ui.register({static_dir: 'ui', entry: 'index.html'});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + lab_ui", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusActive {
		t.Fatalf("plugin = %+v, want active lab ui without declared sha256", plugin)
	}
	if plugin.UI == nil || plugin.UI.ResolvedSHA256 != testSHA256Hex("plugin asset ok") {
		t.Fatalf("ui = %+v, want resolved sha256 %s", plugin.UI, testSHA256Hex("plugin asset ok"))
	}
}

func TestLoadPluginCatalogRejectsObjectPathTraversal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "bad_path", `{
  "api_version": "v1",
  "id": "bad_path",
  "name": "Bad Path",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {"main": "control.js", "permissions": ["ebpf.load"]}
}`)
	writePluginControlScript(t, dir, "bad_path", `
ebpf.loadObject({id: 'observer', path: '../observer.o'});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + bad_path", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "path traversal") {
		t.Fatalf("plugin = %+v, want path traversal error", plugin)
	}
}

func TestLoadPluginCatalogRejectsManifestSymlinkEscape(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "bad_manifest_link")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	outsideManifest := filepath.Join(dir, "outside-plugin.json")
	if err := os.WriteFile(outsideManifest, []byte(`{"id":"bad_manifest_link","name":"Bad Manifest Link","version":"0.1.0"}`), 0o644); err != nil {
		t.Fatalf("WriteFile(outside manifest) error = %v", err)
	}
	if err := os.Symlink(outsideManifest, filepath.Join(pluginDir, pluginManifestFile)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + invalid", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "plugin.json escapes plugin root") {
		t.Fatalf("plugin = %+v, want manifest symlink escape error", plugin)
	}
}

func TestLoadPluginCatalogRejectsOversizedObject(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "too_big")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	objectFile, err := os.Create(filepath.Join(pluginDir, "observer.o"))
	if err != nil {
		t.Fatalf("Create(observer.o) error = %v", err)
	}
	if err := objectFile.Truncate(pluginObjectMaxSize + 1); err != nil {
		_ = objectFile.Close()
		t.Fatalf("Truncate(observer.o) error = %v", err)
	}
	if err := objectFile.Close(); err != nil {
		t.Fatalf("Close(observer.o) error = %v", err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "too_big",
  "name": "Too Big",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {"main": "control.js", "permissions": ["ebpf.load"]}
}`
	cleanManifest, registrationPrelude := testPluginManifestAndRegistrationPrelude(t, manifest)
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(cleanManifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	if registrationPrelude != "" {
		if err := os.WriteFile(filepath.Join(pluginDir, ".runtime-register.js"), []byte(registrationPrelude), 0o644); err != nil {
			t.Fatalf("WriteFile(.runtime-register.js) error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, "control.js"), []byte(registrationPrelude+"\nexports.onReconcile = function () {};\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(default control.js) error = %v", err)
		}
	}
	writePluginControlScript(t, dir, "too_big", `
ebpf.loadObject({id:'observer', path:'observer.o'});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + too_big", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "object exceeds") {
		t.Fatalf("plugin = %+v, want oversized object error", plugin)
	}
}

func TestLoadPluginCatalogParsesBPFObjectSpec(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "packet_observer")
	uiDir := filepath.Join(pluginDir, "ui")
	if err := os.MkdirAll(uiDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte("plugin asset ok"), 0o644); err != nil {
		t.Fatalf("WriteFile(index.html) error = %v", err)
	}
	objectPath := compileTestBPFObject(t, pluginDir, "observer.o")
	sum, err := sha256File(objectPath)
	if err != nil {
		t.Fatalf("sha256File() error = %v", err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "packet_observer",
  "name": "Packet Observer",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {"main": "control.js", "permissions": ["ebpf.load", "hook.attach", "ui"]}
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writePluginControlScript(t, dir, "packet_observer", `
ebpf.loadObject({
  id: 'observer',
  path: 'observer.o',
  sha256: '`+sum+`',
  programs: [{id: 'tc_ingress', section: 'tc/ingress', type: 'tc'}]
});
hooks.attach({
  id: 'observe-ingress',
  engine: 'tc',
  attach: 'ingress',
  stage: 'forward',
  priority: 10,
  program: 'observer:tc_ingress',
  mode: 'observe'
});
ui.register({static_dir: 'ui', entry: 'index.html'});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + packet_observer", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusActive {
		t.Fatalf("plugin status = %q error=%q, want active", plugin.Status, plugin.Error)
	}
	if len(plugin.Objects) != 1 {
		t.Fatalf("objects = %#v, want one object", plugin.Objects)
	}
	object := plugin.Objects[0]
	if object.Status != pluginObjectStatusVerified || object.ResolvedSHA256 != sum || object.ProgramCount != 1 {
		t.Fatalf("object = %+v, want verified object with parsed program", object)
	}
	if len(object.Programs) != 1 || object.Programs[0].Type != kernelEngineTC || object.Programs[0].InstructionCount == 0 {
		t.Fatalf("object programs = %+v, want parsed TC program with instructions", object.Programs)
	}
}

func TestLoadPluginCatalogReportsMissingHookProgramRef(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "bad_hook")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	objectPath := compileTestBPFObject(t, pluginDir, "observer.o")
	sum, err := sha256File(objectPath)
	if err != nil {
		t.Fatalf("sha256File() error = %v", err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "bad_hook",
  "name": "Bad Hook",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {"main": "control.js", "permissions": ["ebpf.load", "hook.attach"]}
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writePluginControlScript(t, dir, "bad_hook", `
ebpf.loadObject({
  id: 'observer',
  path: 'observer.o',
  sha256: '`+sum+`',
  programs: [{id: 'tc_ingress', section: 'tc/ingress', type: 'tc'}]
});
hooks.attach({
  id: 'observe-ingress',
  engine: 'tc',
  stage: 'forward',
  priority: 10,
  program: 'observer:missing',
  mode: 'observe'
});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + bad_hook", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "program \"missing\" not found") {
		t.Fatalf("plugin = %+v, want missing hook program error", plugin)
	}
}

func TestLoadPluginCatalogRejectsHookProgramTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "bad_engine")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	objectPath := compileTestBPFObject(t, pluginDir, "observer.o")
	sum, err := sha256File(objectPath)
	if err != nil {
		t.Fatalf("sha256File() error = %v", err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "bad_engine",
  "name": "Bad Engine",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {"main": "control.js", "permissions": ["ebpf.load", "hook.attach"]}
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writePluginControlScript(t, dir, "bad_engine", `
ebpf.loadObject({
  id: 'observer',
  path: 'observer.o',
  sha256: '`+sum+`',
  programs: [{id: 'tc_ingress', section: 'tc/ingress', type: 'tc'}]
});
hooks.attach({
  id: 'observe-ingress',
  engine: 'xdp',
  stage: 'forward',
  priority: 10,
  program: 'observer:tc_ingress',
  mode: 'observe'
});
`)

	catalog := loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + bad_engine", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, `type = "tc", want hook engine "xdp"`) {
		t.Fatalf("plugin = %+v, want hook engine mismatch error", plugin)
	}
}

func TestPluginAPIListsCatalogAndServesAssets(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "ui_plugin", `{
  "api_version": "v1",
  "id": "ui_plugin",
  "name": "UI Plugin",
  "version": "0.1.0",
  "kind": "ui",
  "ui": {
    "static_dir": "ui",
    "entry": "index.html"
  }
}`)

	db := openTestDB(t)
	pm := &ProcessManager{}
	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, db, pm)

	req := httptest.NewRequest(http.MethodGet, "/api/plugins", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/plugins status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	catalogBody := rec.Body.String()

	var catalog struct {
		Runtime PluginRuntimeCapabilities `json:"runtime"`
		Plugins []struct {
			ID string `json:"id"`
		} `json:"plugins"`
	}
	if err := json.NewDecoder(strings.NewReader(catalogBody)).Decode(&catalog); err != nil {
		t.Fatalf("decode /api/plugins: %v", err)
	}
	if len(catalog.Plugins) != 2 || catalog.Plugins[1].ID != "ui_plugin" {
		t.Fatalf("catalog plugins = %+v body=%s, want fvtap + ui_plugin", catalog.Plugins, catalogBody)
	}
	if catalog.Runtime.ExternalDataplaneAttach {
		t.Fatalf("catalog runtime = %+v, want external dataplane attach disabled", catalog.Runtime)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/plugins/ui_plugin/assets/asset.txt", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated plugin asset status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/plugins/ui_plugin/assets/asset.txt", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET plugin asset status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "plugin asset ok") {
		t.Fatalf("plugin asset body = %q, want test content", rec.Body.String())
	}
}

func TestPluginResourceAPIStoresRecordsAndMarksPending(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "data_plugin", `{
  "api_version": "v1",
  "id": "data_plugin",
  "name": "Data Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [
    {
      "id": "bindings",
      "methods": ["list", "get", "create", "update", "delete"],
      "runtime_update": "manual",
      "max_records": 4,
      "max_record_bytes": 2048,
      "secret_fields": ["password"]
    },
    {
      "id": "readonly",
      "methods": ["list"]
    }
  ],
  "actions": [
    {
      "id": "apply",
      "runtime_update": "none"
    }
  ]
}`)

	db := openTestDB(t)
	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, db, &ProcessManager{})

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/data_plugin/resources/bindings", strings.NewReader(`{"key":"alpha","data":{"name":"alpha","Password":"secret"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST resource status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created pluginRecordResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created record: %v", err)
	}
	if created.Key != "alpha" || created.Revision != 1 {
		t.Fatalf("created record = %+v, want key alpha revision 1", created)
	}
	if created.RuntimeStatus == nil || created.RuntimeStatus.Status != "pending" {
		t.Fatalf("created runtime status = %+v, want pending", created.RuntimeStatus)
	}
	if strings.Contains(string(created.Data), "secret") || !strings.Contains(string(created.Data), "__redacted__") {
		t.Fatalf("created data = %s, want redacted secret", created.Data)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/plugins/data_plugin/resources/bindings", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var listed pluginRecordsResponse
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode listed records: %v", err)
	}
	if len(listed.Records) != 1 || listed.Records[0].Key != "alpha" {
		t.Fatalf("listed records = %+v, want alpha", listed.Records)
	}
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "pending" || listed.RuntimeStatus.Revision != 1 {
		t.Fatalf("runtime status = %+v, want pending revision 1", listed.RuntimeStatus)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/data_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"name":"alpha2","password":"new-secret"},"enabled":false}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var updated pluginRecordResponse
	if err := json.NewDecoder(rec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated record: %v", err)
	}
	if updated.Enabled || updated.Revision != 2 {
		t.Fatalf("updated record = %+v, want disabled revision 2", updated)
	}
	if updated.RuntimeStatus == nil || updated.RuntimeStatus.Status != "pending" || updated.RuntimeStatus.Revision != 2 {
		t.Fatalf("updated runtime status = %+v, want pending revision 2", updated.RuntimeStatus)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/data_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"name":"alpha3"},"enabled":false}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT resource without secret status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	stored, err := store.GetPluginRecord(db, "data_plugin", "bindings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(data_plugin bindings/alpha) after missing secret error = %v", err)
	}
	if !strings.Contains(stored.DataJSON, `"password":"new-secret"`) {
		t.Fatalf("stored data after missing secret = %s, want preserved password", stored.DataJSON)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/data_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"name":"alpha4","password":"__redacted__"},"enabled":false}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT resource with redacted secret status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	stored, err = store.GetPluginRecord(db, "data_plugin", "bindings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(data_plugin bindings/alpha) after redacted secret error = %v", err)
	}
	if !strings.Contains(stored.DataJSON, `"password":"new-secret"`) {
		t.Fatalf("stored data after redacted secret = %s, want preserved password", stored.DataJSON)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/data_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"name":"alpha5","password":""},"enabled":false}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT resource clearing secret status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	stored, err = store.GetPluginRecord(db, "data_plugin", "bindings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(data_plugin bindings/alpha) after clear secret error = %v", err)
	}
	if !strings.Contains(stored.DataJSON, `"password":""`) || strings.Contains(stored.DataJSON, "new-secret") {
		t.Fatalf("stored data after clearing secret = %s, want explicit empty password", stored.DataJSON)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/plugins/data_plugin/resources/readonly", strings.NewReader(`{"data":{"name":"denied"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST readonly status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/plugins/data_plugin/actions/apply", strings.NewReader(`{"payload":{"source":"test"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST action status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var actionResp pluginActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&actionResp); err != nil {
		t.Fatalf("decode action response: %v", err)
	}
	if actionResp.Status != "completed" || actionResp.RuntimeStatus == nil || actionResp.RuntimeStatus.Status != "completed" {
		t.Fatalf("action response = %+v, want completed status", actionResp)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/plugins/data_plugin/resources/bindings/alpha", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/plugins/data_plugin/resources/bindings", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after delete status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	listed = pluginRecordsResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode listed records after delete: %v", err)
	}
	if len(listed.Records) != 0 {
		t.Fatalf("listed records after delete = %+v, want empty", listed.Records)
	}
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "pending" || listed.RuntimeStatus.Revision != 6 {
		t.Fatalf("runtime status after delete = %+v, want pending revision 6", listed.RuntimeStatus)
	}
}

func TestPluginResourceAPIControlMethodsDoNotGrantHTTPWrites(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "status",
    "methods": ["list", "get"],
    "control_methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual"
  }]
}`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "status",
		RecordKey:  "last",
		DataJSON:   `{"phase":"applied"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(status/last) error = %v", err)
	}
	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, db, &ProcessManager{})

	req := httptest.NewRequest(http.MethodGet, "/api/plugins/control_plugin/resources/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET read-only resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/api/plugins/control_plugin/resources/status", body: `{"key":"spoof","data":{"phase":"spoofed"}}`},
		{method: http.MethodPut, path: "/api/plugins/control_plugin/resources/status/last", body: `{"data":{"phase":"spoofed"}}`},
		{method: http.MethodDelete, path: "/api/plugins/control_plugin/resources/status/last"},
	} {
		req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer test-token")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want %d: %s", tc.method, tc.path, rec.Code, http.StatusForbidden, rec.Body.String())
		}
	}

	record, err := store.GetPluginRecord(db, "control_plugin", "status", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(status/last) error = %v", err)
	}
	if record.DataJSON != `{"phase":"applied"}` {
		t.Fatalf("status/last data = %s, want unchanged applied state", record.DataJSON)
	}
}

func TestPluginResourceAPIListPaginatesRecords(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "data_plugin", `{
  "api_version": "v1",
  "id": "data_plugin",
  "name": "Data Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "bindings",
    "methods": ["list"],
    "max_records": 16
  }]
}`)

	db := openTestDB(t)
	for _, key := range []string{"alpha", "beta", "gamma"} {
		if _, err := store.AddPluginRecord(db, &store.PluginRecord{
			PluginID:   "data_plugin",
			ResourceID: "bindings",
			RecordKey:  key,
			DataJSON:   fmt.Sprintf(`{"name":%q}`, key),
			Enabled:    true,
		}); err != nil {
			t.Fatalf("AddPluginRecord(%s) error = %v", key, err)
		}
	}
	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, db, &ProcessManager{})

	req := httptest.NewRequest(http.MethodGet, "/api/plugins/data_plugin/resources/bindings?limit=2&offset=1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET paged resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var listed pluginRecordsResponse
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode paged records: %v", err)
	}
	if listed.Total != 3 || listed.Limit != 2 || listed.Offset != 1 || listed.HasMore {
		t.Fatalf("paged metadata = total:%d limit:%d offset:%d has_more:%v, want 3/2/1/false", listed.Total, listed.Limit, listed.Offset, listed.HasMore)
	}
	if len(listed.Records) != 2 || listed.Records[0].Key != "beta" || listed.Records[1].Key != "gamma" {
		t.Fatalf("paged records = %+v, want beta,gamma", listed.Records)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/plugins/data_plugin/resources/bindings?limit=1&offset=0", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET first page status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	listed = pluginRecordsResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode first page records: %v", err)
	}
	if !listed.HasMore || listed.Total != 3 || len(listed.Records) != 1 || listed.Records[0].Key != "alpha" {
		t.Fatalf("first page = %+v, want alpha with has_more", listed)
	}

	for _, path := range []string{
		"/api/plugins/data_plugin/resources/bindings?limit=5001",
		"/api/plugins/data_plugin/resources/bindings?offset=-1",
	} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s status = %d, want %d: %s", path, rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	}
}

func TestPluginResourceAPIEnforcesManifestLimits(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "limited_plugin", `{
  "api_version": "v1",
  "id": "limited_plugin",
  "name": "Limited Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "bindings",
    "methods": ["list", "create"],
    "max_records": 1,
    "max_record_bytes": 32
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "none",
    "max_payload_bytes": 16
	}]
}`)

	db := openTestDB(t)
	cfg := &Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}
	pm := &ProcessManager{db: db, cfg: cfg}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/limited_plugin/resources/bindings", strings.NewReader("{\"key\":\"alpha\",\"data\":{\n        \"name\"        :        \"alpha\"\n      }}"))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST first record status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created pluginRecordResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode first limited record: %v", err)
	}
	if string(created.Data) != `{"name":"alpha"}` {
		t.Fatalf("first limited record data = %s, want canonical compact JSON", created.Data)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/plugins/limited_plugin/resources/bindings", strings.NewReader(`{"key":"beta","data":{"name":"beta"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST over max_records status = %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/plugins/limited_plugin/resources/bindings", strings.NewReader(`{"key":"gamma","data":{"name":"this payload is too large for the resource"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST over max_record_bytes status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/plugins/limited_plugin/actions/apply", strings.NewReader(`{"payload":{"message":"this payload is too large"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST over action max_payload_bytes status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestPluginDataAPIRejectsUnavailableStore(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "data_plugin", `{
  "api_version": "v1",
  "id": "data_plugin",
  "name": "Data Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "bindings",
    "methods": ["list"]
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "none"
  }]
}`)

	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, nil, &ProcessManager{})

	req := httptest.NewRequest(http.MethodGet, "/api/plugins/data_plugin/resources/bindings", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET resource with nil db status = %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/plugins/data_plugin/actions/apply", strings.NewReader(`{"payload":{}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST action with nil db status = %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestPluginRuntimeApplyStatusPreservesAppliedRevision(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "apply_plugin", `{
  "api_version": "v1",
  "id": "apply_plugin",
  "name": "Apply Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "bindings",
    "methods": ["list", "create", "update"],
    "runtime_update": "runtime_apply",
    "max_records": 4,
    "max_record_bytes": 2048
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }]
}`)

	db := openTestDB(t)
	applyRuntime := &pluginRuntimeApplyTestRuntime{}
	cfg := &Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}
	pm := &ProcessManager{db: db, cfg: cfg, kernelRuntime: applyRuntime}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/apply_plugin/resources/bindings", strings.NewReader(`{"key":"alpha","data":{"name":"alpha"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST runtime_apply resource status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if len(applyRuntime.resourceCalls) != 1 {
		t.Fatalf("resource apply calls = %d, want 1", len(applyRuntime.resourceCalls))
	}
	if got := applyRuntime.resourceCalls[0]; len(got.records) != 1 || got.records[0].Key != "alpha" || !strings.Contains(string(got.records[0].Data), "alpha") {
		t.Fatalf("resource apply records = %+v, want alpha payload", got.records)
	}

	listed := getPluginRecordsForTest(t, handler, "/api/plugins/apply_plugin/resources/bindings")
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "applied" || listed.RuntimeStatus.Revision != 1 || listed.RuntimeStatus.AppliedRevision != 1 {
		t.Fatalf("runtime status after successful apply = %+v, want applied revision 1", listed.RuntimeStatus)
	}

	applyRuntime.resourceErr = fmt.Errorf("runtime map update failed")
	req = httptest.NewRequest(http.MethodPut, "/api/plugins/apply_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"name":"alpha2","z":2,"a":1}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT runtime_apply resource status = %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	var failedApply pluginRecordResponse
	if err := json.NewDecoder(rec.Body).Decode(&failedApply); err != nil {
		t.Fatalf("decode failed runtime apply response: %v", err)
	}
	if failedApply.RuntimeError == "" || !strings.Contains(failedApply.RuntimeError, "runtime map update failed") {
		t.Fatalf("failed runtime apply response = %+v, want runtime_error", failedApply)
	}
	if failedApply.RuntimeStatus == nil || failedApply.RuntimeStatus.Status != "error" {
		t.Fatalf("failed runtime apply status = %+v, want error", failedApply.RuntimeStatus)
	}

	listed = getPluginRecordsForTest(t, handler, "/api/plugins/apply_plugin/resources/bindings")
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "error" || listed.RuntimeStatus.Revision != 2 || listed.RuntimeStatus.AppliedRevision != 1 {
		t.Fatalf("runtime status after failed apply = %+v, want error revision 2 with applied revision 1", listed.RuntimeStatus)
	}
	if !strings.Contains(listed.RuntimeStatus.LastError, "runtime map update failed") {
		t.Fatalf("runtime status last_error = %q, want apply failure", listed.RuntimeStatus.LastError)
	}

	applyRuntime.resourceErr = nil
	req = httptest.NewRequest(http.MethodPut, "/api/plugins/apply_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"name":"alpha2","z":2,"a":1}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT retry same runtime_apply resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(applyRuntime.resourceCalls) != 3 {
		t.Fatalf("resource apply calls after retry = %d, want 3", len(applyRuntime.resourceCalls))
	}
	listed = getPluginRecordsForTest(t, handler, "/api/plugins/apply_plugin/resources/bindings")
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "applied" || listed.RuntimeStatus.Revision != 3 || listed.RuntimeStatus.AppliedRevision != 3 {
		t.Fatalf("runtime status after retry = %+v, want applied revision 3", listed.RuntimeStatus)
	}
	if len(listed.Records) != 1 || listed.Records[0].Revision != 3 {
		t.Fatalf("records after retry = %+v, want alpha revision 3", listed.Records)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/apply_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"z":2,"a":1,"name":"alpha2"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT unchanged runtime_apply resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(applyRuntime.resourceCalls) != 3 {
		t.Fatalf("resource apply calls after unchanged PUT = %d, want still 3", len(applyRuntime.resourceCalls))
	}
	listed = getPluginRecordsForTest(t, handler, "/api/plugins/apply_plugin/resources/bindings")
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "applied" || listed.RuntimeStatus.Revision != 3 || listed.RuntimeStatus.AppliedRevision != 3 {
		t.Fatalf("runtime status after unchanged PUT = %+v, want unchanged applied revision 3", listed.RuntimeStatus)
	}
	if len(listed.Records) != 1 || listed.Records[0].Revision != 3 {
		t.Fatalf("records after unchanged PUT = %+v, want alpha revision 3", listed.Records)
	}

	if err := store.DeletePluginRuntimeStatus(db, "apply_plugin", "resource", "bindings"); err != nil {
		t.Fatalf("DeletePluginRuntimeStatus(apply_plugin bindings) error = %v", err)
	}
	req = httptest.NewRequest(http.MethodPut, "/api/plugins/apply_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"a":1,"name":"alpha2","z":2}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT unchanged resource with missing runtime status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(applyRuntime.resourceCalls) != 4 {
		t.Fatalf("resource apply calls after missing status PUT = %d, want 4", len(applyRuntime.resourceCalls))
	}
	listed = getPluginRecordsForTest(t, handler, "/api/plugins/apply_plugin/resources/bindings")
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "applied" || listed.RuntimeStatus.Revision != 1 || listed.RuntimeStatus.AppliedRevision != 1 {
		t.Fatalf("runtime status after missing status PUT = %+v, want recreated applied status revision 1", listed.RuntimeStatus)
	}
	if len(listed.Records) != 1 || listed.Records[0].Revision != 4 {
		t.Fatalf("records after missing status PUT = %+v, want alpha revision 4", listed.Records)
	}
}

func TestPluginResourceAPIPluginReconcileReportsRuntimeError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile",
    "max_records": 4,
    "max_record_bytes": 2048
  }]
}`)

	db := openTestDB(t)
	cfg := &Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}
	pm := &ProcessManager{
		db:            db,
		cfg:           cfg,
		pluginRuntime: pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{"control_plugin": pluginRuntimeErrorState("attach failed")}}},
	}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/control_plugin/resources/hook_bindings", strings.NewReader(`{"key":"forward","data":{"hook_id":"forward","interfaces":["eth0"]}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST plugin_reconcile resource status = %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	var failed pluginRecordResponse
	if err := json.NewDecoder(rec.Body).Decode(&failed); err != nil {
		t.Fatalf("decode failed plugin_reconcile resource response: %v", err)
	}
	if failed.Error == "" || failed.RuntimeError == "" || !strings.Contains(failed.RuntimeError, "attach failed") {
		t.Fatalf("failed plugin_reconcile resource response = %+v, want error/runtime_error", failed)
	}
	if failed.RuntimeStatus == nil || failed.RuntimeStatus.Status != "error" || !strings.Contains(failed.RuntimeStatus.LastError, "attach failed") {
		t.Fatalf("failed plugin_reconcile resource runtime status = %+v, want error attach failed", failed.RuntimeStatus)
	}

	listed := getPluginRecordsForTest(t, handler, "/api/plugins/control_plugin/resources/hook_bindings")
	if len(listed.Records) != 1 || listed.Records[0].Key != "forward" {
		t.Fatalf("records after failed plugin_reconcile = %+v, want persisted forward record", listed.Records)
	}
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "error" || listed.RuntimeStatus.AppliedRevision == listed.RuntimeStatus.Revision {
		t.Fatalf("listed plugin_reconcile runtime status = %+v, want unapplied error", listed.RuntimeStatus)
	}

	pm.pluginRuntime = pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{}}
	req = httptest.NewRequest(http.MethodPut, "/api/plugins/control_plugin/resources/hook_bindings/forward", strings.NewReader(`{"data":{"hook_id":"forward","interfaces":["eth0","eth1"]}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT recovered plugin_reconcile resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var recovered pluginRecordResponse
	if err := json.NewDecoder(rec.Body).Decode(&recovered); err != nil {
		t.Fatalf("decode recovered plugin_reconcile resource response: %v", err)
	}
	if recovered.RuntimeError != "" || recovered.Error != "" || recovered.RuntimeStatus == nil || recovered.RuntimeStatus.Status != "applied" {
		t.Fatalf("recovered plugin_reconcile resource response = %+v, want applied without error", recovered)
	}
}

func TestPluginStateAPIDisablesControlSurfaceAndRuntime(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual"
  }],
  "ui": {
    "static_dir": "ui",
    "entry": "index.html"
  }
}`)
	writeTestPlugin(t, dir, "lifecycle_plugin", `{
  "api_version": "v1",
  "id": "lifecycle_plugin",
  "name": "Lifecycle Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["kv", "timer", "worker"]
  }
}`)
	writePluginControlScript(t, dir, "lifecycle_plugin", `
exports.onReconcile = function () {
  timer.setTimeout('disable_leak', 5000, {});
  worker.call('bg', 'onWorker', {});
};
exports.onWorker = function () {
  return {ok: true};
};
exports.onTimer = function () {
  kv.set('disable_timer_fired', {value: true});
};
`)

	db := openTestDB(t)
	cfg := &Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}
	pm := &ProcessManager{db: db, cfg: cfg}
	rt := newPluginControlRuntime(db, cfg, pm).(*gojaPluginControlRuntime)
	pm.pluginControlRuntime = rt
	defer rt.Close()
	handler := buildAPIHandler(cfg, db, pm)

	pm.reconcilePluginsForRuntime()
	if !pluginControlVMExistsForTest(rt, "control_plugin") {
		t.Fatal("control VM missing after initial reconcile")
	}
	if !pluginControlVMExistsForTest(rt, "lifecycle_plugin") {
		t.Fatal("lifecycle control VM missing after initial reconcile")
	}
	if timers := rt.pluginTimerList("lifecycle_plugin"); len(timers) != 1 || timers[0]["name"] != "disable_leak" {
		t.Fatalf("lifecycle timers after initial reconcile = %+v, want disable_leak", timers)
	}
	if workers := rt.pluginWorkerList("lifecycle_plugin"); len(workers) != 1 || workers[0]["name"] != "bg" {
		t.Fatalf("lifecycle workers after initial reconcile = %+v, want bg worker", workers)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/plugins/control_plugin/state", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable plugin status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	type pluginStateTestResponse struct {
		PluginID string `json:"plugin_id"`
		Enabled  bool   `json:"enabled"`
		Plugin   struct {
			Enabled       bool               `json:"enabled"`
			Status        string             `json:"status"`
			Runtime       PluginRuntimeState `json:"runtime"`
			Resources     []PluginResource   `json:"resources"`
			UI            *PluginUI          `json:"ui"`
			AssetBasePath string             `json:"asset_base_path"`
		} `json:"plugin"`
	}
	var disabled pluginStateTestResponse
	if err := json.NewDecoder(rec.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode disabled plugin state: %v", err)
	}
	if disabled.Enabled || disabled.Plugin.Enabled || disabled.Plugin.Status != pluginStatusDisabled || disabled.Plugin.Runtime.Mode != pluginRuntimeModeDisabled {
		t.Fatalf("disabled plugin response = %+v, want disabled runtime", disabled)
	}
	if len(disabled.Plugin.Resources) != 0 || disabled.Plugin.UI != nil || disabled.Plugin.AssetBasePath != "" {
		t.Fatalf("disabled plugin surface leaked: resources=%+v ui=%+v asset=%q", disabled.Plugin.Resources, disabled.Plugin.UI, disabled.Plugin.AssetBasePath)
	}
	if pluginControlVMExistsForTest(rt, "control_plugin") {
		t.Fatal("control VM still present after plugin disable")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/plugins/control_plugin/resources/settings", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled plugin resource status = %d, want 404: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/control_plugin/state", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable plugin status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var enabled pluginStateTestResponse
	if err := json.NewDecoder(rec.Body).Decode(&enabled); err != nil {
		t.Fatalf("decode enabled plugin state: %v", err)
	}
	if !enabled.Enabled || !enabled.Plugin.Enabled || enabled.Plugin.Status != pluginStatusActive || len(enabled.Plugin.Resources) != 1 || enabled.Plugin.UI == nil {
		t.Fatalf("enabled plugin response = %+v, want active surface restored", enabled)
	}
	if !pluginControlVMExistsForTest(rt, "control_plugin") {
		t.Fatal("control VM missing after plugin re-enable")
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/lifecycle_plugin/state", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable lifecycle plugin status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var lifecycleDisabled pluginStateTestResponse
	if err := json.NewDecoder(rec.Body).Decode(&lifecycleDisabled); err != nil {
		t.Fatalf("decode disabled lifecycle plugin state: %v", err)
	}
	if lifecycleDisabled.Enabled || lifecycleDisabled.Plugin.Status != pluginStatusDisabled || lifecycleDisabled.Plugin.Runtime.Mode != pluginRuntimeModeDisabled {
		t.Fatalf("disabled lifecycle plugin response = %+v, want disabled runtime", lifecycleDisabled)
	}
	if pluginControlVMExistsForTest(rt, "lifecycle_plugin") {
		t.Fatal("lifecycle control VM still present after plugin disable")
	}
	if timers := rt.pluginTimerList("lifecycle_plugin"); len(timers) != 0 {
		t.Fatalf("lifecycle timers after disable = %+v, want none", timers)
	}
	if workers := rt.pluginWorkerList("lifecycle_plugin"); len(workers) != 0 {
		t.Fatalf("lifecycle workers after disable = %+v, want none", workers)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/plugins/lifecycle_plugin/state", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable lifecycle plugin status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !pluginControlVMExistsForTest(rt, "lifecycle_plugin") {
		t.Fatal("lifecycle control VM missing after plugin re-enable")
	}
	if timers := rt.pluginTimerList("lifecycle_plugin"); len(timers) != 1 || timers[0]["name"] != "disable_leak" {
		t.Fatalf("lifecycle timers after re-enable = %+v, want disable_leak", timers)
	}
	if workers := rt.pluginWorkerList("lifecycle_plugin"); len(workers) != 1 || workers[0]["name"] != "bg" {
		t.Fatalf("lifecycle workers after re-enable = %+v, want bg worker", workers)
	}
}

func TestPluginCatalogFingerprintDetectsPluginFileChanges(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{PluginsDir: dir}

	initial, err := buildPluginCatalogFingerprint(cfg)
	if err != nil {
		t.Fatalf("buildPluginCatalogFingerprint(initial) error = %v", err)
	}
	writeTestPlugin(t, dir, "hot_plugin", `{
  "api_version": "v1",
  "id": "hot_plugin",
  "name": "Hot Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js"
  }
}`)
	added, err := buildPluginCatalogFingerprint(cfg)
	if err != nil {
		t.Fatalf("buildPluginCatalogFingerprint(added) error = %v", err)
	}
	if added == initial {
		t.Fatal("plugin catalog fingerprint did not change after adding plugin")
	}

	controlPath := filepath.Join(dir, "hot_plugin", "control.js")
	if err := os.WriteFile(controlPath, []byte("exports.onReconcile = function () { return 'changed'; };\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(control.js) error = %v", err)
	}
	modified, err := buildPluginCatalogFingerprint(cfg)
	if err != nil {
		t.Fatalf("buildPluginCatalogFingerprint(modified) error = %v", err)
	}
	if modified == added {
		t.Fatal("plugin catalog fingerprint did not change after modifying plugin control script")
	}

	if err := os.RemoveAll(filepath.Join(dir, "hot_plugin")); err != nil {
		t.Fatalf("RemoveAll(hot_plugin) error = %v", err)
	}
	removed, err := buildPluginCatalogFingerprint(cfg)
	if err != nil {
		t.Fatalf("buildPluginCatalogFingerprint(removed) error = %v", err)
	}
	if removed == modified {
		t.Fatal("plugin catalog fingerprint did not change after removing plugin")
	}
}

func TestPluginCatalogFingerprintDetectsContentChangesWithPreservedMetadata(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{PluginsDir: dir}
	writeTestPlugin(t, dir, "hot_plugin", `{
  "api_version": "v1",
  "id": "hot_plugin",
  "name": "Hot Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js"
  }
}`)
	controlPath := filepath.Join(dir, "hot_plugin", "control.js")
	first := []byte("exports.version = 'one';\n")
	second := []byte("exports.version = 'two';\n")
	if len(first) != len(second) {
		t.Fatalf("test fixture size mismatch: %d != %d", len(first), len(second))
	}
	fixedTime := time.Unix(1700000000, 123456789)
	if err := os.WriteFile(controlPath, first, 0o644); err != nil {
		t.Fatalf("WriteFile(control.js first) error = %v", err)
	}
	if err := os.Chtimes(controlPath, fixedTime, fixedTime); err != nil {
		t.Fatalf("Chtimes(control.js first) error = %v", err)
	}
	before, err := buildPluginCatalogFingerprint(cfg)
	if err != nil {
		t.Fatalf("buildPluginCatalogFingerprint(before) error = %v", err)
	}

	if err := os.WriteFile(controlPath, second, 0o644); err != nil {
		t.Fatalf("WriteFile(control.js second) error = %v", err)
	}
	if err := os.Chtimes(controlPath, fixedTime, fixedTime); err != nil {
		t.Fatalf("Chtimes(control.js second) error = %v", err)
	}
	after, err := buildPluginCatalogFingerprint(cfg)
	if err != nil {
		t.Fatalf("buildPluginCatalogFingerprint(after) error = %v", err)
	}
	if after == before {
		t.Fatal("plugin catalog fingerprint did not change after same-size content change with preserved mtime")
	}
}

func TestPluginCatalogDriftReconcilesRuntimeAndQueuesRedistribute(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{
		db:               db,
		cfg:              cfg,
		redistributeWake: make(chan struct{}, 1),
	}
	rt := newPluginControlRuntime(db, cfg, pm).(*gojaPluginControlRuntime)
	pm.pluginControlRuntime = rt
	t.Cleanup(func() { _ = rt.Close() })

	pm.refreshPluginCatalogFingerprint()
	status := pm.snapshotPluginCatalogHotReloadStatus()
	if status == nil || status.LastCheckAt == "" || status.LastCheckResult != pluginCatalogHotReloadResultSuccess {
		t.Fatalf("initial hot reload status = %+v, want successful check", status)
	}
	if pm.detectPluginCatalogDrift() {
		t.Fatal("detectPluginCatalogDrift() = true before plugin directory changes")
	}
	status = pm.snapshotPluginCatalogHotReloadStatus()
	if status == nil || status.LastCheckResult != pluginCatalogHotReloadResultUnchanged || status.LastCheckError != "" {
		t.Fatalf("unchanged hot reload status = %+v, want unchanged without error", status)
	}

	writeTestPlugin(t, dir, "hot_plugin", `{
  "api_version": "v1",
  "id": "hot_plugin",
  "name": "Hot Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js"
  }
}`)
	writePluginControlScript(t, dir, "hot_plugin", `
exports.onReconcile = function () {};
`)

	if !pm.detectPluginCatalogDrift() {
		t.Fatal("detectPluginCatalogDrift() = false after plugin directory changes")
	}
	if !pluginControlVMExistsForTest(rt, "hot_plugin") {
		t.Fatal("hot_plugin control VM missing after catalog drift reconcile")
	}
	pm.mu.Lock()
	redistributePending := pm.redistributePending
	pm.mu.Unlock()
	if !redistributePending {
		t.Fatal("redistributePending = false, want queued redistribute after plugin catalog drift")
	}
	status = pm.snapshotPluginCatalogHotReloadStatus()
	if status == nil || status.LastReloadAt == "" || status.LastReloadSource != pluginCatalogHotReloadSourceAuto || status.LastReloadResult != pluginCatalogHotReloadResultSuccess {
		t.Fatalf("changed hot reload status = %+v, want auto reload success", status)
	}
	if status.CatalogFingerprint == "" || status.FingerprintShortHash == "" || !strings.HasPrefix(status.CatalogFingerprint, status.FingerprintShortHash) {
		t.Fatalf("hot reload fingerprint fields = %+v, want full and short hash", status)
	}
	catalog := pm.pluginCatalogWithConfig(cfg)
	if catalog.HotReload == nil || catalog.HotReload.LastReloadSource != pluginCatalogHotReloadSourceAuto {
		t.Fatalf("catalog hot reload status = %+v, want exposed auto reload status", catalog.HotReload)
	}
}

func TestPluginActionRuntimeApplyReportsError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "apply_plugin", `{
  "api_version": "v1",
  "id": "apply_plugin",
  "name": "Apply Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply",
    "max_payload_bytes": 1024
  }]
}`)

	db := openTestDB(t)
	applyRuntime := &pluginRuntimeApplyTestRuntime{actionErr: fmt.Errorf("action apply failed")}
	cfg := &Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}
	pm := &ProcessManager{db: db, cfg: cfg, kernelRuntime: applyRuntime}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/apply_plugin/actions/apply", strings.NewReader(`{"payload":{"source":"test"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST runtime_apply action status = %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	var failed pluginActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&failed); err != nil {
		t.Fatalf("decode failed action response: %v", err)
	}
	if failed.Error == "" || failed.RuntimeError == "" || !strings.Contains(failed.RuntimeError, "action apply failed") {
		t.Fatalf("failed action response = %+v, want error/runtime_error", failed)
	}
	if failed.RuntimeStatus == nil || failed.RuntimeStatus.Status != "error" || !strings.Contains(failed.RuntimeStatus.LastError, "action apply failed") {
		t.Fatalf("failed action runtime status = %+v, want error status", failed.RuntimeStatus)
	}
	if len(applyRuntime.actionCalls) != 1 || !strings.Contains(string(applyRuntime.actionCalls[0].payload), "test") {
		t.Fatalf("action apply calls = %+v, want one payload call", applyRuntime.actionCalls)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "apply_plugin", "action", "apply")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil() error = %v", err)
	}
	if status == nil || status.Status != "error" || status.Revision != 1 || !strings.Contains(status.LastError, "action apply failed") {
		t.Fatalf("action runtime status = %+v, want error revision 1", status)
	}
}

func TestApplyPluginActionRuntimeUpdateRuntimeApplyMarksRuntimeError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "apply_plugin", `{
  "api_version": "v1",
  "id": "apply_plugin",
  "name": "Apply Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply",
    "max_payload_bytes": 1024
  }]
}`)

	db := openTestDB(t)
	applyRuntime := &pluginRuntimeApplyTestRuntime{actionErr: fmt.Errorf("action apply failed")}
	pm := &ProcessManager{kernelRuntime: applyRuntime}
	cfg := &Config{PluginsDir: dir}
	plugin := loadTestPluginByID(t, cfg, "apply_plugin")
	action := pluginActionByIDForTest(t, plugin, "apply")

	err := applyPluginActionRuntimeUpdate(db, pm, plugin, action, json.RawMessage(`{"source":"direct"}`))
	if err == nil || !strings.Contains(err.Error(), "action apply failed") {
		t.Fatalf("applyPluginActionRuntimeUpdate() error = %v, want action apply failed", err)
	}
	if len(applyRuntime.actionCalls) != 1 || !strings.Contains(string(applyRuntime.actionCalls[0].payload), "direct") {
		t.Fatalf("action apply calls = %+v, want one direct payload call", applyRuntime.actionCalls)
	}
	status, statusErr := store.PluginRuntimeStatusOrNil(db, "apply_plugin", "action", "apply")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(apply action) error = %v", statusErr)
	}
	if status == nil || status.Status != "error" || status.AppliedRevision == status.Revision || !strings.Contains(status.LastError, "action apply failed") {
		t.Fatalf("action runtime status after direct failed apply = %+v, want error without applied overwrite", status)
	}
}

func TestPluginActionAPIPluginReconcileReportsRuntimeError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "reload_hooks",
    "runtime_update": "plugin_reconcile",
    "max_payload_bytes": 1024
  }]
}`)

	db := openTestDB(t)
	cfg := &Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}
	pm := &ProcessManager{
		db:            db,
		cfg:           cfg,
		pluginRuntime: pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{"control_plugin": pluginRuntimeErrorState("attach failed")}}},
	}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/control_plugin/actions/reload_hooks", strings.NewReader(`{"payload":{"reason":"test"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST plugin_reconcile action status = %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	var failed pluginActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&failed); err != nil {
		t.Fatalf("decode failed plugin_reconcile action response: %v", err)
	}
	if failed.Error == "" || failed.RuntimeError == "" || !strings.Contains(failed.RuntimeError, "attach failed") {
		t.Fatalf("failed plugin_reconcile action response = %+v, want error/runtime_error", failed)
	}
	if failed.RuntimeStatus == nil || failed.RuntimeStatus.Status != "error" || !strings.Contains(failed.RuntimeStatus.LastError, "attach failed") {
		t.Fatalf("failed plugin_reconcile action runtime status = %+v, want error attach failed", failed.RuntimeStatus)
	}

	pm.pluginRuntime = pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{}}
	req = httptest.NewRequest(http.MethodPost, "/api/plugins/control_plugin/actions/reload_hooks", strings.NewReader(`{"payload":{"reason":"retry"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST recovered plugin_reconcile action status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var recovered pluginActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&recovered); err != nil {
		t.Fatalf("decode recovered plugin_reconcile action response: %v", err)
	}
	if recovered.RuntimeError != "" || recovered.Error != "" || recovered.RuntimeStatus == nil || recovered.RuntimeStatus.Status != "applied" {
		t.Fatalf("recovered plugin_reconcile action response = %+v, want applied without error", recovered)
	}
}

func TestPluginGojaControlActionPersistsKV(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply",
    "max_payload_bytes": 1024
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function (ctx) {
  kv.set('last_action', {
    action: ctx.action.id,
    source: ctx.payload.source
  });
};
`)

	db := openTestDB(t)
	cfg := &Config{WebBind: "127.0.0.1", WebPort: 8080, WebToken: "test-token", PluginsDir: dir}
	pm := &ProcessManager{db: db, cfg: cfg}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/control_plugin/actions/apply", strings.NewReader(`{"payload":{"source":"test"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST goja action status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "last_action")
	if err != nil {
		t.Fatalf("GetPluginRecord(last_action) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"source":"test"`) || !strings.Contains(record.DataJSON, `"action":"apply"`) {
		t.Fatalf("last_action data = %s, want action/source payload", record.DataJSON)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "action", "apply")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil() error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("action status = %+v, want applied revision 1", status)
	}
}

func TestPluginGojaControlKeepsPersistentStateAcrossActions(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
var topLevelRuns = 0;
topLevelRuns++;
var actionCount = 0;
exports.onAction = function () {
  actionCount++;
  kv.set('state', {top_level_runs: topLevelRuns, action_count: actionCount});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	for i := 0; i < 2; i++ {
		if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatalf("ApplyPluginAction(%d) error = %v", i, err)
		}
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "state")
	if err != nil {
		t.Fatalf("GetPluginRecord(state) error = %v", err)
	}
	for _, want := range []string{`"top_level_runs":1`, `"action_count":2`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("state data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlRestartsPersistentVMWhenScriptChanges(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
var actionCount = 0;
exports.onAction = function () {
  actionCount++;
  kv.set('state', {version: 1, action_count: actionCount});
};
`)

	cfg := &Config{PluginsDir: dir}
	plugin := loadTestPluginByID(t, cfg, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction(version 1) error = %v", err)
	}

	writePluginControlScript(t, dir, "control_plugin", `
var actionCount = 0;
exports.onAction = function () {
  actionCount++;
  kv.set('state', {version: 2, action_count: actionCount});
};
`)
	plugin = loadTestPluginByID(t, cfg, "control_plugin")
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction(version 2) error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "state")
	if err != nil {
		t.Fatalf("GetPluginRecord(state) error = %v", err)
	}
	for _, want := range []string{`"version":2`, `"action_count":1`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("state data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlScriptChangeClearsStaleTimers(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["timer"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onReconcile = function () {
  timer.setInterval('stale_timer', 60000, {version: 1});
};
`)

	cfg := &Config{PluginsDir: dir}
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	rt.Reconcile(loadPluginCatalogWithState(cfg, db))
	if timers := rt.pluginTimerList("control_plugin"); len(timers) != 1 || timers[0]["name"] != "stale_timer" {
		t.Fatalf("timers after v1 reconcile = %+v, want stale_timer", timers)
	}

	writePluginControlScript(t, dir, "control_plugin", `
exports.onReconcile = function () {};
`)
	rt.Reconcile(loadPluginCatalogWithState(cfg, db))
	if timers := rt.pluginTimerList("control_plugin"); len(timers) != 0 {
		t.Fatalf("timers after script change = %+v, want stale timers cleared", timers)
	}
}

func TestPluginGojaWorkerKeepsPersistentStateAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "worker"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
var mainCount = 0;
var workerCount = 0;
var workerGlobalAvailable = worker && typeof worker.list === 'function';
exports.onAction = function () {
  mainCount++;
  var first = worker.call('bg', 'onWorker', {step: 1});
  var second = worker.call('bg', 'onWorker', {step: 2});
  kv.set('worker_result', {
    main_count: mainCount,
    first_count: first.count,
    second_count: second.count,
    worker_name: second.worker,
    worker_total: worker.list().length
  });
};
exports.onWorker = function (ctx) {
  workerCount++;
  return {count: workerCount, worker: ctx.worker.name, step: ctx.payload.step, worker_global: workerGlobalAvailable};
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	for i := 0; i < 2; i++ {
		if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatalf("ApplyPluginAction(%d) error = %v", i, err)
		}
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "worker_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(worker_result) error = %v", err)
	}
	for _, want := range []string{`"main_count":2`, `"first_count":3`, `"second_count":4`, `"worker_name":"bg"`, `"worker_total":1`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("worker_result data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaWorkerRejectsMissingPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  worker.call('bg', 'onWorker', {});
};
exports.onWorker = function () {
  return {};
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission worker is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want worker permission error", err)
	}
}

func TestPluginGojaWorkerRejectsOversizedPayload(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["worker"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", fmt.Sprintf(`
exports.onAction = function () {
  worker.call('bg', 'onWorker', {value: new Array(%d).join('x')});
};
exports.onWorker = function () {
  return {};
};
`, pluginControlWorkerMaxPayloadBytes+10))

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "worker.call payload exceeds") {
		t.Fatalf("ApplyPluginAction() error = %v, want worker payload limit error", err)
	}
}

func TestPluginGojaWorkerRejectsRegistrationAPIAfterInit(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "worker"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
plugin.action({id: 'apply', runtime_update: 'runtime_apply'});
exports.onAction = function () {
  worker.call('bg', 'onWorker', {});
};
exports.onWorker = function () {
  plugin.resource({id: 'late', methods: ['list']});
  return {};
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "plugin.resource is only available during plugin registration") {
		t.Fatalf("ApplyPluginAction() error = %v, want worker registration API unavailable error", err)
	}
}

func TestPluginGojaWorkerDispatchDoesNotBlockControlAction(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "net.l2", "worker"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  worker.dispatch('slow', 'onWorker', {});
  kv.set('after_dispatch', {value: true});
};
exports.onWorker = function () {
  net.l2.recv({
    interface: 'eth0',
    ethertype: '0x8863',
    timeout_ms: 1000,
    max_bytes: 64
  });
  kv.set('worker_done', {value: true});
};
`)

	cfg := &Config{PluginsDir: dir}
	plugin := loadTestPluginByID(t, cfg, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	enteredRecv := make(chan struct{}, 1)
	releaseRecv := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseRecv) })
		_ = rt.Close()
	})
	rt.l2Transport = &pluginControlL2TransportTest{
		recvFunc: func(req pluginControlL2RecvRequest) (pluginControlL2Frame, error) {
			select {
			case enteredRecv <- struct{}{}:
			default:
			}
			<-releaseRecv
			return pluginControlL2Frame{
				Interface: req.Interface,
				IfIndex:   7,
				EtherType: req.EtherType,
				DstMAC:    mustMACForTest(t, "02:00:00:00:00:01"),
				SrcMAC:    mustMACForTest(t, "02:00:00:00:00:02"),
				Payload:   []byte{0x01},
			}, nil
		},
	}

	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if _, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "after_dispatch"); err != nil {
		t.Fatalf("GetPluginRecord(after_dispatch) error = %v", err)
	}
	select {
	case <-enteredRecv:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not enter blocking recv")
	}
	releaseOnce.Do(func() { close(releaseRecv) })
	waitForPluginRecordForTest(t, db, "control_plugin", pluginControlKVResourceID, "worker_done", 2*time.Second)
}

func TestPluginGojaControlRejectsRegistrationAPIAfterInit(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
plugin.action({id: 'apply', runtime_update: 'runtime_apply'});
exports.onAction = function () {
  plugin.resource({id: 'late', methods: ['list']});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "plugin.resource is only available during plugin registration") {
		t.Fatalf("ApplyPluginAction() error = %v, want registration API unavailable error", err)
	}
}

func TestPluginGojaControlSerializesSamePluginActions(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  var current = kv.get('counter');
  var value = current && current.data && current.data.value ? Number(current.data.value) : 0;
  net.l2.recv({
    interface: 'eth0',
    ethertype: '0x8863',
    timeout_ms: 1000,
    max_bytes: 64
  });
  kv.set('counter', {value: value + 1});
};
`)

	cfg := &Config{PluginsDir: dir}
	plugin := loadTestPluginByID(t, cfg, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	enteredRecv := make(chan struct{}, 2)
	releaseRecv := make(chan struct{})
	var closeRelease sync.Once
	defer closeRelease.Do(func() { close(releaseRecv) })
	dstMAC := mustMACForTest(t, "02:00:00:00:00:01")
	srcMAC := mustMACForTest(t, "02:00:00:00:00:02")
	rt.l2Transport = &pluginControlL2TransportTest{
		recvFunc: func(req pluginControlL2RecvRequest) (pluginControlL2Frame, error) {
			enteredRecv <- struct{}{}
			<-releaseRecv
			return pluginControlL2Frame{
				Interface: req.Interface,
				IfIndex:   7,
				EtherType: req.EtherType,
				DstMAC:    dstMAC,
				SrcMAC:    srcMAC,
				Payload:   []byte{0x01},
			}, nil
		},
	}
	t.Cleanup(func() { _ = rt.Close() })

	errCh := make(chan error, 2)
	go func() {
		errCh <- rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	}()
	select {
	case <-enteredRecv:
	case err := <-errCh:
		t.Fatalf("first ApplyPluginAction returned before blocking recv: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("first ApplyPluginAction did not enter blocking recv")
	}
	go func() {
		errCh <- rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	}()
	time.Sleep(50 * time.Millisecond)
	closeRelease.Do(func() { close(releaseRecv) })

	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("ApplyPluginAction(%d) error = %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("ApplyPluginAction(%d) timed out", i)
		}
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "counter")
	if err != nil {
		t.Fatalf("GetPluginRecord(counter) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"value":2`) {
		t.Fatalf("counter = %s, want serialized value 2", record.DataJSON)
	}
}

func TestPluginGojaControlKVSetHonorsMaxRecordBytes(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  kv.set('too_large', {value: new Array(70000).join('x')});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "kv.set: value exceeds") {
		t.Fatalf("ApplyPluginAction() error = %v, want kv max bytes error", err)
	}
	if _, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "too_large"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(kv too_large) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlKVSetHonorsRecordLimit(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  kv.set('overflow', {value: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	for i := 0; i < pluginControlMaxKVRecords; i++ {
		if _, err := store.AddPluginRecord(db, &store.PluginRecord{
			PluginID:   "control_plugin",
			ResourceID: pluginControlKVResourceID,
			RecordKey:  fmt.Sprintf("k%04d", i),
			DataJSON:   `{"value":true}`,
			Enabled:    true,
		}); err != nil {
			t.Fatalf("AddPluginRecord(kv %d) error = %v", i, err)
		}
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "kv.set: resource record limit reached") {
		t.Fatalf("ApplyPluginAction() error = %v, want kv record limit error", err)
	}
	if _, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "overflow"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(kv overflow) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlResourceApplyReceivesRecords(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "create", "update"],
    "runtime_update": "runtime_apply",
    "max_records": 4,
    "max_record_bytes": 2048
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onResourceApply = function (ctx) {
  kv.set('last_resource', {
    resource: ctx.resource.id,
    count: ctx.records.length,
    first: ctx.records[0].data.name
  });
};
`)

	db := openTestDB(t)
	cfg := &Config{WebBind: "127.0.0.1", WebPort: 8080, WebToken: "test-token", PluginsDir: dir}
	pm := &ProcessManager{db: db, cfg: cfg}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/control_plugin/resources/settings", strings.NewReader(`{"key":"alpha","data":{"name":"alpha"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST goja resource status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "last_resource")
	if err != nil {
		t.Fatalf("GetPluginRecord(last_resource) error = %v", err)
	}
	for _, want := range []string{`"resource":"settings"`, `"count":1`, `"first":"alpha"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("last_resource data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlReconcileAppliesRuntimeApplyResources(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "get", "create", "update"],
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onResourceApply = function (ctx) {
  kv.set('reconciled_resource', {
    resource: ctx.resource.id,
    count: ctx.records.length,
    first: ctx.records[0].data.name
  });
};
`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "settings",
		RecordKey:  "alpha",
		DataJSON:   `{"name":"alpha"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(settings/alpha) error = %v", err)
	}
	if err := store.MarkPluginRuntimeError(db, "control_plugin", "resource", "settings", "previous runtime failure"); err != nil {
		t.Fatalf("MarkPluginRuntimeError(settings) error = %v", err)
	}

	cfg := &Config{PluginsDir: dir}
	rt := newPluginControlRuntime(db, cfg, nil)
	t.Cleanup(func() { _ = rt.Close() })
	catalog := loadPluginCatalog(cfg)
	snapshot := rt.Reconcile(catalog)
	if state, ok := snapshot.stateFor("control_plugin"); !ok || state.Error != "" {
		t.Fatalf("control_plugin reconcile state = %+v ok=%t, want no error", state, ok)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "reconciled_resource")
	if err != nil {
		t.Fatalf("GetPluginRecord(reconciled_resource) error = %v", err)
	}
	for _, want := range []string{`"resource":"settings"`, `"count":1`, `"first":"alpha"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("reconciled_resource data = %s, want %s", record.DataJSON, want)
		}
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.LastError != "" || status.AppliedRevision != status.Revision {
		t.Fatalf("settings runtime status after reconcile = %+v, want applied with cleared error", status)
	}
}

func TestPluginGojaControlReconcileSkipsEmptyRuntimeApplyResourceWithoutStatus(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "get", "create", "update"],
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": []
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onReconcile = function () {};
`)

	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	rt := newPluginControlRuntime(db, cfg, nil)
	t.Cleanup(func() { _ = rt.Close() })
	snapshot := rt.Reconcile(loadPluginCatalog(cfg))
	if state, ok := snapshot.stateFor("control_plugin"); !ok || state.Error != "" {
		t.Fatalf("control_plugin reconcile state = %+v ok=%t, want no error for empty runtime_apply resource", state, ok)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) error = %v", err)
	}
	if status != nil {
		t.Fatalf("settings runtime status = %+v, want nil for untouched empty resource", status)
	}
}

func TestPluginGojaControlResourceSetHonorsMaxRecordBytes(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update"],
    "runtime_update": "none",
    "max_records": 4,
    "max_record_bytes": 16
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.set('settings', 'alpha', {value: 'this payload is too large'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "resources.set: data exceeds resource max_record_bytes") {
		t.Fatalf("ApplyPluginAction() error = %v, want max_record_bytes error", err)
	}
	if _, err := store.GetPluginRecord(db, "control_plugin", "settings", "alpha"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(settings/alpha) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlResourceSetUsesControlMethods(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "status",
    "methods": ["list", "get"],
    "control_methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual"
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.set('status', 'last', {phase: 'applied'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", "status", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(status/last) error = %v", err)
	}
	if record.DataJSON != `{"phase":"applied"}` {
		t.Fatalf("status/last data = %s, want applied status", record.DataJSON)
	}
}

func TestPluginGojaControlResourceSetMarksResourcePending(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.set('settings', 'alpha', {name: 'alpha'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) error = %v", err)
	}
	if status == nil || status.Status != "pending" || status.Revision != 1 || status.LastError != "" {
		t.Fatalf("settings runtime status = %+v, want pending revision 1", status)
	}
}

func TestPluginGojaControlResourceSetNoopsUnchangedRecord(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.set('settings', 'alpha', {name: 'alpha'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("first ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(settings/alpha) error = %v", err)
	}
	if record.Revision != 1 {
		t.Fatalf("settings/alpha revision = %d, want 1", record.Revision)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("settings runtime status = %+v, want revision 1", status)
	}
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("second ApplyPluginAction() error = %v", err)
	}
	record, err = store.GetPluginRecord(db, "control_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(settings/alpha) after no-op error = %v", err)
	}
	if record.Revision != 1 {
		t.Fatalf("settings/alpha revision after no-op = %d, want 1", record.Revision)
	}
	status, err = store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) after no-op error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("settings runtime status after no-op = %+v, want revision 1", status)
	}
}

func TestPluginGojaControlResourceSetPreservesOwnSecretFields(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual",
    "secret_fields": ["password"]
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.set('settings', 'alpha', {username: 'alice2', password: '__redacted__'});
  resources.set('settings', 'beta', {username: 'bob2'});
};
`)

	db := openTestDB(t)
	for _, item := range []store.PluginRecord{
		{PluginID: "control_plugin", ResourceID: "settings", RecordKey: "alpha", DataJSON: `{"username":"alice","password":"alpha-secret"}`, Enabled: true},
		{PluginID: "control_plugin", ResourceID: "settings", RecordKey: "beta", DataJSON: `{"username":"bob","password":"beta-secret"}`, Enabled: true},
	} {
		current := item
		if _, err := store.AddPluginRecord(db, &current); err != nil {
			t.Fatalf("AddPluginRecord(settings/%s) error = %v", current.RecordKey, err)
		}
	}

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	for _, tc := range []struct {
		key      string
		password string
		username string
	}{
		{key: "alpha", password: `"password":"alpha-secret"`, username: `"username":"alice2"`},
		{key: "beta", password: `"password":"beta-secret"`, username: `"username":"bob2"`},
	} {
		record, err := store.GetPluginRecord(db, "control_plugin", "settings", tc.key)
		if err != nil {
			t.Fatalf("GetPluginRecord(settings/%s) error = %v", tc.key, err)
		}
		if !strings.Contains(record.DataJSON, tc.password) {
			t.Fatalf("settings/%s = %s, missing preserved %s", tc.key, record.DataJSON, tc.password)
		}
		if !strings.Contains(record.DataJSON, tc.username) {
			t.Fatalf("settings/%s = %s, missing updated %s", tc.key, record.DataJSON, tc.username)
		}
	}
}

func TestPluginGojaControlResourceDeleteMarksResourcePending(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "delete", "get"],
    "runtime_update": "manual"
  }],
  "actions": [{
    "id": "delete",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.delete('settings', 'alpha');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "settings",
		RecordKey:  "alpha",
		DataJSON:   `{"name":"alpha"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(settings/alpha) error = %v", err)
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if _, err := store.GetPluginRecord(db, "control_plugin", "settings", "alpha"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(settings/alpha) error = %v, want sql.ErrNoRows", err)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) error = %v", err)
	}
	if status == nil || status.Status != "pending" || status.Revision != 1 || status.LastError != "" {
		t.Fatalf("settings runtime status = %+v, want pending revision 1", status)
	}
}

func TestPluginGojaControlResourceDeleteNoopsMissingRecord(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "delete", "get"],
    "runtime_update": "manual"
  }],
  "actions": [{
    "id": "delete",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.delete('settings', 'alpha');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "settings",
		RecordKey:  "alpha",
		DataJSON:   `{"name":"alpha"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(settings/alpha) error = %v", err)
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("first ApplyPluginAction() error = %v", err)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("settings runtime status = %+v, want revision 1", status)
	}
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("second ApplyPluginAction() error = %v", err)
	}
	status, err = store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) after missing delete error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("settings runtime status after missing delete = %+v, want revision 1", status)
	}
}

func TestPluginGojaControlResourceSetApplyUsesProcessApplierWhenHandlerMissing(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "create", "update", "get"],
    "runtime_update": "runtime_apply",
    "max_records": 4,
    "max_record_bytes": 2048
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.set('settings', 'alpha', {name: 'alpha'}, true, true);
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	applier := &pluginRuntimeApplyTestRuntime{}
	pm := &ProcessManager{db: db, cfg: cfg, kernelRuntime: applier}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if len(applier.resourceCalls) != 1 {
		t.Fatalf("resource applier calls = %+v, want one resource apply", applier.resourceCalls)
	}
	call := applier.resourceCalls[0]
	if call.plugin.ID != "control_plugin" || call.resource.ID != "settings" || len(call.records) != 1 || call.records[0].Key != "alpha" {
		t.Fatalf("resource applier call = %+v, want control_plugin/settings alpha", call)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(settings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("settings runtime status = %+v, want applied revision 1", status)
	}
}

func TestPluginGojaControlResourceSetApplyRunsOwnPluginReconcile(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  resources.set('hook_bindings', 'forward', {
    hook_id: 'forward',
    interfaces: ['eth0']
  }, true, true);
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{db: db, cfg: cfg}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", "hook_bindings", "forward")
	if err != nil {
		t.Fatalf("GetPluginRecord(hook_bindings/forward) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"hook_id":"forward"`) || !strings.Contains(record.DataJSON, `"eth0"`) {
		t.Fatalf("hook_bindings/forward = %s, want forward eth0 binding", record.DataJSON)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "hook_bindings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(hook_bindings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("hook_bindings runtime status = %+v, want applied revision 1", status)
	}
}

func TestProcessManagerReconcileMarksPluginReconcileResourceApplied(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }]
}`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "hook_bindings",
		RecordKey:  "forward",
		DataJSON:   `{"hook_id":"forward","interfaces":["eth0"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings/forward) error = %v", err)
	}
	if err := store.MarkPluginRuntimeError(db, "control_plugin", "resource", "hook_bindings", "previous plugin runtime failure"); err != nil {
		t.Fatalf("MarkPluginRuntimeError(hook_bindings) error = %v", err)
	}

	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{db: db, cfg: cfg}
	pm.reconcilePluginsForRuntime()

	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "hook_bindings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(hook_bindings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.LastError != "" || status.AppliedRevision != status.Revision {
		t.Fatalf("hook_bindings runtime status after reconcile = %+v, want applied with cleared error", status)
	}
}

func TestProcessManagerPluginReconcileUsesUnifiedKernelCatalogReconcile(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }]
}`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "hook_bindings",
		RecordKey:  "forward",
		DataJSON:   `{"hook_id":"forward","interfaces":["eth0"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings/forward) error = %v", err)
	}
	if err := store.BumpPluginResourcePending(db, "control_plugin", "hook_bindings"); err != nil {
		t.Fatalf("BumpPluginResourcePending(hook_bindings) error = %v", err)
	}

	cfg := &Config{
		PluginsDir:    dir,
		DefaultEngine: ruleEngineKernel,
	}
	kernelRuntime := &pluginPipelineKernelRuntimeTest{
		kernelSupported: true,
		snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"control_plugin": {
				Mode:       pluginRuntimeModeDataplane,
				Attachable: true,
				Attached:   true,
			},
		}},
	}
	pm := &ProcessManager{
		ruleWorkers:                          make(map[int]*WorkerInfo),
		rangeWorkers:                         make(map[int]*WorkerInfo),
		db:                                   db,
		cfg:                                  cfg,
		rulePlans:                            make(map[int64]ruleDataplanePlan),
		rangePlans:                           make(map[int64]rangeDataplanePlan),
		egressNATPlans:                       make(map[int64]ruleDataplanePlan),
		dynamicEgressNATParents:              make(map[string]struct{}),
		managedNetworkInterfaces:             make(map[string]struct{}),
		ipv6AssignmentInterfaces:             make(map[string]struct{}),
		kernelRuntime:                        kernelRuntime,
		kernelRules:                          make(map[int64]bool),
		kernelRanges:                         make(map[int64]bool),
		kernelEgressNATs:                     make(map[int64]bool),
		kernelRuleEngines:                    make(map[int64]string),
		kernelRangeEngines:                   make(map[int64]string),
		kernelEgressNATEngines:               make(map[int64]string),
		kernelFlowOwners:                     make(map[uint32]kernelCandidateOwner),
		kernelRuleStats:                      make(map[int64]RuleStatsReport),
		kernelRangeStats:                     make(map[int64]RangeStatsReport),
		kernelEgressNATStats:                 make(map[int64]EgressNATStatsReport),
		kernelStatsSnapshot:                  emptyKernelRuleStatsSnapshot(),
		kernelNetlinkOwnerRetryCooldownUntil: make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState),
		kernelNetlinkOwnerRetryFailures:      make(map[kernelCandidateOwner]int),
	}

	snapshot := pm.reconcilePluginsForRuntime()
	if kernelRuntime.reconcilePluginsCalls != 0 {
		t.Fatalf("ReconcilePlugins() calls = %d, want unified kernel catalog reconcile only", kernelRuntime.reconcilePluginsCalls)
	}
	if kernelRuntime.reconcileWithCatalogCalls != 1 {
		t.Fatalf("ReconcileWithPluginCatalog() calls = %d, want 1", kernelRuntime.reconcileWithCatalogCalls)
	}
	if _, ok := snapshot.stateFor("control_plugin"); !ok {
		t.Fatalf("plugin snapshot = %+v, want control_plugin state", snapshot)
	}
	if len(kernelRuntime.lastCatalog.Plugins) == 0 {
		t.Fatal("kernel runtime did not receive plugin catalog")
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "hook_bindings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(hook_bindings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.LastError != "" || status.AppliedRevision != status.Revision {
		t.Fatalf("hook_bindings runtime status after reconcile = %+v, want applied current revision", status)
	}
}

func TestProcessManagerReconcileMarksPluginReconcileResourceError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }]
}`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "hook_bindings",
		RecordKey:  "forward",
		DataJSON:   `{"hook_id":"forward","interfaces":["eth0"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings/forward) error = %v", err)
	}
	if err := store.BumpPluginResourcePending(db, "control_plugin", "hook_bindings"); err != nil {
		t.Fatalf("BumpPluginResourcePending(hook_bindings) error = %v", err)
	}

	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{
		db:            db,
		cfg:           cfg,
		pluginRuntime: pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{"control_plugin": pluginRuntimeErrorState("attach failed")}}},
	}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	pm.reconcilePluginsForRuntime()

	status, err := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "hook_bindings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(hook_bindings) error = %v", err)
	}
	if status == nil || status.Status != "error" || !strings.Contains(status.LastError, "attach failed") {
		t.Fatalf("hook_bindings runtime status after failed reconcile = %+v, want error attach failed", status)
	}
}

func TestApplyPluginResourceRuntimeUpdatePluginReconcileReturnsRuntimeError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }]
}`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "hook_bindings",
		RecordKey:  "forward",
		DataJSON:   `{"hook_id":"forward","interfaces":["eth0"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings/forward) error = %v", err)
	}
	if err := store.BumpPluginResourcePending(db, "control_plugin", "hook_bindings"); err != nil {
		t.Fatalf("BumpPluginResourcePending(hook_bindings) error = %v", err)
	}

	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{
		db:            db,
		cfg:           cfg,
		pluginRuntime: pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{"control_plugin": pluginRuntimeErrorState("attach failed")}}},
	}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	plugin := loadTestPluginByID(t, cfg, "control_plugin")
	resource := pluginResourceByIDForTest(t, plugin, "hook_bindings")
	err := applyPluginResourceRuntimeUpdate(db, pm, plugin, resource)
	if err == nil || !strings.Contains(err.Error(), "attach failed") {
		t.Fatalf("applyPluginResourceRuntimeUpdate() error = %v, want attach failed", err)
	}

	status, statusErr := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "hook_bindings")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(hook_bindings) error = %v", statusErr)
	}
	if status == nil || status.Status != "error" || status.AppliedRevision == status.Revision || !strings.Contains(status.LastError, "attach failed") {
		t.Fatalf("hook_bindings runtime status after failed apply = %+v, want error without applied overwrite", status)
	}
}

func TestApplyPluginActionRuntimeUpdatePluginReconcileReturnsRuntimeError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "reload_hooks",
    "runtime_update": "plugin_reconcile"
  }]
}`)

	db := openTestDB(t)
	if err := store.UpsertPluginRuntimeStatus(db, store.PluginRuntimeStatus{
		PluginID:   "control_plugin",
		TargetType: "action",
		TargetID:   "reload_hooks",
		Status:     "pending",
	}); err != nil {
		t.Fatalf("UpsertPluginRuntimeStatus(reload_hooks) error = %v", err)
	}

	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{
		db:            db,
		cfg:           cfg,
		pluginRuntime: pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{"control_plugin": pluginRuntimeErrorState("attach failed")}}},
	}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	defer pm.pluginControlRuntime.Close()
	plugin := loadTestPluginByID(t, cfg, "control_plugin")
	action := pluginActionByIDForTest(t, plugin, "reload_hooks")
	err := applyPluginActionRuntimeUpdate(db, pm, plugin, action, json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "attach failed") {
		t.Fatalf("applyPluginActionRuntimeUpdate() error = %v, want attach failed", err)
	}

	status, statusErr := store.PluginRuntimeStatusOrNil(db, "control_plugin", "action", "reload_hooks")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(reload_hooks) error = %v", statusErr)
	}
	if status == nil || status.Status == "applied" || status.AppliedRevision == status.Revision {
		t.Fatalf("reload_hooks runtime status after failed apply = %+v, want not applied", status)
	}
}

func TestApplyPluginResourceRuntimeUpdatePluginReconcileRequiresProcessManager(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }]
}`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "control_plugin",
		ResourceID: "hook_bindings",
		RecordKey:  "forward",
		DataJSON:   `{"hook_id":"forward","interfaces":["eth0"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings/forward) error = %v", err)
	}
	if err := store.BumpPluginResourcePending(db, "control_plugin", "hook_bindings"); err != nil {
		t.Fatalf("BumpPluginResourcePending(hook_bindings) error = %v", err)
	}

	cfg := &Config{PluginsDir: dir}
	plugin := loadTestPluginByID(t, cfg, "control_plugin")
	resource := pluginResourceByIDForTest(t, plugin, "hook_bindings")
	err := applyPluginResourceRuntimeUpdate(db, nil, plugin, resource)
	if err == nil || !strings.Contains(err.Error(), "requires process manager") {
		t.Fatalf("applyPluginResourceRuntimeUpdate() error = %v, want requires process manager", err)
	}

	status, statusErr := store.PluginRuntimeStatusOrNil(db, "control_plugin", "resource", "hook_bindings")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(hook_bindings) error = %v", statusErr)
	}
	if status == nil || status.Status != "error" || status.AppliedRevision == status.Revision || !strings.Contains(status.LastError, "requires process manager") {
		t.Fatalf("hook_bindings runtime status after unavailable reconcile = %+v, want error without applied overwrite", status)
	}
}

func TestApplyPluginActionRuntimeUpdatePluginReconcileRequiresProcessManager(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "reload_hooks",
    "runtime_update": "plugin_reconcile"
  }]
}`)

	db := openTestDB(t)
	if err := store.UpsertPluginRuntimeStatus(db, store.PluginRuntimeStatus{
		PluginID:   "control_plugin",
		TargetType: "action",
		TargetID:   "reload_hooks",
		Status:     "pending",
	}); err != nil {
		t.Fatalf("UpsertPluginRuntimeStatus(reload_hooks) error = %v", err)
	}

	cfg := &Config{PluginsDir: dir}
	plugin := loadTestPluginByID(t, cfg, "control_plugin")
	action := pluginActionByIDForTest(t, plugin, "reload_hooks")
	err := applyPluginActionRuntimeUpdate(db, nil, plugin, action, json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "requires process manager") {
		t.Fatalf("applyPluginActionRuntimeUpdate() error = %v, want requires process manager", err)
	}

	status, statusErr := store.PluginRuntimeStatusOrNil(db, "control_plugin", "action", "reload_hooks")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(reload_hooks) error = %v", statusErr)
	}
	if status == nil || status.Status != "error" || status.AppliedRevision == status.Revision || !strings.Contains(status.LastError, "requires process manager") {
		t.Fatalf("reload_hooks runtime status after unavailable reconcile = %+v, want error without applied overwrite", status)
	}
}

func TestPluginGojaControlPluginResourceSetRequiresPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission plugin.resource is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want plugin.resource permission error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginResourceSetRequiresResourceAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "resource access target_plugin/settings method create is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want resource access error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginResourceSetRejectsDisabledTarget(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["create", "update", "get"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	if err := store.SetPluginEnabled(db, "target_plugin", false); err != nil {
		t.Fatalf("SetPluginEnabled(target_plugin false) error = %v", err)
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "plugin target_plugin is not active") {
		t.Fatalf("ApplyPluginAction() error = %v, want disabled target error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginActionCallRequiresPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "run",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.actions.call('target_plugin', 'apply', {value: 'alpha'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onAction = function () {
  kv.set('called', {value: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission plugin.action is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want plugin.action permission error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", pluginControlKVResourceID, "called"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target called) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginActionCallRequiresActionAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "run",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.action"]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.actions.call('target_plugin', 'apply', {value: 'alpha'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onAction = function () {
  kv.set('called', {value: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "action access target_plugin/apply is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want action access error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", pluginControlKVResourceID, "called"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target called) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginActionCallRejectsDisabledTarget(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "run",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.action"],
    "action_access": [{
      "plugin": "target_plugin",
      "actions": ["apply"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.actions.call('target_plugin', 'apply', {value: 'alpha'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onAction = function () {
  kv.set('called', {value: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	if err := store.SetPluginEnabled(db, "target_plugin", false); err != nil {
		t.Fatalf("SetPluginEnabled(target_plugin false) error = %v", err)
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "plugin target_plugin is not active") {
		t.Fatalf("ApplyPluginAction() error = %v, want disabled target error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", pluginControlKVResourceID, "called"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target called) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginActionCallRejectsUnknownTargetAction(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "run",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.action"],
    "action_access": [{
      "plugin": "target_plugin",
      "actions": ["missing"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.actions.call('target_plugin', 'missing', {});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "action target_plugin/missing is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want unknown target action error", err)
	}
}

func TestPluginGojaControlPluginActionCallRejectsLargePayload(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "run",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.action"],
    "action_access": [{
      "plugin": "target_plugin",
      "actions": ["apply"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.actions.call('target_plugin', 'apply', {value: 'too-large'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply",
    "max_payload_bytes": 4
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onAction = function () {
  kv.set('called', {value: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "invalid action payload") {
		t.Fatalf("ApplyPluginAction() error = %v, want payload error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", pluginControlKVResourceID, "called"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target called) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginActionCallRejectsSelfCall(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "run",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.action"],
    "action_access": [{
      "plugin": "source_plugin",
      "actions": ["run"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.actions.call('source_plugin', 'run', {});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "self action calls are not supported") {
		t.Fatalf("ApplyPluginAction() error = %v, want self-call error", err)
	}
}

func TestPluginGojaControlPluginActionCallAppliesTargetAction(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "run",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "plugin.action"],
    "action_access": [{
      "plugin": "target_plugin",
      "actions": ["apply"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  var result = plugins.actions.call('target_plugin', 'apply', {value: 'alpha'});
  kv.set('call_result', result);
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onAction = function (ctx) {
  kv.set('last_payload', {
    plugin: ctx.plugin.id,
    action: ctx.action.id,
    value: ctx.payload.value
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "run"), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	target, err := store.GetPluginRecord(db, "target_plugin", pluginControlKVResourceID, "last_payload")
	if err != nil {
		t.Fatalf("GetPluginRecord(target last_payload) error = %v", err)
	}
	for _, want := range []string{`"plugin":"target_plugin"`, `"action":"apply"`, `"value":"alpha"`} {
		if !strings.Contains(target.DataJSON, want) {
			t.Fatalf("target last_payload = %s, missing %s", target.DataJSON, want)
		}
	}
	result, err := store.GetPluginRecord(db, "source_plugin", pluginControlKVResourceID, "call_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(source call_result) error = %v", err)
	}
	for _, want := range []string{`"status":"completed"`, `"plugin":"target_plugin"`, `"action":"apply"`, `"runtime_update":"runtime_apply"`} {
		if !strings.Contains(result.DataJSON, want) {
			t.Fatalf("source call_result = %s, missing %s", result.DataJSON, want)
		}
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "target_plugin", "action", "apply")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target action) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision == 0 {
		t.Fatalf("target action runtime status = %+v, want applied", status)
	}
}

func TestPluginGojaControlPluginResourceListRequiresResourceAccessMethod(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "read",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["get"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.list('target_plugin', 'settings');
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "resource access target_plugin/settings method list is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want resource access method error", err)
	}
}

func TestPluginGojaControlPluginResourceSetRequiresUpdateAccessForExistingRecord(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["create"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'});
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha2'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "resource access target_plugin/settings method update is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want update resource access error", err)
	}
	record, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"name":"alpha"`) || strings.Contains(record.DataJSON, "alpha2") {
		t.Fatalf("target settings/alpha = %s, want first create only", record.DataJSON)
	}
}

func TestPluginGojaControlPluginResourceSetRequiresCreateAccessForNewRecord(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha2'});
  plugins.resources.set('target_plugin', 'settings', 'beta', {name: 'beta'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "target_plugin",
		ResourceID: "settings",
		RecordKey:  "alpha",
		DataJSON:   `{"name":"alpha"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(target settings/alpha) error = %v", err)
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "resource access target_plugin/settings method create is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want create resource access error", err)
	}
	alpha, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v", err)
	}
	if !strings.Contains(alpha.DataJSON, `"name":"alpha2"`) {
		t.Fatalf("target settings/alpha = %s, want update with update-only access", alpha.DataJSON)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "settings", "beta"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target settings/beta) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginResourceSetDoesNotUseTargetControlMethods(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "status",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'status', 'last', {phase: 'spoofed'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "status",
    "methods": ["list", "get"],
    "control_methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "resource target_plugin/status does not allow create") {
		t.Fatalf("ApplyPluginAction() error = %v, want target methods denial", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "status", "last"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target status/last) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlPluginResourceGetList(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "read",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["get", "list"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  var alpha = plugins.resources.get('target_plugin', 'settings', 'alpha');
  var missing = plugins.resources.get('target_plugin', 'settings', 'missing');
  var all = plugins.resources.list('target_plugin', 'settings');
  kv.set('read_result', {
    alpha_name: alpha && alpha.data && alpha.data.name,
    missing_is_null: missing === null,
    count: all.length,
    second_key: all[1] && all[1].key
  });
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	for _, item := range []store.PluginRecord{
		{PluginID: "target_plugin", ResourceID: "settings", RecordKey: "alpha", DataJSON: `{"name":"alpha"}`, Enabled: true},
		{PluginID: "target_plugin", ResourceID: "settings", RecordKey: "beta", DataJSON: `{"name":"beta"}`, Enabled: true},
	} {
		current := item
		if _, err := store.AddPluginRecord(db, &current); err != nil {
			t.Fatalf("AddPluginRecord(%s) error = %v", current.RecordKey, err)
		}
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	result, err := store.GetPluginRecord(db, "source_plugin", pluginControlKVResourceID, "read_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(read_result) error = %v", err)
	}
	for _, want := range []string{`"alpha_name":"alpha"`, `"missing_is_null":true`, `"count":2`, `"second_key":"beta"`} {
		if !strings.Contains(result.DataJSON, want) {
			t.Fatalf("read_result = %s, missing %s", result.DataJSON, want)
		}
	}
}

func TestPluginGojaControlListAPIsSupportPagination(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list"]
  }],
  "actions": [{
    "id": "read",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "plugin.resource", "resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["list"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  kv.set('seed', {ready: true});
  var own = resources.list('settings', {limit: 2, offset: 1});
  var cross = plugins.resources.list('target_plugin', 'settings', {limit: 1, offset: 2});
  var kvPage = kv.list({limit: 1, offset: 0});
  kv.set('page_result', {
    own_count: own.length,
    own_first: own[0] && own[0].key,
    own_second: own[1] && own[1].key,
    cross_count: cross.length,
    cross_first: cross[0] && cross[0].key,
    kv_count: kvPage.length,
    kv_first: kvPage[0] && kvPage[0].key
  });
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list"]
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	for _, pluginID := range []string{"source_plugin", "target_plugin"} {
		for _, key := range []string{"alpha", "beta", "gamma"} {
			if _, err := store.AddPluginRecord(db, &store.PluginRecord{
				PluginID:   pluginID,
				ResourceID: "settings",
				RecordKey:  key,
				DataJSON:   fmt.Sprintf(`{"name":%q}`, key),
				Enabled:    true,
			}); err != nil {
				t.Fatalf("AddPluginRecord(%s %s) error = %v", pluginID, key, err)
			}
		}
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	result, err := store.GetPluginRecord(db, "source_plugin", pluginControlKVResourceID, "page_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(page_result) error = %v", err)
	}
	for _, want := range []string{
		`"own_count":2`,
		`"own_first":"beta"`,
		`"own_second":"gamma"`,
		`"cross_count":1`,
		`"cross_first":"gamma"`,
		`"kv_count":1`,
		`"kv_first":"seed"`,
	} {
		if !strings.Contains(result.DataJSON, want) {
			t.Fatalf("page_result = %s, missing %s", result.DataJSON, want)
		}
	}
}

func TestPluginGojaControlListAPIsRejectInvalidLimit(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list"]
  }],
  "actions": [{
    "id": "read",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", fmt.Sprintf(`
exports.onAction = function () {
  resources.list('settings', {limit: %d});
};
`, pluginResourceListHardLimit+1))

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "resources.list: limit must be between 1 and") {
		t.Fatalf("ApplyPluginAction() error = %v, want list limit error", err)
	}
}

func TestPluginGojaControlPluginResourceReadRedactsTargetSecrets(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "read",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["get", "list", "create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  var direct = plugins.resources.get('target_plugin', 'settings', 'alpha');
  var all = plugins.resources.list('target_plugin', 'settings');
  var updated = plugins.resources.set('target_plugin', 'settings', 'alpha', {
    username: 'alice',
    password: 'new-secret'
  });
  kv.set('read_result', {
    direct_password: direct && direct.data && direct.data.password,
    list_password: all[0] && all[0].data && all[0].data.password,
    set_password: updated && updated.data && updated.data.password
  });
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "get", "create", "update"],
    "runtime_update": "manual",
    "secret_fields": ["password"]
  }]
}`)

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "target_plugin",
		ResourceID: "settings",
		RecordKey:  "alpha",
		DataJSON:   `{"username":"alice","password":"old-secret"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(target settings/alpha) error = %v", err)
	}
	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	result, err := store.GetPluginRecord(db, "source_plugin", pluginControlKVResourceID, "read_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(read_result) error = %v", err)
	}
	for _, want := range []string{`"direct_password":"__redacted__"`, `"list_password":"__redacted__"`, `"set_password":"__redacted__"`} {
		if !strings.Contains(result.DataJSON, want) {
			t.Fatalf("read_result = %s, missing %s", result.DataJSON, want)
		}
	}
	target, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v", err)
	}
	if !strings.Contains(target.DataJSON, `"password":"new-secret"`) {
		t.Fatalf("target settings/alpha = %s, want stored unredacted password", target.DataJSON)
	}
}

func TestPluginGojaControlPluginResourceSetPreservesTargetSecretFields(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["get", "create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  var alpha = plugins.resources.get('target_plugin', 'settings', 'alpha');
  var updatedAlpha = plugins.resources.set('target_plugin', 'settings', 'alpha', {
    username: 'alice2',
    password: alpha && alpha.data && alpha.data.password
  });
  var updatedBeta = plugins.resources.set('target_plugin', 'settings', 'beta', {
    username: 'bob2'
  });
  var unchangedGamma = plugins.resources.set('target_plugin', 'settings', 'gamma', {
    username: 'carol',
    password: 'gamma-secret'
  });
  kv.set('set_result', {
    alpha_password: updatedAlpha && updatedAlpha.data && updatedAlpha.data.password,
    beta_password: updatedBeta && updatedBeta.data && updatedBeta.data.password,
    gamma_password: unchangedGamma && unchangedGamma.data && unchangedGamma.data.password
  });
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["get", "create", "update"],
    "runtime_update": "manual",
    "secret_fields": ["password"]
  }]
}`)

	db := openTestDB(t)
	for _, item := range []store.PluginRecord{
		{PluginID: "target_plugin", ResourceID: "settings", RecordKey: "alpha", DataJSON: `{"username":"alice","password":"alpha-secret"}`, Enabled: true},
		{PluginID: "target_plugin", ResourceID: "settings", RecordKey: "beta", DataJSON: `{"username":"bob","password":"beta-secret"}`, Enabled: true},
		{PluginID: "target_plugin", ResourceID: "settings", RecordKey: "gamma", DataJSON: `{"username":"carol","password":"gamma-secret"}`, Enabled: true},
	} {
		current := item
		if _, err := store.AddPluginRecord(db, &current); err != nil {
			t.Fatalf("AddPluginRecord(target settings/%s) error = %v", current.RecordKey, err)
		}
	}

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	result, err := store.GetPluginRecord(db, "source_plugin", pluginControlKVResourceID, "set_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(set_result) error = %v", err)
	}
	for _, want := range []string{`"alpha_password":"__redacted__"`, `"beta_password":"__redacted__"`, `"gamma_password":"__redacted__"`} {
		if !strings.Contains(result.DataJSON, want) {
			t.Fatalf("set_result = %s, missing %s", result.DataJSON, want)
		}
	}
	for _, tc := range []struct {
		key      string
		password string
		username string
	}{
		{key: "alpha", password: `"password":"alpha-secret"`, username: `"username":"alice2"`},
		{key: "beta", password: `"password":"beta-secret"`, username: `"username":"bob2"`},
		{key: "gamma", password: `"password":"gamma-secret"`, username: `"username":"carol"`},
	} {
		record, err := store.GetPluginRecord(db, "target_plugin", "settings", tc.key)
		if err != nil {
			t.Fatalf("GetPluginRecord(target settings/%s) error = %v", tc.key, err)
		}
		if !strings.Contains(record.DataJSON, tc.password) {
			t.Fatalf("target settings/%s = %s, missing preserved %s", tc.key, record.DataJSON, tc.password)
		}
		if !strings.Contains(record.DataJSON, tc.username) {
			t.Fatalf("target settings/%s = %s, missing updated %s", tc.key, record.DataJSON, tc.username)
		}
	}
}

func TestPluginGojaControlPluginResourceSetAppliesTargetResource(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'}, true, true);
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "create", "update", "get"],
    "runtime_update": "runtime_apply"
  }, {
    "id": "status",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource"]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onResourceApply = function (ctx) {
  resources.set('status', 'last', {
    resource: ctx.resource.id,
    count: ctx.records.length,
    first: ctx.records[0].data.name
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"name":"alpha"`) {
		t.Fatalf("target settings/alpha = %s, want name alpha", record.DataJSON)
	}
	statusRecord, err := store.GetPluginRecord(db, "target_plugin", "status", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(target status/last) error = %v", err)
	}
	for _, want := range []string{`"resource":"settings"`, `"count":1`, `"first":"alpha"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("target status/last = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("target settings runtime status = %+v, want applied revision 1", status)
	}
}

func TestPluginGojaControlPluginResourceSetNoopsUnchangedTargetRecord(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'});
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("first ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v", err)
	}
	if record.Revision != 1 {
		t.Fatalf("target settings/alpha revision = %d, want 1", record.Revision)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("target settings runtime status = %+v, want revision 1", status)
	}
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("second ApplyPluginAction() error = %v", err)
	}
	record, err = store.GetPluginRecord(db, "target_plugin", "settings", "alpha")
	if err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) after no-op error = %v", err)
	}
	if record.Revision != 1 {
		t.Fatalf("target settings/alpha revision after no-op = %d, want 1", record.Revision)
	}
	status, err = store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) after no-op error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("target settings runtime status after no-op = %+v, want revision 1", status)
	}
}

func TestPluginGojaControlPluginResourceSetUsesProcessApplierChain(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'}, true, true);
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "create", "update", "get"],
    "runtime_update": "runtime_apply"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	applier := &pluginRuntimeApplyTestRuntime{}
	pm := &ProcessManager{db: db, cfg: cfg, kernelRuntime: applier}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if len(applier.resourceCalls) != 1 {
		t.Fatalf("resource applier calls = %+v, want one target resource apply", applier.resourceCalls)
	}
	call := applier.resourceCalls[0]
	if call.plugin.ID != "target_plugin" || call.resource.ID != "settings" || len(call.records) != 1 || call.records[0].Key != "alpha" {
		t.Fatalf("resource applier call = %+v, want target_plugin/settings alpha", call)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("target settings runtime status = %+v, want applied revision 1", status)
	}
}

func TestPluginGojaControlPluginResourceSetApplyRunsPrivilegedLabRuntimeApplyFallback(t *testing.T) {
	dir := t.TempDir()
	sourceControl := `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'}, true, true);
};
`
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "1.0.0",
  "kind": "control",
  "stability": "stable",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "sha256": "`+testSHA256Hex(sourceControl)+`",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", sourceControl)
	setTestPluginControlSHA(t, dir, "source_plugin")
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "stability": "lab",
  "resources": [{
    "id": "settings",
    "methods": ["list", "create", "update", "get"],
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onResourceApply = function () {
  kv.set('applied', {ok: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	rt := newPluginControlRuntime(db, cfg, nil)

	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha"); err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", pluginControlKVResourceID, "applied"); err != nil {
		t.Fatalf("GetPluginRecord(target applied KV) error = %v", err)
	}
	status, statusErr := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) error = %v", statusErr)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("target settings runtime status = %+v, want applied revision 1", status)
	}
}

func TestPluginGojaControlPluginResourceSetApplyRunsPluginReconcile(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "hook_bindings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'hook_bindings', 'forward', {
    hook_id: 'forward',
    interfaces: ['eth0']
  }, true, true);
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{db: db, cfg: cfg}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "target_plugin", "hook_bindings", "forward")
	if err != nil {
		t.Fatalf("GetPluginRecord(target hook_bindings/forward) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"hook_id":"forward"`) || !strings.Contains(record.DataJSON, `"eth0"`) {
		t.Fatalf("target hook_bindings/forward = %s, want forward eth0 binding", record.DataJSON)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "hook_bindings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target hook_bindings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("target hook_bindings runtime status = %+v, want applied revision 1", status)
	}
}

func TestPluginGojaControlPluginResourceSetApplyAllowsPrivilegedLabPluginReconcile(t *testing.T) {
	dir := t.TempDir()
	sourceControl := `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'hook_bindings', 'forward', {
    hook_id: 'forward',
    interfaces: ['eth0']
  }, true, true);
};
`
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "1.0.0",
  "kind": "control",
  "stability": "stable",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "sha256": "`+testSHA256Hex(sourceControl)+`",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "hook_bindings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", sourceControl)
	setTestPluginControlSHA(t, dir, "source_plugin")
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "stability": "lab",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "target_plugin", `
exports.onReconcile = function () {};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{db: db, cfg: cfg, pluginRuntime: pluginDataplaneRuntimeTest{}}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "target_plugin", "hook_bindings", "forward")
	if err != nil {
		t.Fatalf("GetPluginRecord(target hook_bindings/forward) error = %v, want persisted binding despite runtime error", err)
	}
	if !strings.Contains(record.DataJSON, `"hook_id":"forward"`) || !strings.Contains(record.DataJSON, `"eth0"`) {
		t.Fatalf("target hook_bindings/forward = %s, want persisted binding", record.DataJSON)
	}
	status, statusErr := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "hook_bindings")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target hook_bindings) error = %v", statusErr)
	}
	if status == nil || status.Status != "applied" || status.LastError != "" || status.AppliedRevision != status.Revision {
		t.Fatalf("target hook_bindings runtime status = %+v, want applied lab plugin reconcile", status)
	}
}

func TestPluginGojaControlPluginResourceSetApplyReturnsPluginReconcileError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "hook_bindings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'hook_bindings', 'forward', {
    hook_id: 'forward',
    interfaces: ['eth0']
  }, true, true);
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	pm := &ProcessManager{
		db:            db,
		cfg:           cfg,
		pluginRuntime: pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{"target_plugin": pluginRuntimeErrorState("attach failed")}}},
	}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "attach failed") {
		t.Fatalf("ApplyPluginAction() error = %v, want attach failed", err)
	}
	record, recordErr := store.GetPluginRecord(db, "target_plugin", "hook_bindings", "forward")
	if recordErr != nil {
		t.Fatalf("GetPluginRecord(target hook_bindings/forward) error = %v", recordErr)
	}
	if !strings.Contains(record.DataJSON, `"hook_id":"forward"`) || !strings.Contains(record.DataJSON, `"eth0"`) {
		t.Fatalf("target hook_bindings/forward = %s, want persisted binding despite runtime error", record.DataJSON)
	}
	status, statusErr := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "hook_bindings")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target hook_bindings) error = %v", statusErr)
	}
	if status == nil || status.Status != "error" || status.AppliedRevision == status.Revision || !strings.Contains(status.LastError, "attach failed") {
		t.Fatalf("target hook_bindings runtime status = %+v, want error without applied overwrite", status)
	}
}

func TestPluginGojaControlPluginResourceSetApplyMarksTargetRuntimeError(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["create", "update"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.set('target_plugin', 'settings', 'alpha', {name: 'alpha'}, true, true);
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "create", "update", "get"],
    "runtime_update": "runtime_apply"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	cfg := &Config{PluginsDir: dir}
	applier := &pluginRuntimeApplyTestRuntime{resourceErr: errors.New("kernel map update failed")}
	pm := &ProcessManager{db: db, cfg: cfg, kernelRuntime: applier}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "kernel map update failed") {
		t.Fatalf("ApplyPluginAction() error = %v, want target runtime apply error", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha"); err != nil {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v, want record persisted before runtime apply error", err)
	}
	status, statusErr := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if statusErr != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) error = %v", statusErr)
	}
	if status == nil || status.Status != "error" || !strings.Contains(status.LastError, "kernel map update failed") {
		t.Fatalf("target settings runtime status = %+v, want runtime error", status)
	}
}

func TestPluginGojaControlPluginResourceDeleteAppliesTargetResource(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "delete",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["delete"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.delete('target_plugin', 'settings', 'alpha', true);
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "runtime_apply"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "target_plugin",
		ResourceID: "settings",
		RecordKey:  "alpha",
		DataJSON:   `{"name":"alpha"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(target settings/alpha) error = %v", err)
	}
	cfg := &Config{PluginsDir: dir}
	applier := &pluginRuntimeApplyTestRuntime{}
	pm := &ProcessManager{db: db, cfg: cfg, kernelRuntime: applier}
	rt := newPluginControlRuntime(db, cfg, pm)
	pm.pluginControlRuntime = rt

	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction(delete) error = %v", err)
	}
	if _, err := store.GetPluginRecord(db, "target_plugin", "settings", "alpha"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(target settings/alpha) error = %v, want sql.ErrNoRows", err)
	}
	if len(applier.resourceCalls) != 1 {
		t.Fatalf("resource applier calls = %+v, want one target resource apply after delete", applier.resourceCalls)
	}
	call := applier.resourceCalls[0]
	if call.plugin.ID != "target_plugin" || call.resource.ID != "settings" || len(call.records) != 0 {
		t.Fatalf("resource applier call = %+v, want target_plugin/settings with zero records", call)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) error = %v", err)
	}
	if status == nil || status.Status != "applied" || status.AppliedRevision != 1 {
		t.Fatalf("target settings runtime status = %+v, want applied revision 1", status)
	}
}

func TestPluginGojaControlPluginResourceDeleteNoopsMissingTargetRecord(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "source_plugin", `{
  "api_version": "v1",
  "id": "source_plugin",
  "name": "Source Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "delete",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["plugin.resource"],
    "resource_access": [{
      "plugin": "target_plugin",
      "resource": "settings",
      "methods": ["delete"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "source_plugin", `
exports.onAction = function () {
  plugins.resources.delete('target_plugin', 'settings', 'alpha');
};
`)
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version": "v1",
  "id": "target_plugin",
  "name": "Target Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "settings",
    "methods": ["create", "update", "delete", "get"],
    "runtime_update": "manual"
  }]
}`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "source_plugin")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "target_plugin",
		ResourceID: "settings",
		RecordKey:  "alpha",
		DataJSON:   `{"name":"alpha"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(target settings/alpha) error = %v", err)
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("first ApplyPluginAction(delete) error = %v", err)
	}
	status, err := store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("target settings runtime status = %+v, want revision 1", status)
	}
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("second ApplyPluginAction(delete) error = %v", err)
	}
	status, err = store.PluginRuntimeStatusOrNil(db, "target_plugin", "resource", "settings")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(target settings) after missing delete error = %v", err)
	}
	if status == nil || status.Revision != 1 {
		t.Fatalf("target settings runtime status after missing delete = %+v, want revision 1", status)
	}
}

func TestPluginGojaControlEBPFMapAPIUsesHostController(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["ebpf.map_write"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  ebpf.mapPut('bindings_v4', '01020304', '1112131415161718');
  ebpf.mapDelete('bindings_v4', '01020304');
  ebpf.mapClear('bindings_v4');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	controller := &pluginControlMapControllerTest{}
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, controller)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if len(controller.calls) != 3 {
		t.Fatalf("map calls = %+v, want put/delete/clear", controller.calls)
	}
	if controller.calls[0] != "put:control_plugin::bindings_v4:01020304:1112131415161718" {
		t.Fatalf("put call = %q", controller.calls[0])
	}
	if controller.calls[1] != "delete:control_plugin::bindings_v4:01020304" {
		t.Fatalf("delete call = %q", controller.calls[1])
	}
	if controller.calls[2] != "clear:control_plugin::bindings_v4" {
		t.Fatalf("clear call = %q", controller.calls[2])
	}
}

func TestPluginGojaControlEBPFMapAPILegacyCallAllowsEmptyObject(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["ebpf.map_write"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  ebpf.mapPut('bindings_v4', '01020304', '1112131415161718');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	controller := &pluginControlMapControllerTest{}
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, controller)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if len(controller.calls) != 1 || controller.calls[0] != "put:control_plugin::bindings_v4:01020304:1112131415161718" {
		t.Fatalf("map calls = %+v, want legacy put with empty object", controller.calls)
	}
}

func TestPluginGojaControlEBPFMapAPIRejectsReservedRuntimeMaps(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["ebpf.map_write"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  ebpf.mapPut('tc_prog_chain_v4', '01020304', '11121314');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	controller := &pluginControlMapControllerTest{}
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, controller)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "ebpf.mapPut: map tc_prog_chain_v4 is reserved") {
		t.Fatalf("ApplyPluginAction() error = %v, want reserved map error", err)
	}
	if len(controller.calls) != 0 {
		t.Fatalf("map calls = %+v, want no controller call for reserved map", controller.calls)
	}
}

func TestPluginGojaControlEBPFMapAPIRejectsUndeclaredObject(t *testing.T) {
	host := &pluginControlHost{
		vm: goja.New(),
		plugin: LoadedPlugin{PluginManifest: PluginManifest{
			ID: "control_plugin",
		}, Objects: []PluginObject{{ID: "declared"}}},
	}
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("requirePluginObjectID() did not panic for undeclared object")
		}
		if !strings.Contains(fmt.Sprint(recovered), "ebpf.mapPut: object observer is not declared") {
			t.Fatalf("panic = %v, want undeclared object error", recovered)
		}
	}()
	host.requirePluginObjectID("observer", "ebpf.mapPut")
}

func TestPluginGojaControlEBPFMapAPIRejectsExplicitObjectWithoutRegisteredObjects(t *testing.T) {
	host := &pluginControlHost{
		vm: goja.New(),
		plugin: LoadedPlugin{PluginManifest: PluginManifest{
			ID: "control_plugin",
		}},
	}
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("requirePluginObjectID() did not panic for explicit object without registered objects")
		}
		if !strings.Contains(fmt.Sprint(recovered), "ebpf.mapPut: object observer is not declared") {
			t.Fatalf("panic = %v, want undeclared object error", recovered)
		}
	}()
	host.requirePluginObjectID("observer", "ebpf.mapPut")
}

func TestPluginGojaControlRejectsMissingEBPFPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  ebpf.mapPut('observer', 'bindings_v4', '01020304', '1112131415161718');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, &pluginControlMapControllerTest{})
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission ebpf.map_write is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want ebpf permission error", err)
	}
}

func TestPluginGojaControlCryptoAPI(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["crypto", "kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  var random = crypto.randomBytes(4);
  var chap = crypto.md5([7], 'password', {hex: '01020304'});
  kv.set('crypto_result', {
    md5: crypto.md5('abc'),
    control_sha256: crypto.sha256File('control.js'),
    chap_len: chap.length,
    random_len: random.length,
    random_hex: /^[0-9a-f]+$/.test(random)
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	controlSHA, err := sha256File(filepath.Join(dir, "control_plugin", "control.js"))
	if err != nil {
		t.Fatalf("sha256File(control.js) error = %v", err)
	}
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "crypto_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(crypto_result) error = %v", err)
	}
	for _, want := range []string{
		`"md5":"900150983cd24fb0d6963f7d28e17f72"`,
		`"control_sha256":"` + controlSHA + `"`,
		`"chap_len":32`,
		`"random_len":8`,
		`"random_hex":true`,
	} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("crypto_result data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlCryptoSHA256FileRejectsPathEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "outside.txt"), []byte("outside"), 0o644); err != nil {
		t.Fatalf("WriteFile(outside.txt) error = %v", err)
	}
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["crypto"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  crypto.sha256File('../outside.txt');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "crypto.sha256File: path escapes plugin root") {
		t.Fatalf("ApplyPluginAction() error = %v, want sha256File path escape error", err)
	}
}

func TestPluginGojaControlSecretAPI(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "secret"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function (ctx) {
  secret.set('password', ctx.payload.password);
  var before = secret.get('password');
  secret.delete('password');
  var after = secret.get('password');
  kv.set('secret_result', {
    before: before,
    after_is_null: after === null
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{"password":"s3cr3t"}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "secret_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(secret_result) error = %v", err)
	}
	for _, want := range []string{`"before":"s3cr3t"`, `"after_is_null":true`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("secret_result data = %s, want %s", record.DataJSON, want)
		}
	}
	if _, err := store.GetPluginRecord(db, "control_plugin", pluginControlSecretResourceID, "password"); err == nil {
		t.Fatalf("GetPluginRecord(secret password) error = nil, want deleted secret")
	}
}

func TestPluginGojaControlSecretSetHonorsRecordLimit(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["secret"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  secret.set('overflow', 'new-secret');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	for i := 0; i < pluginControlMaxSecrets; i++ {
		if _, err := store.AddPluginRecord(db, &store.PluginRecord{
			PluginID:   "control_plugin",
			ResourceID: pluginControlSecretResourceID,
			RecordKey:  fmt.Sprintf("s%04d", i),
			DataJSON:   `"secret"`,
			Enabled:    true,
		}); err != nil {
			t.Fatalf("AddPluginRecord(secret %d) error = %v", i, err)
		}
	}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "secret.set: resource record limit reached") {
		t.Fatalf("ApplyPluginAction() error = %v, want secret record limit error", err)
	}
	if _, err := store.GetPluginRecord(db, "control_plugin", pluginControlSecretResourceID, "overflow"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(secret overflow) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlRejectsMissingCryptoPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  crypto.md5('abc');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission crypto is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want crypto permission error", err)
	}
}

func TestPluginGojaControlTimerTimeoutFiresOnTimer(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "timer"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  timer.setTimeout('dial_retry', 20, {attempt: 3});
};
exports.onTimer = function (ctx) {
  kv.set('timer_result', {
    name: ctx.timer.name,
    kind: ctx.timer.kind,
    attempt: ctx.timer.payload.attempt
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record := waitForPluginRecordForTest(t, db, "control_plugin", pluginControlKVResourceID, "timer_result", 2*time.Second)
	for _, want := range []string{`"name":"dial_retry"`, `"kind":"timeout"`, `"attempt":3`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("timer_result data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlTimerIntervalCanClearItself(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "timer"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  kv.set('tick_count', {value: 0});
  timer.setInterval('heartbeat', 20, {kind: 'echo'});
};
exports.onTimer = function () {
  var record = kv.get('tick_count');
  var value = record ? record.data.value : 0;
  value++;
  kv.set('tick_count', {value: value});
  if (value >= 2) {
    timer.clear('heartbeat');
  }
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	waitForPluginRecordContainingForTest(t, db, "control_plugin", pluginControlKVResourceID, "tick_count", 2*time.Second, `"value":2`)
	time.Sleep(100 * time.Millisecond)
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "tick_count")
	if err != nil {
		t.Fatalf("GetPluginRecord(tick_count) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"value":2`) {
		t.Fatalf("tick_count after clear = %s, want still value 2", record.DataJSON)
	}
}

func TestPluginGojaControlTimerStatusClearsAfterRecovery(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "timer"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  kv.set('timer_should_fail', {value: true});
  timer.setInterval('recovering_timer', 50, {});
};
exports.onTimer = function () {
  var record = kv.get('timer_should_fail');
  if (record && record.data.value) {
    kv.set('timer_failed', {value: true});
    kv.set('timer_should_fail', {value: false});
    throw new Error('temporary timer failure');
  }
  kv.set('timer_recovered', {value: true});
  timer.clear('recovering_timer');
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	waitForPluginRecordForTest(t, db, "control_plugin", pluginControlKVResourceID, "timer_failed", 2*time.Second)
	failed := waitForPluginRuntimeStatusForTest(t, db, "control_plugin", pluginControlTimerRuntimeTarget, "recovering_timer", pluginControlTimerRuntimeStatusErr, 2*time.Second)
	if !strings.Contains(failed.LastError, "temporary timer failure") {
		t.Fatalf("failed timer runtime status = %+v, want temporary timer failure", failed)
	}
	waitForPluginRecordForTest(t, db, "control_plugin", pluginControlKVResourceID, "timer_recovered", 2*time.Second)
	recovered := waitForPluginRuntimeStatusForTest(t, db, "control_plugin", pluginControlTimerRuntimeTarget, "recovering_timer", pluginControlTimerRuntimeStatusOK, 2*time.Second)
	if recovered.LastError != "" {
		t.Fatalf("recovered timer runtime status = %+v, want empty last_error", recovered)
	}
	if recovered.Revision <= failed.Revision {
		t.Fatalf("recovered timer revision = %d, want > failed revision %d", recovered.Revision, failed.Revision)
	}
}

func TestPluginGojaControlRejectsTooManyTimers(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["timer"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", fmt.Sprintf(`
exports.onAction = function () {
  for (var i = 0; i < %d; i++) {
    timer.setTimeout('retry_' + i, 1000, {});
  }
};
`, pluginControlMaxTimersPerPlugin+1))

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "plugin timer limit reached") {
		t.Fatalf("ApplyPluginAction() error = %v, want timer limit error", err)
	}
	if timers := rt.pluginTimerList("control_plugin"); len(timers) != 0 {
		t.Fatalf("timers = %+v, want no partial timer apply on limit error", timers)
	}
}

func TestPluginGojaControlRejectsMissingTimerPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  timer.setTimeout('retry', 20);
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission timer is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want timer permission error", err)
	}
}

func TestPluginGojaControlCloseStopsTimers(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "timer"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  timer.setTimeout('should_not_fire', 100, {});
};
exports.onTimer = function () {
  kv.set('closed_timer_fired', {value: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil)
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "closed_timer_fired"); err == nil {
		t.Fatalf("GetPluginRecord(closed_timer_fired) error = nil, want no timer fire after Close")
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(closed_timer_fired) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlReconcileCancelsInactivePluginTimers(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "timer"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  timer.setTimeout('should_not_fire_after_remove', 40, {});
};
exports.onTimer = function () {
  kv.set('inactive_timer_fired', {value: true});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	if timers := rt.pluginTimerList("control_plugin"); len(timers) != 1 {
		t.Fatalf("timers before inactive reconcile = %+v, want one timer", timers)
	}

	snapshot := rt.Reconcile(PluginCatalog{})
	if len(snapshot.Plugins) != 0 {
		t.Fatalf("inactive reconcile snapshot = %+v, want no active plugins", snapshot)
	}
	if timers := rt.pluginTimerList("control_plugin"); len(timers) != 0 {
		t.Fatalf("timers after inactive reconcile = %+v, want none", timers)
	}

	time.Sleep(100 * time.Millisecond)
	if _, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "inactive_timer_fired"); err == nil {
		t.Fatalf("GetPluginRecord(inactive_timer_fired) error = nil, want no timer fire after inactive reconcile")
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetPluginRecord(inactive_timer_fired) error = %v, want sql.ErrNoRows", err)
	}
}

func TestPluginGojaControlL2APIUsesHostTransport(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  net.l2.send({
    interface: 'eth0',
    ethertype: '0x8863',
    dst_mac: 'ff:ff:ff:ff:ff:ff',
    src_mac: '02:00:00:00:00:01',
    payload: '01020304'
  });
  var frame = net.l2.recv({
    interface: 'eth0',
    ethertype: '0x8863',
    timeout_ms: 20,
    max_bytes: 256
  });
  kv.set('l2_result', {
    src: frame.src_mac,
    dst: frame.dst_mac,
    ethertype: frame.ethertype,
    payload: frame.payload_hex
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{
		recvFrame: pluginControlL2Frame{
			Interface: "eth0",
			IfIndex:   7,
			EtherType: 0x8863,
			DstMAC:    mustMACForTest(t, "02:00:00:00:00:01"),
			SrcMAC:    mustMACForTest(t, "02:00:00:00:00:02"),
			Payload:   []byte{0x11, 0x22},
			Frame:     []byte{0xff, 0xee},
		},
	}
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	transport := rt.l2Transport.(*pluginControlL2TransportTest)
	if len(transport.sends) != 1 {
		t.Fatalf("l2 sends = %+v, want one send", transport.sends)
	}
	send := transport.sends[0]
	if send.Interface != "eth0" || send.EtherType != 0x8863 || !send.HasSrcMAC {
		t.Fatalf("send request = %+v, want eth0 L2 frame with src mac", send)
	}
	if got := formatPluginControlMAC(send.DstMAC); got != "ff:ff:ff:ff:ff:ff" {
		t.Fatalf("send dst mac = %q", got)
	}
	if got := hex.EncodeToString(send.Payload); got != "01020304" {
		t.Fatalf("send payload = %q", got)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "l2_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(l2_result) error = %v", err)
	}
	for _, want := range []string{
		`"src":"02:00:00:00:00:02"`,
		`"dst":"02:00:00:00:00:01"`,
		`"ethertype":"0x8863"`,
		`"payload":"1122"`,
	} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("l2_result data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlL2ExchangeUsesHostTransport(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  var frame = net.l2.exchange({
    interface: 'eth0',
    ethertype: '0x8863',
    dst_mac: 'ff:ff:ff:ff:ff:ff',
    payload: '0109'
  });
  kv.set('exchange_result', {
    src: frame.src_mac,
    payload: frame.payload_hex
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{
		recvFrame: pluginControlL2Frame{
			Interface: "eth0",
			IfIndex:   7,
			EtherType: 0x8863,
			DstMAC:    mustMACForTest(t, "02:00:00:00:00:01"),
			SrcMAC:    mustMACForTest(t, "02:00:00:00:00:02"),
			Payload:   []byte{0x07, 0x19},
			Frame:     []byte{0xff, 0xee},
		},
	}
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	transport := rt.l2Transport.(*pluginControlL2TransportTest)
	if len(transport.exchanges) != 1 {
		t.Fatalf("l2 exchanges = %+v, want one exchange", transport.exchanges)
	}
	exchange := transport.exchanges[0]
	if exchange.Send.Interface != "eth0" || exchange.Send.EtherType != 0x8863 || exchange.Recv.Timeout <= 0 {
		t.Fatalf("exchange request = %+v, want eth0 L2 exchange request", exchange)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "exchange_result")
	if err != nil {
		t.Fatalf("GetPluginRecord(exchange_result) error = %v", err)
	}
	for _, want := range []string{`"src":"02:00:00:00:00:02"`, `"payload":"0719"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("exchange_result data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlStateMachinePrimitives(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "stateful_l2_plugin", `{
  "api_version": "v1",
  "id": "stateful_l2_plugin",
  "name": "Stateful L2 Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "dial",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["crypto", "ebpf.map_write", "kv", "net.l2", "secret", "timer"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "stateful_l2_plugin", `
exports.onAction = function (ctx) {
  secret.set('password', ctx.payload.password);
  var reply = net.l2.exchange({
    interface: ctx.payload.interface,
    ethertype: '0x88b5',
    dst_mac: 'ff:ff:ff:ff:ff:ff',
    payload: '01020304',
    timeout_ms: 50,
    max_bytes: 512
  });
  if (reply === null) {
    kv.set('control_state', {phase: 'retry'});
    timer.setTimeout('retry', 100, {attempt: 2});
    return;
  }
  var password = secret.get('password');
  var chap = crypto.md5([1], password, {hex: '01020304'});
  ebpf.mapPut('sessions', '00000010', '00000020');
  timer.setInterval('keepalive', 1000, {session: 16});
  kv.set('control_state', {
    phase: 'ready',
    peer: reply.src_mac,
    chap_len: chap.length
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "stateful_l2_plugin")
	db := openTestDB(t)
	controller := &pluginControlMapControllerTest{}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, controller).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{
		recvFrame: pluginControlL2Frame{
			Interface: "eth0",
			IfIndex:   7,
			EtherType: 0x88b5,
			DstMAC:    mustMACForTest(t, "02:00:00:00:00:01"),
			SrcMAC:    mustMACForTest(t, "02:00:00:00:00:02"),
			Payload:   []byte{0x05, 0x06, 0x07, 0x08},
			Frame:     []byte{0xff, 0xee},
		},
	}
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{"interface":"eth0","password":"secret"}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "stateful_l2_plugin", pluginControlKVResourceID, "control_state")
	if err != nil {
		t.Fatalf("GetPluginRecord(control_state) error = %v", err)
	}
	for _, want := range []string{`"phase":"ready"`, `"peer":"02:00:00:00:00:02"`, `"chap_len":32`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("control_state data = %s, want %s", record.DataJSON, want)
		}
	}
	if len(controller.calls) != 1 || controller.calls[0] != "put:stateful_l2_plugin::sessions:00000010:00000020" {
		t.Fatalf("map calls = %+v, want session map put", controller.calls)
	}
	timers := rt.pluginTimerList("stateful_l2_plugin")
	if len(timers) != 1 || timers[0]["name"] != "keepalive" || timers[0]["kind"] != pluginControlTimerKindInterval {
		t.Fatalf("timers = %+v, want keepalive interval", timers)
	}
}

func TestPluginGojaControlL2RecvTimeoutReturnsNull(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv", "net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  var frame = net.l2.recv({interface: 'eth0', ethertype: '0x8863', timeout_ms: 20});
  kv.set('l2_timeout', {timeout: frame === null});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{recvErr: errPluginControlL2Timeout}
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", pluginControlKVResourceID, "l2_timeout")
	if err != nil {
		t.Fatalf("GetPluginRecord(l2_timeout) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"timeout":true`) {
		t.Fatalf("l2_timeout data = %s, want timeout true", record.DataJSON)
	}
}

func TestPluginGojaControlRejectsUndeclaredL2NetAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  net.l2.send({interface: 'vmbr0', ethertype: '0x8863', dst_mac: 'ff:ff:ff:ff:ff:ff'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{}
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "net_access operation l2 on interface vmbr0 is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want l2 net_access denial", err)
	}
}

func TestPluginGojaControlRejectsMissingL2Permission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  net.l2.send({interface: 'eth0', ethertype: '0x8863', dst_mac: 'ff:ff:ff:ff:ff:ff'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission net.l2 is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want net.l2 permission error", err)
	}
}

func TestPluginGojaControlNetAdminAPIUsesHostController(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "events",
    "methods": ["get", "create", "update"]
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource", "net.admin"],
    "net_access": [{
      "interfaces": ["br*"],
      "operations": ["link.create", "link.master"]
    }, {
      "interfaces": ["fwd*"],
      "operations": ["addr.write", "link.create", "link.master", "link.offload", "link.read", "link.state", "route.write"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  var bridge = net.link.ensureBridge({name: 'brlan0', mtu: 1500, up: true});
  var pair = net.link.ensureVeth({host: 'fwdlocal0', peer: 'fwdvtap0', mtu: 1492, up: true});
  var member = net.link.setMaster({link: 'fwdvtap0', master: bridge.name});
  net.addr.replace({interface: 'fwdlocal0', cidr: '169.254.77.1/30'});
  net.route.replace({dst: '0.0.0.0/0', dev: 'fwdlocal0', table: 100, metric: 10});
  net.link.setMTU('fwdvtap0', 1492);
  net.link.setOffloads('fwdvtap0', {tx: false, tso: false, gso: false, gro: false, sg: false});
  net.link.setUp('fwdvtap0', true);
  var link = net.link.get('fwdvtap0');
  var links = net.link.list();
  net.link.clearMaster('fwdvtap0');
  resources.set('events', 'last', {
    bridge: bridge.name,
    host: pair.host.name,
    peer: pair.peer.name,
    member_master: member.master_name,
    peer_ifindex: link.ifindex,
    links: links.length
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	wantCalls := []string{
		"ensureBridge:brlan0:1500:true",
		"ensureVeth:fwdlocal0:fwdvtap0:1492:true",
		"setMaster:fwdvtap0:brlan0:true",
		"addrReplace:fwdlocal0:169.254.77.1/30",
		"routeReplace:0.0.0.0/0:fwdlocal0::100:10",
		"setMTU:fwdvtap0:1492",
		"setOffloads:fwdvtap0:gro=false,gso=false,sg=false,tso=false,tx=false",
		"setUp:fwdvtap0:true",
		"get:fwdvtap0",
		"list",
		"clearMaster:fwdvtap0",
	}
	if strings.Join(controller.calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("net admin calls = %+v, want %+v", controller.calls, wantCalls)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", "events", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(events/last) error = %v", err)
	}
	for _, want := range []string{`"bridge":"brlan0"`, `"host":"fwdlocal0"`, `"peer":"fwdvtap0"`, `"member_master":"brlan0"`, `"peer_ifindex":102`, `"links":2`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("events/last data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlRejectsUndeclaredNetAdminAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["net.admin"],
    "net_access": [{
      "interfaces": ["fwd*"],
      "operations": ["link.create"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  net.link.ensureVeth({host: 'eth0', peer: 'fwdvtap0'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "net_access operation link.create on interface eth0 is not declared") {
		t.Fatalf("ApplyPluginAction() error = %v, want net_access denial", err)
	}
}

func TestPluginGojaControlRejectsRouteWithoutDev(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["net.admin"],
    "net_access": [{
      "interfaces": ["fwd*"],
      "operations": ["route.write"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  net.route.replace({dst: '0.0.0.0/0', gateway: '192.0.2.1'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "net.route.replace: dev is required for route.write net_access") {
		t.Fatalf("ApplyPluginAction() error = %v, want route dev denial", err)
	}
}

func TestPluginGojaControlNetLinkListFiltersByNetAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "events",
    "methods": ["get", "create", "update"]
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["resource", "net.admin"],
    "net_access": [{
      "interfaces": ["fwdlocal*"],
      "operations": ["link.read"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  var links = net.link.list();
  resources.set('events', 'links', {count: links.length, name: links[0] ? links[0].name : ''});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", "events", "links")
	if err != nil {
		t.Fatalf("GetPluginRecord(events/links) error = %v", err)
	}
	for _, want := range []string{`"count":1`, `"name":"fwdlocal0"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("events/links data = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginGojaControlRejectsMissingNetAdminPermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  net.link.ensureVeth({host: 'fwdlocal0', peer: 'fwdvtap0'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "permission net.admin is required") {
		t.Fatalf("ApplyPluginAction() error = %v, want net.admin permission error", err)
	}
}

func TestPluginGojaControlRejectsTooLongInterfaceName(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["net.admin"],
    "net_access": [{
      "interfaces": ["fwd*"],
      "operations": ["link.create"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  net.link.ensureVeth({host: 'fwdlocal-realtest', peer: 'fwdvtap-realtest'});
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "exceeds 15 bytes") {
		t.Fatalf("ApplyPluginAction() error = %v, want interface length error", err)
	}
}

func TestPluginGojaControlRejectsInvalidInterfaceNameCharacters(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ifaceName string
	}{
		{name: "slash", ifaceName: "fwd/local0"},
		{name: "backslash", ifaceName: `fwd\local0`},
		{name: "space", ifaceName: "fwd local0"},
		{name: "tab", ifaceName: "fwd\tlocal0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["net.admin"],
    "net_access": [{
      "interfaces": ["fwd*"],
      "operations": ["link.create"]
    }]
  }
}`)
			script := fmt.Sprintf(`
exports.onAction = function () {
  net.link.ensureVeth({host: %q, peer: 'fwdvtap0'});
};
`, tc.ifaceName)
			writePluginControlScript(t, dir, "control_plugin", script)

			plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
			rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil).(*gojaPluginControlRuntime)
			rt.netAdmin = &pluginControlNetAdminTest{}
			t.Cleanup(func() { _ = rt.Close() })
			err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
			if err == nil || !strings.Contains(err.Error(), "contains invalid characters or exceeds 15 bytes") {
				t.Fatalf("ApplyPluginAction() error = %v, want interface character error", err)
			}
			if len(rt.netAdmin.(*pluginControlNetAdminTest).calls) != 0 {
				t.Fatalf("net admin calls = %+v, want no calls for invalid interface name", rt.netAdmin.(*pluginControlNetAdminTest).calls)
			}
		})
	}
}

func TestMergePluginRuntimeSnapshotPrefersDataplaneState(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "mixed", Name: "Mixed", Version: "0.1.0", Kind: "pipeline"},
		Status:         pluginStatusActive,
		Runtime: PluginRuntimeState{
			Mode:   pluginRuntimeModeControl,
			Reason: "control script loaded",
			Error:  "control warning",
		},
	}}}
	mergePluginRuntimeSnapshot(&catalog, pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"mixed": {
			Mode:            pluginRuntimeModeDataplane,
			Attachable:      true,
			Attached:        true,
			AttachmentCount: 1,
			Reason:          "dataplane attached",
		},
	}})

	got := catalog.Plugins[0].Runtime
	if got.Mode != pluginRuntimeModeDataplane || !got.Attached || got.AttachmentCount != 1 {
		t.Fatalf("merged runtime = %+v, want dataplane state", got)
	}
	if !strings.Contains(got.Reason, "control script loaded") || !strings.Contains(got.Reason, "dataplane attached") {
		t.Fatalf("merged reason = %q, want control and dataplane details", got.Reason)
	}
	if got.Error != "control warning" {
		t.Fatalf("merged error = %q, want control warning preserved", got.Error)
	}
}

func TestPluginGojaControlTimeout(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  while (true) {}
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
	startedAt := time.Now()
	err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("ApplyPluginAction() error = %v, want timeout", err)
	}
	if elapsed := time.Since(startedAt); elapsed > pluginControlTimeout+3*time.Second {
		t.Fatalf("timeout elapsed = %s, want bounded runtime", elapsed)
	}
}

func TestPluginAssetHandlerRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	staticDir := filepath.Join(dir, "ui")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	outsidePath := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(outsidePath, []byte("secret"), 0o644); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	linkPath := filepath.Join(staticDir, "secret.txt")
	if err := os.Symlink(outsidePath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/assets/secret.txt", nil)
	rec := httptest.NewRecorder()
	pluginAssetHandler("/assets/", staticDir).ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("symlink escape status = %d, want non-OK", rec.Code)
	}
}

func TestPluginAssetHandlerServesIndexWithoutDirectoryListing(t *testing.T) {
	dir := t.TempDir()
	staticDir := filepath.Join(dir, "ui")
	nestedDir := filepath.Join(staticDir, "nested")
	emptyDir := filepath.Join(staticDir, "empty")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(nested) error = %v", err)
	}
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(empty) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("root index"), 0o644); err != nil {
		t.Fatalf("WriteFile(root index) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(nestedDir, "index.html"), []byte("nested index"), 0o644); err != nil {
		t.Fatalf("WriteFile(nested index) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(emptyDir, "secret.txt"), []byte("must not list"), 0o644); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	handler := pluginAssetHandler("/assets/", staticDir)

	req := httptest.NewRequest(http.MethodGet, "/assets/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "root index") {
		t.Fatalf("GET root index status=%d body=%q, want root index", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/assets/nested/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "nested index") {
		t.Fatalf("GET nested index status=%d body=%q, want nested index", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/assets/empty/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "secret.txt") || strings.Contains(rec.Body.String(), "must not list") {
		t.Fatalf("GET directory without index status=%d body=%q, want no directory listing", rec.Code, rec.Body.String())
	}
}

func TestPluginControlMainRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outsidePath := filepath.Join(dir, "outside.js")
	if err := os.WriteFile(outsidePath, []byte("exports.onAction = function () {};"), 0o644); err != nil {
		t.Fatalf("WriteFile(outside.js) error = %v", err)
	}
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["kv"]
  }
}`)
	linkPath := filepath.Join(dir, "control_plugin", "control.js")
	if err := os.Remove(linkPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Remove(control.js) error = %v", err)
	}
	if err := os.Symlink(outsidePath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	plugin, err := loadPluginFromDir(filepath.Join(dir, "control_plugin"), "control_plugin")
	if err != nil {
		t.Fatalf("loadPluginFromDir() error = %v", err)
	}
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "control.main escapes plugin root") {
		t.Fatalf("plugin status=%s error=%q, want control.main escape error", plugin.Status, plugin.Error)
	}
}

func TestExamplePacketObserverPluginManifest(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "packet_observer")
	rootDir := filepath.Join(t.TempDir(), "packet_observer")
	copyDirForTest(t, sourceDir, rootDir)
	compileBPFObjectFromSource(t, filepath.Join(rootDir, "packet_observer.bpf.c"), filepath.Join(rootDir, "packet_observer.o"))

	plugin, err := loadPluginFromDir(rootDir, "packet_observer")
	if err != nil {
		t.Fatalf("load example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	if plugin.ID != "packet_observer" || plugin.Status != pluginStatusActive {
		t.Fatalf("example plugin = %+v, want active packet_observer", plugin)
	}
	if plugin.Stability != pluginStabilityLab {
		t.Fatalf("packet_observer stability = %q, want lab", plugin.Stability)
	}
	if len(plugin.Hooks) != 1 || plugin.Hooks[0].Engine != kernelEngineTC {
		t.Fatalf("example plugin hooks = %+v, want one TC hook", plugin.Hooks)
	}
	if len(plugin.Objects) != 1 || plugin.Objects[0].Status != pluginObjectStatusVerified {
		t.Fatalf("example plugin objects = %+v, want one verified object", plugin.Objects)
	}
}

func TestApplyPluginHookBindingsFromDBOverridesManifestHookInterfaces(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "pipe_plugin", `{
  "api_version": "v1",
  "id": "pipe_plugin",
  "name": "Pipe Plugin",
  "version": "0.1.0",
  "kind": "pipeline",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "plugin_reconcile"
  }],
	"objects": [{
    "id": "observer",
    "path": "observer.o",
    "programs": [{"id": "tc_ingress", "section": "tc/ingress", "type": "tc"}]
  }],
  "hooks": [{
    "id": "observe",
    "engine": "tc",
    "attach": "ingress",
    "stage": "forward",
    "priority": 10,
    "program": "observer:tc_ingress",
    "mode": "observe",
    "interfaces": ["old0"]
  }]
}`)
	compileTestBPFObject(t, filepath.Join(dir, "pipe_plugin"), "observer.o")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "pipe_plugin",
		ResourceID: pluginHookBindingsResourceID,
		RecordKey:  "observe",
		DataJSON:   `{"hook_id":"observe","interfaces":["new0","new1"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings) error = %v", err)
	}
	catalog := applyPluginHookBindingsFromDB(loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir}), db)
	var plugin LoadedPlugin
	for _, item := range catalog.Plugins {
		if item.ID == "pipe_plugin" {
			plugin = item
			break
		}
	}
	if len(plugin.Hooks) != 1 || strings.Join(plugin.Hooks[0].Interfaces, ",") != "new0,new1" {
		t.Fatalf("hook interfaces = %+v, want new0,new1", plugin.Hooks)
	}
}

func TestApplyPluginHookBindingsFromDBSkipsInvalidInterfaces(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "pipe_plugin", `{
  "api_version": "v1",
  "id": "pipe_plugin",
  "name": "Pipe Plugin",
  "version": "0.1.0",
  "kind": "pipeline",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "plugin_reconcile"
  }],
	"objects": [{
    "id": "observer",
    "path": "observer.o",
    "programs": [{"id": "tc_ingress", "section": "tc/ingress", "type": "tc"}]
  }],
  "hooks": [{
    "id": "observe",
    "engine": "tc",
    "attach": "ingress",
    "stage": "forward",
    "priority": 10,
    "program": "observer:tc_ingress",
    "mode": "observe",
    "interfaces": ["old0"]
  }]
}`)
	compileTestBPFObject(t, filepath.Join(dir, "pipe_plugin"), "observer.o")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "pipe_plugin",
		ResourceID: pluginHookBindingsResourceID,
		RecordKey:  "observe",
		DataJSON:   `{"hook_id":"observe","interfaces":["new 0"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings invalid interfaces) error = %v", err)
	}
	catalog := applyPluginHookBindingsFromDB(loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir}), db)
	var plugin LoadedPlugin
	for _, item := range catalog.Plugins {
		if item.ID == "pipe_plugin" {
			plugin = item
			break
		}
	}
	if len(plugin.Hooks) != 1 || strings.Join(plugin.Hooks[0].Interfaces, ",") != "old0" {
		t.Fatalf("hook interfaces after invalid binding = %+v, want original old0", plugin.Hooks)
	}
}

func TestApplyPluginHookBindingsFromDBDisabledRecordSuppressesManifestHook(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "pipe_plugin", `{
  "api_version": "v1",
  "id": "pipe_plugin",
  "name": "Pipe Plugin",
  "version": "0.1.0",
  "kind": "pipeline",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "plugin_reconcile"
  }],
	"objects": [{
    "id": "observer",
    "path": "observer.o",
    "programs": [{"id": "tc_ingress", "section": "tc/ingress", "type": "tc"}]
  }],
  "hooks": [{
    "id": "forward",
    "engine": "tc",
    "attach": "ingress",
    "stage": "forward",
    "priority": 10,
    "program": "observer:tc_ingress",
    "mode": "observe"
  }, {
    "id": "reply",
    "engine": "tc",
    "attach": "ingress",
    "stage": "reply",
    "priority": 1010,
    "program": "observer:tc_ingress",
    "mode": "observe"
  }]
}`)
	compileTestBPFObject(t, filepath.Join(dir, "pipe_plugin"), "observer.o")
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "pipe_plugin",
		ResourceID: pluginHookBindingsResourceID,
		RecordKey:  "reply",
		DataJSON:   `{"hook_id":"reply"}`,
		Enabled:    false,
	}); err != nil {
		t.Fatalf("AddPluginRecord(disabled hook_bindings) error = %v", err)
	}
	records, err := store.GetPluginRecords(db, "pipe_plugin", pluginHookBindingsResourceID)
	if err != nil {
		t.Fatalf("GetPluginRecords(hook_bindings) error = %v", err)
	}
	if len(records) != 1 || records[0].Enabled {
		t.Fatalf("hook binding records = %+v, want one disabled record", records)
	}
	bindings := pluginHookBindingsFromRecords("pipe_plugin", records)
	if _, ok := bindings.Disabled["reply"]; !ok {
		t.Fatalf("pluginHookBindingsFromRecords() = %+v, want disabled reply", bindings)
	}

	catalog := applyPluginHookBindingsFromDB(loadPluginCatalogWithControlRegistration(&Config{PluginsDir: dir}), db)
	var plugin LoadedPlugin
	for _, item := range catalog.Plugins {
		if item.ID == "pipe_plugin" {
			plugin = item
			break
		}
	}
	if len(plugin.Hooks) != 1 || plugin.Hooks[0].ID != "forward" {
		t.Fatalf("hooks = %+v, want only forward hook after disabled reply binding", plugin.Hooks)
	}
}

func TestExampleVToLocalPluginManifest(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)

	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	if plugin.ID != "vtolocal" || plugin.Status != pluginStatusActive {
		t.Fatalf("vtolocal example plugin = %+v, want active vtolocal", plugin)
	}
	if plugin.Stability != pluginStabilityStable {
		t.Fatalf("vtolocal stability = %q, want stable", plugin.Stability)
	}
	if plugin.Control == nil || plugin.Control.Main != "control.js" {
		t.Fatalf("vtolocal control = %+v, want control.js", plugin.Control)
	}
	if plugin.Control.SHA256 == "" || plugin.Control.ResolvedSHA256 == "" || plugin.Control.SHA256 != plugin.Control.ResolvedSHA256 {
		t.Fatalf("vtolocal control hashes = declared %q resolved %q, want matching non-empty hashes", plugin.Control.SHA256, plugin.Control.ResolvedSHA256)
	}
	if plugin.UI == nil || plugin.UI.SHA256 == "" || plugin.UI.ResolvedSHA256 == "" || plugin.UI.SHA256 != plugin.UI.ResolvedSHA256 {
		t.Fatalf("vtolocal ui hashes = %+v, want matching non-empty hashes", plugin.UI)
	}
	if len(plugin.Resources) != 2 || len(plugin.Actions) != 2 || plugin.UI == nil {
		t.Fatalf("vtolocal resources/actions/ui = %d/%d/%+v, want complete example surface", len(plugin.Resources), len(plugin.Actions), plugin.UI)
	}
	assertPluginResourceMethodsForTest(t, plugin, "status", "get,list", "create,delete,get,list,update")
	if len(plugin.Control.Permissions) != 5 || strings.Join(plugin.Control.Permissions, ",") != "net.admin,plugin.register,resource,timer,ui" {
		t.Fatalf("vtolocal permissions = %+v, want net.admin,plugin.register,resource,timer,ui", plugin.Control.Permissions)
	}
	if !pluginControlHasNetAccess(plugin, "link.create", "fwdlocal0") || !pluginControlHasNetAccess(plugin, "addr.write", "vtolocal0") || !pluginControlHasNetAccess(plugin, "route.write", "fwdlocal0") {
		t.Fatalf("vtolocal net access = %+v, want fwd*/vtolocal* create/address/route access", plugin.Control.NetAccess)
	}
	if pluginControlHasNetAccess(plugin, "link.master", "eth0") {
		t.Fatalf("vtolocal net access = %+v, want no link.master on eth0", plugin.Control.NetAccess)
	}
}

func TestExampleVToLocalApplyActionPersistsLinkAndArmsRepairTimer(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "apply")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		getErrors: map[string]error{"brlan0": fmt.Errorf("link not found")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{
	  "profile_key":"default",
	  "host_interface":"fwdlocal0",
	  "vtap_interface":"fwdvtap0",
	  "host_addresses":["169.254.253.1/30"],
	  "vtap_addresses":["169.254.253.2/30"],
	  "mtu":1492
	}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(vtolocal apply) error = %v", err)
	}
	linkRecord, err := store.GetPluginRecord(db, "vtolocal", "links", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal links/default) error = %v", err)
	}
	if !linkRecord.Enabled {
		t.Fatalf("vtolocal links/default Enabled = false, want true after action apply")
	}
	for _, want := range []string{
		"ensureVeth:fwdlocal0:fwdvtap0:1492:true",
		"addrReplace:fwdlocal0:169.254.253.1/30",
		"addrReplace:fwdvtap0:169.254.253.2/30",
	} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"host_interface":"fwdlocal0"`, `"vtap_interface":"fwdvtap0"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 1 || timers[0]["name"] != "vtolocal_repair" {
		t.Fatalf("vtolocal timers after action apply = %+v, want vtolocal_repair interval", timers)
	}
}

func TestExampleWANCorePluginManifest(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)

	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	if plugin.ID != "wan_core" || plugin.Status != pluginStatusActive {
		t.Fatalf("wan_core example plugin = %+v, want active wan_core", plugin)
	}
	if plugin.Stability != pluginStabilityStable {
		t.Fatalf("wan_core stability = %q, want stable", plugin.Stability)
	}
	if plugin.Control == nil || plugin.Control.Main != "control.js" {
		t.Fatalf("wan_core control = %+v, want control.js", plugin.Control)
	}
	if plugin.Control.SHA256 == "" || plugin.Control.ResolvedSHA256 == "" || plugin.Control.SHA256 != plugin.Control.ResolvedSHA256 {
		t.Fatalf("wan_core control hashes = declared %q resolved %q, want matching non-empty hashes", plugin.Control.SHA256, plugin.Control.ResolvedSHA256)
	}
	if plugin.UI == nil || plugin.UI.SHA256 == "" || plugin.UI.ResolvedSHA256 == "" || plugin.UI.SHA256 != plugin.UI.ResolvedSHA256 {
		t.Fatalf("wan_core ui hashes = %+v, want matching non-empty hashes", plugin.UI)
	}
	if len(plugin.Resources) != 3 || len(plugin.Actions) != 2 || plugin.UI == nil {
		t.Fatalf("wan_core resources/actions/ui = %d/%d/%+v, want complete example surface", len(plugin.Resources), len(plugin.Actions), plugin.UI)
	}
	assertPluginResourceMethodsForTest(t, plugin, "status", "get,list", "create,delete,get,list,update")
	if len(plugin.Control.Permissions) != 5 || strings.Join(plugin.Control.Permissions, ",") != "net.admin,plugin.register,resource,timer,ui" {
		t.Fatalf("wan_core permissions = %+v, want net.admin,plugin.register,resource,timer,ui", plugin.Control.Permissions)
	}
	if !pluginControlHasNetAccess(plugin, "link.create", "fwdwan0") || !pluginControlHasNetAccess(plugin, "addr.write", "fwdwan0") || !pluginControlHasNetAccess(plugin, "route.write", "fwdwan0") || !pluginControlHasNetAccess(plugin, "link.delete", "fwdwan0") {
		t.Fatalf("wan_core net access = %+v, want fwd* create/address/route/delete access", plugin.Control.NetAccess)
	}
	if pluginControlHasNetAccess(plugin, "addr.write", "wan0") || pluginControlHasNetAccess(plugin, "link.delete", "wan0") {
		t.Fatalf("wan_core net access = %+v, want no write/delete access on wan* physical-style names", plugin.Control.NetAccess)
	}
	if pluginControlHasNetAccess(plugin, "link.master", "eth0") {
		t.Fatalf("wan_core net access = %+v, want no link.master on eth0", plugin.Control.NetAccess)
	}
}

func TestExampleLANCorePluginManifest(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)

	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	if plugin.ID != "lan_core" || plugin.Status != pluginStatusActive {
		t.Fatalf("lan_core example plugin = %+v, want active lan_core", plugin)
	}
	if plugin.Stability != pluginStabilityStable {
		t.Fatalf("lan_core stability = %q, want stable", plugin.Stability)
	}
	if plugin.Control == nil || plugin.Control.Main != "control.js" {
		t.Fatalf("lan_core control = %+v, want control.js", plugin.Control)
	}
	if plugin.Control.SHA256 == "" || plugin.Control.ResolvedSHA256 == "" || plugin.Control.SHA256 != plugin.Control.ResolvedSHA256 {
		t.Fatalf("lan_core control hashes = declared %q resolved %q, want matching non-empty hashes", plugin.Control.SHA256, plugin.Control.ResolvedSHA256)
	}
	if plugin.UI == nil || plugin.UI.SHA256 == "" || plugin.UI.ResolvedSHA256 == "" || plugin.UI.SHA256 != plugin.UI.ResolvedSHA256 {
		t.Fatalf("lan_core ui hashes = %+v, want matching non-empty hashes", plugin.UI)
	}
	if len(plugin.Resources) != 3 || len(plugin.Actions) != 2 || plugin.UI == nil {
		t.Fatalf("lan_core resources/actions/ui = %d/%d/%+v, want complete example surface", len(plugin.Resources), len(plugin.Actions), plugin.UI)
	}
	assertPluginResourceMethodsForTest(t, plugin, "status", "get,list", "create,delete,get,list,update")
	assertPluginResourceMethodsForTest(t, plugin, "egress_nat_plans", "get,list", "create,delete,get,list,update")
	if len(plugin.Control.Permissions) != 6 || strings.Join(plugin.Control.Permissions, ",") != "net.admin,plugin.register,plugin.resource,resource,timer,ui" {
		t.Fatalf("lan_core permissions = %+v, want net.admin,plugin.register,plugin.resource,resource,timer,ui", plugin.Control.Permissions)
	}
	if len(plugin.Control.ResourceAccess) != 1 || plugin.Control.ResourceAccess[0].Plugin != "wan_core" || plugin.Control.ResourceAccess[0].Resource != "status" || strings.Join(plugin.Control.ResourceAccess[0].Methods, ",") != "get" {
		t.Fatalf("lan_core resource access = %+v, want wan_core/status get", plugin.Control.ResourceAccess)
	}
	if !pluginControlHasNetAccess(plugin, "link.create", "brlan0") || !pluginControlHasNetAccess(plugin, "addr.write", "brlan0") || !pluginControlHasNetAccess(plugin, "link.read", "brlan0") || !pluginControlHasNetAccess(plugin, "link.create", "vmbr0") || !pluginControlHasNetAccess(plugin, "addr.write", "vmbr0") || !pluginControlHasNetAccess(plugin, "link.read", "vmbr0") || !pluginControlHasNetAccess(plugin, "link.master", "eth1") {
		t.Fatalf("lan_core net access = %+v, want bridge create/address/read and member read/master access", plugin.Control.NetAccess)
	}
	if pluginControlHasNetAccess(plugin, "link.delete", "vmbr0") {
		t.Fatalf("lan_core net access = %+v, want no link.delete on vmbr0", plugin.Control.NetAccess)
	}
}

func TestExampleRouterWizardPluginManifest(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "router_wizard")
	rootDir := filepath.Join(t.TempDir(), "router_wizard")
	copyDirForTest(t, sourceDir, rootDir)

	plugin, err := loadPluginFromDir(rootDir, "router_wizard")
	if err != nil {
		t.Fatalf("load router_wizard example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	if plugin.ID != "router_wizard" || plugin.Status != pluginStatusActive {
		t.Fatalf("router_wizard example plugin = %+v, want active router_wizard", plugin)
	}
	if plugin.Stability != pluginStabilityLab {
		t.Fatalf("router_wizard stability = %q, want lab", plugin.Stability)
	}
	if plugin.Kind != "control" {
		t.Fatalf("router_wizard kind = %q, want control", plugin.Kind)
	}
	if plugin.Control == nil || plugin.Control.Main != "control.js" {
		t.Fatalf("router_wizard control = %+v, want control.js", plugin.Control)
	}
	if plugin.UI == nil || plugin.UI.Page != "router" || plugin.UI.Entry != "index.html" {
		t.Fatalf("router_wizard ui = %+v, want router/index.html", plugin.UI)
	}
	if len(plugin.Resources) != 2 || len(plugin.Actions) != 3 {
		t.Fatalf("router_wizard resources/actions = %d/%d, want 2/3", len(plugin.Resources), len(plugin.Actions))
	}
	assertPluginResourceMethodsForTest(t, plugin, "config", "create,delete,get,list,update", "")
	assertPluginResourceMethodsForTest(t, plugin, "status", "get,list", "create,delete,get,list,update")
	for _, want := range []string{"plugin.register", "plugin.resource", "plugin.action", "resource", "ui"} {
		if !containsString(plugin.Control.Permissions, want) {
			t.Fatalf("router_wizard permissions = %+v, missing %s", plugin.Control.Permissions, want)
		}
	}
	if !pluginControlHasResourceAccess(plugin, "wan_core", "status", "get") ||
		!pluginControlHasResourceAccess(plugin, "lan_core", "egress_nat_plans", "get") ||
		!pluginControlHasResourceAccess(plugin, "pppoe_client", "wan_links", "get") {
		t.Fatalf("router_wizard resource access = %+v, want downstream status reads", plugin.Control.ResourceAccess)
	}
	if !pluginControlHasActionAccess(plugin, "pppoe_client", "dial") ||
		!pluginControlHasActionAccess(plugin, "wan_core", "apply_session") ||
		!pluginControlHasActionAccess(plugin, "lan_core", "apply_network") ||
		!pluginControlHasActionAccess(plugin, "vtolocal", "apply") {
		t.Fatalf("router_wizard action access = %+v, want downstream orchestration actions", plugin.Control.ActionAccess)
	}
}

func TestExampleLANCoreApplyNetworkCreatesBridgeAndEgressPlan(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "apply_network" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("apply_network action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		getErrors: map[string]error{"brlan0": fmt.Errorf("link not found")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0","lanp1"],
	  "addresses":["192.168.100.1/24","fd00:100::1/64"],
	  "mtu":1500,
	  "wan_ref":"default",
	  "wan_egress_interface":"fwdwan0",
	  "wan_egress_source_ip":"198.51.100.2",
	  "protocol":"tcp+udp+icmp",
	  "auto_egress_nat":true
	}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core apply_network) error = %v", err)
	}
	profileRecord, err := store.GetPluginRecord(db, "lan_core", "profiles", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core profiles/default) error = %v", err)
	}
	if !profileRecord.Enabled {
		t.Fatalf("lan_core profiles/default Enabled = false, want true after action apply")
	}
	for _, want := range []string{
		"ensureBridge:brlan0:1500:true",
		"addrReplace:brlan0:192.168.100.1/24",
		"addrReplace:brlan0:fd00:100::1/64",
		"setMaster:lanp0:brlan0:true",
		"setMaster:lanp1:brlan0:true",
	} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"bridge":"brlan0"`, `"bridge_created":true`, `"bridge_existing":false`, `"wan_ref":"default"`, `"parent_interface":"brlan0"`, `"out_interface":"fwdwan0"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if !planRecord.Enabled {
		t.Fatalf("lan_core egress_nat_plans/default Enabled = false, want true")
	}
	for _, want := range []string{`"owner_plugin":"lan_core"`, `"source":"lan_core"`, `"parent_interface":"brlan0"`, `"out_interface":"fwdwan0"`, `"protocol":"tcp+udp+icmp"`, `"enabled":true`} {
		if !strings.Contains(planRecord.DataJSON, want) {
			t.Fatalf("lan_core egress_nat_plans/default = %s, missing %s", planRecord.DataJSON, want)
		}
	}
	effective, err := loadEffectiveEnabledEgressNATItems(db, &Config{PluginsDir: filepath.Dir(rootDir)})
	if err != nil {
		t.Fatalf("loadEffectiveEnabledEgressNATItems() error = %v", err)
	}
	if len(effective) != 1 || effective[0].ID >= 0 || effective[0].ParentInterface != "brlan0" || effective[0].OutInterface != "fwdwan0" {
		t.Fatalf("effective egress nats after lan_core apply = %+v, want one synthetic brlan0 -> fwdwan0 item", effective)
	}
	if effective[0].Protocol != "tcp+udp+icmp" {
		t.Fatalf("effective egress nat protocol = %q, want tcp+udp+icmp", effective[0].Protocol)
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 1 || timers[0]["name"] != "lan_repair" {
		t.Fatalf("lan_core timers after action apply = %+v, want lan_repair interval", timers)
	}

	delete(controller.getErrors, "brlan0")
	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("repair ApplyPluginAction(lan_core apply_network) error = %v", err)
	}
	statusRecord, err = store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) after repair error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"bridge":"brlan0"`, `"bridge_created":true`, `"bridge_existing":true`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default after repair = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCoreApplyNetworkDeletesRemovedManagedBridgeAddress(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "apply_network")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	first := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0"],
	  "addresses":["192.168.100.1/24","fd00:100::1/64"],
	  "wan_egress_interface":"fwdwan0"
	}`)
	if err := rt.ApplyPluginAction(plugin, action, first); err != nil {
		t.Fatalf("first ApplyPluginAction(lan_core apply_network) error = %v", err)
	}

	controller.calls = nil
	second := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0"],
	  "addresses":["192.168.100.1/24"],
	  "wan_egress_interface":"fwdwan0"
	}`)
	if err := rt.ApplyPluginAction(plugin, action, second); err != nil {
		t.Fatalf("second ApplyPluginAction(lan_core apply_network) error = %v", err)
	}
	if !containsString(controller.calls, "addrDelete:brlan0:fd00:100::1/64") {
		t.Fatalf("net admin calls = %+v, missing stale bridge address delete", controller.calls)
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"cleanup_errors":[]`, `"bridge_addresses":["192.168.100.1/24"]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCoreApplyNetworkDeletesManagedBridgeAddressWhenBridgeChanges(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "apply_network")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	first := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0"],
	  "addresses":["192.168.100.1/24"],
	  "wan_egress_interface":"fwdwan0"
	}`)
	if err := rt.ApplyPluginAction(plugin, action, first); err != nil {
		t.Fatalf("first ApplyPluginAction(lan_core apply_network) error = %v", err)
	}

	controller.calls = nil
	second := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan1",
	  "ports":["lanp0"],
	  "addresses":["192.168.100.1/24"],
	  "wan_egress_interface":"fwdwan0"
	}`)
	if err := rt.ApplyPluginAction(plugin, action, second); err != nil {
		t.Fatalf("second ApplyPluginAction(lan_core apply_network) error = %v", err)
	}
	if !containsString(controller.calls, "addrDelete:brlan0:192.168.100.1/24") {
		t.Fatalf("net admin calls = %+v, missing stale old bridge address delete", controller.calls)
	}
}

func TestExampleLANCoreApplyNetworkDetachesRemovedManagedPort(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "apply_network")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	first := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0","lanp1"],
	  "addresses":["192.168.100.1/24"],
	  "wan_egress_interface":"fwdwan0"
	}`)
	if err := rt.ApplyPluginAction(plugin, action, first); err != nil {
		t.Fatalf("first ApplyPluginAction(lan_core apply_network) error = %v", err)
	}

	controller.calls = nil
	second := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0"],
	  "addresses":["192.168.100.1/24"],
	  "wan_egress_interface":"fwdwan0"
	}`)
	if err := rt.ApplyPluginAction(plugin, action, second); err != nil {
		t.Fatalf("second ApplyPluginAction(lan_core apply_network) error = %v", err)
	}
	if !containsString(controller.calls, "clearMaster:lanp1") {
		t.Fatalf("net admin calls = %+v, missing removed managed port detach", controller.calls)
	}
	if containsString(controller.calls, "clearMaster:lanp0") {
		t.Fatalf("net admin calls = %+v, want retained managed port lanp0 left attached", controller.calls)
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"cleanup_errors":[]`, `"managed_ports":["lanp0"]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCorePlanStaysDisabledWithoutWANEgress(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "apply_network" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("apply_network action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0"],
	  "addresses":["192.168.100.1/24"],
	  "auto_egress_nat":true
	}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core apply_network) error = %v", err)
	}
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if planRecord.Enabled {
		t.Fatalf("lan_core egress_nat_plans/default Enabled = true, want false without WAN egress")
	}
	for _, want := range []string{`"enabled":false`, `"parent_interface":"brlan0"`, `"out_interface":""`} {
		if !strings.Contains(planRecord.DataJSON, want) {
			t.Fatalf("lan_core egress_nat_plans/default = %s, missing %s", planRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCoreApplyNetworkAcceptsNestedProfileKey(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "apply_network" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("apply_network action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{
	  "key":"office",
	  "profile":{
	    "bridge":"brlan2",
	    "ports":[],
	    "addresses":["192.168.200.1/24"],
	    "wan_egress_interface":"fwdwan0",
	    "auto_egress_nat":true
	  }
	}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core nested profile) error = %v", err)
	}
	if _, err := store.GetPluginRecord(db, "lan_core", "status", "object-object"); err == nil {
		t.Fatal("unexpected lan_core status/object-object record from stringified profile object")
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "office")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/office) error = %v", err)
	}
	for _, want := range []string{`"lan_id":"office"`, `"bridge":"brlan2"`, `"out_interface":"fwdwan0"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/office = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCoreResourceApplyIsolatesInvalidProfile(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "profiles")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	records := []PluginResourceRecord{
		{
			Key:     "bad",
			Enabled: true,
			Data:    json.RawMessage(`{"bridge":"this-bridge-name-is-too-long","ports":[],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`),
		},
		{
			Key:     "good",
			Enabled: true,
			Data:    json.RawMessage(`{"bridge":"brlan0","ports":[],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`),
		},
	}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err == nil || !strings.Contains(err.Error(), "failed to apply 1 LAN profile record") {
		t.Fatalf("ApplyPluginResourceData(lan_core profiles) error = %v, want partial apply error", err)
	}
	badStatus, err := store.GetPluginRecord(db, "lan_core", "status", "bad")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/bad) error = %v", err)
	}
	if badStatus.Enabled {
		t.Fatalf("lan_core status/bad enabled = true, want false after apply error")
	}
	for _, want := range []string{`"phase":"error"`, `"lan_id":"bad"`, `"last_error":`} {
		if !strings.Contains(badStatus.DataJSON, want) {
			t.Fatalf("lan_core status/bad = %s, missing %s", badStatus.DataJSON, want)
		}
	}
	badPlan, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "bad")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/bad) error = %v", err)
	}
	if badPlan.Enabled || !strings.Contains(badPlan.DataJSON, `"enabled":false`) {
		t.Fatalf("lan_core egress_nat_plans/bad = %+v, want disabled fail-closed plan", badPlan)
	}
	goodStatus, err := store.GetPluginRecord(db, "lan_core", "status", "good")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/good) error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"lan_id":"good"`, `"bridge":"brlan0"`} {
		if !strings.Contains(goodStatus.DataJSON, want) {
			t.Fatalf("lan_core status/good = %s, missing %s", goodStatus.DataJSON, want)
		}
	}
}

func TestExampleLANCoreDisabledProfileResourceDisablesEgressPlan(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "profiles")

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "egress_nat_plans",
		RecordKey:  "default",
		DataJSON:   `{"enabled":true,"parent_interface":"brlan0","out_interface":"fwdwan0"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: false,
		Data:    json.RawMessage(`{"bridge":"brlan0","wan_egress_interface":"fwdwan0","auto_egress_nat":true}`),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core disabled profile) error = %v", err)
	}
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if planRecord.Enabled {
		t.Fatalf("lan_core egress_nat_plans/default enabled = true, want false after disabled profile apply")
	}
	for _, want := range []string{`"enabled":false`, `"parent_interface":"brlan0"`, `"out_interface":"fwdwan0"`, `"note":"disabled because lan_core profile is disabled"`} {
		if !strings.Contains(planRecord.DataJSON, want) {
			t.Fatalf("lan_core egress_nat_plans/default = %s, missing %s", planRecord.DataJSON, want)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("lan_core status/default enabled = true, want false after disabled profile apply")
	}
	if !strings.Contains(statusRecord.DataJSON, `"phase":"disabled"`) {
		t.Fatalf("lan_core status/default = %s, want disabled phase", statusRecord.DataJSON)
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 0 {
		t.Fatalf("lan_core timers after disabled profile apply = %+v, want none", timers)
	}
}

func TestExampleLANCoreDisabledProfileKeepsRepairTimerForOtherEnabledProfiles(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "profiles")

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "other",
		DataJSON:   `{"bridge":"brlan1","ports":[],"addresses":["192.168.101.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profiles/other) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: false,
		Data:    json.RawMessage(`{"bridge":"brlan0","wan_egress_interface":"fwdwan0","auto_egress_nat":true}`),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core disabled profile with other enabled) error = %v", err)
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 1 || timers[0]["name"] != "lan_repair" {
		t.Fatalf("lan_core timers after disabling one of multiple profiles = %+v, want lan_repair", timers)
	}
}

func TestExampleLANCoreRepairTimerRecoversMissingPort(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "profiles")

	db := openTestDB(t)
	profileJSON := `{"bridge":"brlan0","ports":["lanp0","lanp1"],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON:   profileJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profiles/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		getErrors: map[string]error{"lanp1": fmt.Errorf("link not found")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(profileJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core profiles) error = %v", err)
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) partial error = %v", err)
	}
	for _, want := range []string{`"phase":"partial"`, `"missing_ports":["lanp1"]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core partial status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 1 {
		t.Fatalf("lan_core timers after partial apply = %+v, want one repair timer", timers)
	}

	controller.getErrors = nil
	firePluginTimerForTest(t, rt, "lan_core", "lan_repair")
	statusRecord, err = store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) recovered error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"missing_ports":[]`, `"failed_ports":[]`, `"name":"lanp1"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core recovered status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCoreTeardownDisablesProfileAndRepairTimer(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "profiles")
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	profileJSON := `{"bridge":"brlan0","ports":["lanp0"],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON:   profileJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profiles/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		getErrors: map[string]error{"brlan0": fmt.Errorf("link not found")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(profileJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core profiles) error = %v", err)
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 1 {
		t.Fatalf("lan_core timers before teardown = %+v, want one repair timer", timers)
	}
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
	}
	for _, want := range []string{"clearMaster:lanp0", "delete:brlan0"} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	profileRecord, err := store.GetPluginRecord(db, "lan_core", "profiles", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core profiles/default) error = %v", err)
	}
	if profileRecord.Enabled {
		t.Fatalf("lan_core profiles/default enabled = true, want false after teardown")
	}
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if planRecord.Enabled {
		t.Fatalf("lan_core egress_nat_plans/default enabled = true, want false after teardown")
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("lan_core status/default enabled = true, want false after teardown")
	}
	for _, want := range []string{`"phase":"deleted"`, `"bridge_created":true`, `"bridge_delete_skipped":false`, `"managed_ports":["lanp0"]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 0 {
		t.Fatalf("lan_core timers after teardown = %+v, want none", timers)
	}
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: false,
		Data:    json.RawMessage(profileJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core disabled profile after teardown) error = %v", err)
	}
	statusRecord, err = store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) after disabled profile apply error = %v", err)
	}
	for _, want := range []string{`"phase":"deleted"`, `"bridge_created":true`, `"bridge_delete_skipped":false`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default after disabled profile apply = %s, missing %s", statusRecord.DataJSON, want)
		}
	}

	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("second ApplyPluginAction(lan_core teardown) error = %v", err)
	}
	for _, forbidden := range []string{"addrDelete:brlan0:192.168.100.1/24", "clearMaster:lanp0", "delete:brlan0"} {
		if containsString(controller.calls, forbidden) {
			t.Fatalf("net admin calls after repeated teardown = %+v, want no repeated cleanup call %s", controller.calls, forbidden)
		}
	}
	statusRecord, err = store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) after repeated teardown error = %v", err)
	}
	for _, want := range []string{`"phase":"deleted"`, `"bridge_delete_skipped":true`, `"bridge_delete_skip_reason":"previous lan_core status already deleted this plugin-created bridge"`, `"managed_ports":[]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default after repeated teardown = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCoreTeardownWithoutStatusDoesNotDeleteBridgeOrPorts(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	profileJSON := `{"bridge":"brlan0","ports":["lanp0"],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON:   profileJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profiles/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core teardown without status) error = %v", err)
	}
	for _, forbidden := range []string{"clearMaster:lanp0", "delete:brlan0", "addrDelete:brlan0:192.168.100.1/24"} {
		if containsString(controller.calls, forbidden) {
			t.Fatalf("net admin calls = %+v, want no unmanaged teardown call %s without prior status", controller.calls, forbidden)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"phase":"deleted"`, `"bridge_delete_skipped":true`, `"bridge_delete_skip_reason":"no previous lan_core status proves this bridge was plugin-created"`, `"managed_ports":[]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleLANCoreTeardownPreservesVMBridge(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "profiles")
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	profileJSON := `{"bridge":"vmbr0","ports":["lanp0"],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON:   profileJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profiles/default) error = %v", err)
	}
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "egress_nat_plans",
		RecordKey:  "default",
		DataJSON:   `{"enabled":true,"parent_interface":"vmbr0","out_interface":"fwdwan0"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(profileJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core vmbr profile) error = %v", err)
	}
	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
	}
	if !containsString(controller.calls, "clearMaster:lanp0") {
		t.Fatalf("net admin calls = %+v, missing clearMaster:lanp0", controller.calls)
	}
	if !containsString(controller.calls, "addrDelete:vmbr0:192.168.100.1/24") {
		t.Fatalf("net admin calls = %+v, missing addrDelete:vmbr0:192.168.100.1/24", controller.calls)
	}
	if containsString(controller.calls, "delete:vmbr0") {
		t.Fatalf("net admin calls = %+v, want vmbr0 preserved", controller.calls)
	}
	profileRecord, err := store.GetPluginRecord(db, "lan_core", "profiles", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core profiles/default) error = %v", err)
	}
	if profileRecord.Enabled {
		t.Fatalf("lan_core profiles/default enabled = true, want false after vmbr teardown")
	}
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if planRecord.Enabled || !strings.Contains(planRecord.DataJSON, `"enabled":false`) {
		t.Fatalf("lan_core egress_nat_plans/default = %+v, want disabled plan after vmbr teardown", planRecord)
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("lan_core status/default enabled = true, want false after vmbr teardown")
	}
	for _, want := range []string{`"phase":"deleted"`, `"bridge":"vmbr0"`, `"bridge_preserved":true`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if strings.Contains(statusRecord.DataJSON, `"last_error"`) {
		t.Fatalf("lan_core status/default = %s, want no last_error for preserved vmbr teardown", statusRecord.DataJSON)
	}
}

func TestExampleLANCoreTeardownPreservesExistingVMBridgeMember(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "profiles")
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	profileJSON := `{"bridge":"vmbr0","ports":["lanp0"],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON:   profileJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profiles/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		links: map[string]pluginControlNetLinkInfo{
			"vmbr0": {Name: "vmbr0", IfIndex: 201, Kind: "bridge", MTU: 1500, MAC: "02:00:00:00:20:01", Up: true},
			"lanp0": {Name: "lanp0", IfIndex: 202, Kind: "device", MTU: 1500, MAC: "02:00:00:00:20:02", Up: true,
				MasterName: "vmbr0", MasterIfIndex: 201},
		},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(profileJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core existing vmbr member) error = %v", err)
	}
	if containsString(controller.calls, "setMaster:lanp0:vmbr0:true") {
		t.Fatalf("net admin calls = %+v, want no setMaster for pre-existing vmbr member", controller.calls)
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) apply error = %v", err)
	}
	if !strings.Contains(statusRecord.DataJSON, `"managed_ports":[]`) {
		t.Fatalf("lan_core status/default = %s, want no managed ports for pre-existing vmbr member", statusRecord.DataJSON)
	}

	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
	}
	if containsString(controller.calls, "clearMaster:lanp0") {
		t.Fatalf("net admin calls = %+v, want pre-existing vmbr member preserved", controller.calls)
	}
	if !containsString(controller.calls, "addrDelete:vmbr0:192.168.100.1/24") {
		t.Fatalf("net admin calls = %+v, missing managed vmbr address cleanup", controller.calls)
	}
	if containsString(controller.calls, "delete:vmbr0") {
		t.Fatalf("net admin calls = %+v, want vmbr0 preserved", controller.calls)
	}
}

func TestExampleLANCoreTeardownDisablesProfileWhenPortDetachFails(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "lan_core")
	rootDir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	profileJSON := `{"bridge":"brlan0","ports":["lanp0","lanp1"],"addresses":["192.168.100.1/24"],"wan_egress_interface":"fwdwan0","auto_egress_nat":true}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON:   profileJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profiles/default) error = %v", err)
	}
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "egress_nat_plans",
		RecordKey:  "default",
		DataJSON:   `{"enabled":true,"parent_interface":"brlan0","out_interface":"fwdwan0"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "status",
		RecordKey:  "default",
		DataJSON:   `{"phase":"applied","bridge":"brlan0","bridge_created":true,"bridge_addresses":["192.168.100.1/24"],"managed_ports":["lanp0","lanp1"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core status/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		clearMasterErrors: map[string]error{"lanp1": fmt.Errorf("link not found")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
	}
	for _, want := range []string{"clearMaster:lanp0", "clearMaster:lanp1", "delete:brlan0"} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	profileRecord, err := store.GetPluginRecord(db, "lan_core", "profiles", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core profiles/default) error = %v", err)
	}
	if profileRecord.Enabled {
		t.Fatalf("lan_core profiles/default enabled = true, want false after partial teardown")
	}
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if planRecord.Enabled || !strings.Contains(planRecord.DataJSON, `"enabled":false`) {
		t.Fatalf("lan_core egress_nat_plans/default = %+v, want disabled plan after partial teardown", planRecord)
	}
	statusRecord, err := store.GetPluginRecord(db, "lan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("lan_core status/default enabled = true, want false after partial teardown")
	}
	for _, want := range []string{`"phase":"delete_partial"`, `"failed_ports":[`, `"name":"lanp1"`, `"last_error":"failed to detach 1 LAN port(s)"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("lan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestPluginEgressNATPlanAppearsInEffectiveEgressNATItems(t *testing.T) {
	pluginsDir := t.TempDir()
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "lan_core"), filepath.Join(pluginsDir, "lan_core"))
	cfg := &Config{PluginsDir: pluginsDir}
	db := openTestDB(t)
	insertPluginEgressNATPlanForTest(t, db, "lan_core", "default", `{
	  "enabled":true,
	  "parent_interface":"brlan0",
	  "out_interface":"fwdwan0",
	  "out_source_ip":"198.51.100.2",
	  "protocol":"tcp+udp",
	  "nat_type":"full_cone",
	  "redirect_mode":"raw_l2"
	}`, true)

	items, err := loadEffectiveEnabledEgressNATItems(db, cfg)
	if err != nil {
		t.Fatalf("loadEffectiveEnabledEgressNATItems() error = %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("effective egress nats = %+v, want one plugin plan", items)
	}
	item := items[0]
	if item.ID >= 0 {
		t.Fatalf("plugin egress nat id = %d, want synthetic negative id", item.ID)
	}
	if item.ParentInterface != "brlan0" || item.OutInterface != "fwdwan0" || item.OutSourceIP != "198.51.100.2" || item.Protocol != "tcp+udp" || item.NATType != egressNATTypeFullCone || item.RedirectMode != egressNATRedirectModePreparedL2 || !item.Enabled {
		t.Fatalf("plugin egress nat = %+v, want normalized lan_core plan", item)
	}

	explicitID, err := dbAddEgressNAT(db, &EgressNAT{
		ParentInterface: "brlan1",
		OutInterface:    "fwdwan0",
		Protocol:        "udp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}

	meta, err := loadEffectiveEgressNATMetaByIDs(db, []int64{explicitID, item.ID}, cfg)
	if err != nil {
		t.Fatalf("loadEffectiveEgressNATMetaByIDs() error = %v", err)
	}
	if got := meta[explicitID]; got.ParentInterface != "brlan1" || got.OutInterface != "fwdwan0" {
		t.Fatalf("effective meta[%d] = %+v, want explicit egress nat metadata", explicitID, got)
	}
	if got := meta[item.ID]; got.ParentInterface != "brlan0" || got.OutInterface != "fwdwan0" {
		t.Fatalf("effective meta[%d] = %+v, want plugin egress nat metadata", item.ID, got)
	}
	protocols, err := loadEffectiveEgressNATProtocolByIDs(db, []int64{explicitID, item.ID}, cfg)
	if err != nil {
		t.Fatalf("loadEffectiveEgressNATProtocolByIDs() error = %v", err)
	}
	if protocols[explicitID] != "udp" {
		t.Fatalf("effective protocol[%d] = %q, want udp", explicitID, protocols[explicitID])
	}
	if protocols[item.ID] != "tcp+udp" {
		t.Fatalf("effective protocol[%d] = %q, want tcp+udp", item.ID, protocols[item.ID])
	}
}

func TestPluginEgressNATPlanRequiresActivePluginAndNoOverlap(t *testing.T) {
	pluginsDir := t.TempDir()
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "lan_core"), filepath.Join(pluginsDir, "lan_core"))
	cfg := &Config{PluginsDir: pluginsDir}
	disabled := false
	db := openTestDB(t)
	insertPluginEgressNATPlanForTest(t, db, "lan_core", "default", `{
	  "enabled":true,
	  "parent_interface":"brlan0",
	  "out_interface":"fwdwan0",
	  "protocol":"tcp+udp"
	}`, true)

	items, err := loadEffectiveEnabledEgressNATItems(db, &Config{PluginsDir: pluginsDir, PluginsEnabledSetting: &disabled})
	if err != nil {
		t.Fatalf("loadEffectiveEnabledEgressNATItems(disabled plugins) error = %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("effective egress nats with plugins disabled = %+v, want none", items)
	}

	enabled := true
	if err := store.SetPluginEnabled(db, "lan_core", false); err != nil {
		t.Fatalf("SetPluginEnabled(lan_core false) error = %v", err)
	}
	items, err = loadEffectiveEnabledEgressNATItems(db, &Config{PluginsDir: pluginsDir, PluginsEnabledSetting: &enabled})
	if err != nil {
		t.Fatalf("loadEffectiveEnabledEgressNATItems(disabled plugin state) error = %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("effective egress nats with plugin state disabled = %+v, want none", items)
	}
	if err := store.SetPluginEnabled(db, "lan_core", true); err != nil {
		t.Fatalf("SetPluginEnabled(lan_core true) error = %v", err)
	}

	explicit := EgressNAT{
		ParentInterface: "brlan0",
		OutInterface:    "fwdwan0",
		Protocol:        "tcp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         true,
	}
	id, err := dbAddEgressNAT(db, &explicit)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}
	items, err = loadEffectiveEnabledEgressNATItems(db, cfg)
	if err != nil {
		t.Fatalf("loadEffectiveEnabledEgressNATItems(overlap) error = %v", err)
	}
	if len(items) != 1 || items[0].ID != id {
		t.Fatalf("effective egress nats with overlap = %+v, want explicit nat %d only", items, id)
	}
}

func TestPluginEgressNATPlanAllowsLabPluginByDefault(t *testing.T) {
	pluginsDir := t.TempDir()
	writeTestPlugin(t, pluginsDir, "lab_router", `{
  "api_version": "v1",
  "id": "lab_router",
  "name": "Lab Router",
  "version": "0.1.0",
  "stability": "lab",
  "resources": [{
    "id": "egress_nat_plans",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual"
  }]
}`)
	db := openTestDB(t)
	insertPluginEgressNATPlanForTest(t, db, "lab_router", "default", `{
	  "enabled":true,
	  "parent_interface":"brlab0",
	  "out_interface":"fwdwan0",
	  "protocol":"tcp+udp"
	}`, true)

	items, err := loadEffectiveEnabledEgressNATItems(db, &Config{PluginsDir: pluginsDir})
	if err != nil {
		t.Fatalf("loadEffectiveEnabledEgressNATItems(default lab) error = %v", err)
	}
	if len(items) != 1 || items[0].ParentInterface != "brlab0" {
		t.Fatalf("effective egress nats with default lab plugin = %+v, want lab plan", items)
	}
}

func TestLANCoreActionRedistributesPluginEgressNATPlanToKernelRuntime(t *testing.T) {
	pluginsDir := t.TempDir()
	rootDir := filepath.Join(pluginsDir, "lan_core")
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "lan_core"), rootDir)
	plugin, err := loadPluginFromDir(rootDir, "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "apply_network" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("apply_network action not found in %+v", plugin.Actions)
	}

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "brlan0", Kind: "bridge"},
			{Name: "lanp0", Parent: "brlan0", Kind: "tuntap"},
			{Name: "lanp1", Parent: "brlan0", Kind: "tuntap"},
			{Name: "fwdwan0", Kind: "device", Addrs: []string{"198.51.100.2"}},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	db := openTestDB(t)
	cfg := &Config{
		PluginsDir:    pluginsDir,
		DefaultEngine: ruleEngineKernel,
	}
	kernelRuntime := &pluginRuntimeApplyTestRuntime{kernelSupported: true}
	pm := &ProcessManager{
		ruleWorkers:                          make(map[int]*WorkerInfo),
		rangeWorkers:                         make(map[int]*WorkerInfo),
		db:                                   db,
		cfg:                                  cfg,
		rulePlans:                            make(map[int64]ruleDataplanePlan),
		rangePlans:                           make(map[int64]rangeDataplanePlan),
		egressNATPlans:                       make(map[int64]ruleDataplanePlan),
		dynamicEgressNATParents:              make(map[string]struct{}),
		managedNetworkInterfaces:             make(map[string]struct{}),
		ipv6AssignmentInterfaces:             make(map[string]struct{}),
		kernelRuntime:                        kernelRuntime,
		kernelRules:                          make(map[int64]bool),
		kernelRanges:                         make(map[int64]bool),
		kernelEgressNATs:                     make(map[int64]bool),
		kernelRuleEngines:                    make(map[int64]string),
		kernelRangeEngines:                   make(map[int64]string),
		kernelEgressNATEngines:               make(map[int64]string),
		kernelFlowOwners:                     make(map[uint32]kernelCandidateOwner),
		kernelRuleStats:                      make(map[int64]RuleStatsReport),
		kernelRangeStats:                     make(map[int64]RangeStatsReport),
		kernelEgressNATStats:                 make(map[int64]EgressNATStatsReport),
		kernelStatsSnapshot:                  emptyKernelRuleStatsSnapshot(),
		kernelNetlinkOwnerRetryCooldownUntil: make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState),
		kernelNetlinkOwnerRetryFailures:      make(map[kernelCandidateOwner]int),
	}
	controlRuntime := newPluginControlRuntime(db, cfg, pm).(*gojaPluginControlRuntime)
	controlRuntime.netAdmin = &pluginControlNetAdminTest{}
	pm.pluginControlRuntime = controlRuntime
	t.Cleanup(func() { _ = controlRuntime.Close() })

	payload := json.RawMessage(`{
	  "lan_id":"default",
	  "bridge":"brlan0",
	  "ports":["lanp0","lanp1"],
	  "addresses":["192.168.100.1/24"],
	  "wan_egress_interface":"fwdwan0",
	  "wan_egress_source_ip":"198.51.100.2",
	  "auto_egress_nat":true
	}`)
	if err := applyPluginActionRuntimeUpdate(db, pm, plugin, action, payload); err != nil {
		t.Fatalf("applyPluginActionRuntimeUpdate(lan_core apply_network) error = %v", err)
	}
	if len(kernelRuntime.lastRules) != 4 {
		t.Fatalf("kernel runtime rules = %+v, want 4 egress nat synthetic rules", kernelRuntime.lastRules)
	}
	for _, rule := range kernelRuntime.lastRules {
		if !isKernelEgressNATRule(rule) {
			t.Fatalf("kernel runtime rule = %+v, want egress nat synthetic rule", rule)
		}
		if rule.OutInterface != "fwdwan0" || rule.OutSourceIP != "198.51.100.2" {
			t.Fatalf("kernel runtime rule = %+v, want fwdwan0 source 198.51.100.2", rule)
		}
	}
	pm.mu.Lock()
	egressNATPlans := cloneRuleDataplanePlans(pm.egressNATPlans)
	kernelEgressNATs := cloneKernelOwnerMap(pm.kernelEgressNATs)
	pm.mu.Unlock()
	if len(egressNATPlans) != 1 || len(kernelEgressNATs) != 1 {
		t.Fatalf("pm egress nat state plans=%+v kernel=%+v, want one active plugin egress nat", egressNATPlans, kernelEgressNATs)
	}
	for id, plan := range egressNATPlans {
		if id >= 0 || plan.EffectiveEngine != ruleEngineKernel || !plan.KernelEligible {
			t.Fatalf("plugin egress nat plan[%d] = %+v, want active synthetic kernel plan", id, plan)
		}
		if !kernelEgressNATs[id] {
			t.Fatalf("kernelEgressNATs = %+v, missing synthetic owner %d", kernelEgressNATs, id)
		}
	}
}

func TestPluginReconcileRedistributesGeneratedEgressNATPlans(t *testing.T) {
	pluginsDir := t.TempDir()
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "lan_core"), filepath.Join(pluginsDir, "lan_core"))

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "brlan0", Kind: "bridge"},
			{Name: "lanp0", Parent: "brlan0", Kind: "tuntap"},
			{Name: "fwdwan0", Kind: "device", Addrs: []string{"198.51.100.2"}},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON: `{
		  "bridge":"brlan0",
		  "ports":["lanp0"],
		  "addresses":["192.168.100.1/24"],
		  "wan_egress_interface":"fwdwan0",
		  "wan_egress_source_ip":"198.51.100.2",
		  "auto_egress_nat":true
		}`,
		Enabled: true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profile) error = %v", err)
	}

	cfg := &Config{
		PluginsDir:    pluginsDir,
		DefaultEngine: ruleEngineKernel,
	}
	kernelRuntime := &pluginRuntimeApplyTestRuntime{kernelSupported: true}
	pm := &ProcessManager{
		ruleWorkers:                          make(map[int]*WorkerInfo),
		rangeWorkers:                         make(map[int]*WorkerInfo),
		db:                                   db,
		cfg:                                  cfg,
		rulePlans:                            make(map[int64]ruleDataplanePlan),
		rangePlans:                           make(map[int64]rangeDataplanePlan),
		egressNATPlans:                       make(map[int64]ruleDataplanePlan),
		dynamicEgressNATParents:              make(map[string]struct{}),
		managedNetworkInterfaces:             make(map[string]struct{}),
		ipv6AssignmentInterfaces:             make(map[string]struct{}),
		kernelRuntime:                        kernelRuntime,
		kernelRules:                          make(map[int64]bool),
		kernelRanges:                         make(map[int64]bool),
		kernelEgressNATs:                     make(map[int64]bool),
		kernelRuleEngines:                    make(map[int64]string),
		kernelRangeEngines:                   make(map[int64]string),
		kernelEgressNATEngines:               make(map[int64]string),
		kernelFlowOwners:                     make(map[uint32]kernelCandidateOwner),
		kernelRuleStats:                      make(map[int64]RuleStatsReport),
		kernelRangeStats:                     make(map[int64]RangeStatsReport),
		kernelEgressNATStats:                 make(map[int64]EgressNATStatsReport),
		kernelStatsSnapshot:                  emptyKernelRuleStatsSnapshot(),
		kernelNetlinkOwnerRetryCooldownUntil: make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState),
		kernelNetlinkOwnerRetryFailures:      make(map[kernelCandidateOwner]int),
	}
	controlRuntime := newPluginControlRuntime(db, cfg, pm).(*gojaPluginControlRuntime)
	controlRuntime.netAdmin = &pluginControlNetAdminTest{}
	pm.pluginControlRuntime = controlRuntime
	t.Cleanup(func() { _ = controlRuntime.Close() })

	pm.reconcilePluginsForRuntime()

	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) error = %v", err)
	}
	if !planRecord.Enabled || !strings.Contains(planRecord.DataJSON, `"out_interface":"fwdwan0"`) {
		t.Fatalf("lan_core egress_nat_plans/default = %+v, want enabled fwdwan0 plan", planRecord)
	}
	if len(kernelRuntime.lastRules) != 2 {
		t.Fatalf("kernel runtime rules = %+v, want 2 egress nat synthetic rules from reconcile", kernelRuntime.lastRules)
	}
	for _, rule := range kernelRuntime.lastRules {
		if !isKernelEgressNATRule(rule) || rule.OutInterface != "fwdwan0" {
			t.Fatalf("kernel runtime rule = %+v, want fwdwan0 egress nat synthetic rule", rule)
		}
	}
}

func TestLANCoreRepairTimerRedistributesWANCoreStatusChanges(t *testing.T) {
	pluginsDir := t.TempDir()
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "lan_core"), filepath.Join(pluginsDir, "lan_core"))
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "wan_core"), filepath.Join(pluginsDir, "wan_core"))

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "brlan0", Kind: "bridge"},
			{Name: "lanp0", Parent: "brlan0", Kind: "tuntap"},
			{Name: "fwdwan0", Kind: "device", Addrs: []string{"198.51.100.2"}},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: "profiles",
		RecordKey:  "default",
		DataJSON: `{
		  "bridge":"brlan0",
		  "ports":["lanp0"],
		  "addresses":["192.168.100.1/24"],
		  "wan_ref":"default",
		  "auto_egress_nat":true
		}`,
		Enabled: true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(lan_core profile) error = %v", err)
	}
	wanStatus := store.PluginRecord{
		PluginID:   "wan_core",
		ResourceID: "status",
		RecordKey:  "default",
		DataJSON: `{
		  "phase":"applied",
		  "egress_nat_parent_interface":"fwdwan0",
		  "forward_parent_interface":"fwdwan0",
		  "ipv4":"198.51.100.2"
		}`,
		Enabled: true,
	}
	if _, err := store.AddPluginRecord(db, &wanStatus); err != nil {
		t.Fatalf("AddPluginRecord(wan_core status) error = %v", err)
	}

	cfg := &Config{
		PluginsDir:    pluginsDir,
		DefaultEngine: ruleEngineKernel,
	}
	kernelRuntime := &pluginRuntimeApplyTestRuntime{kernelSupported: true}
	pm := &ProcessManager{
		ruleWorkers:                          make(map[int]*WorkerInfo),
		rangeWorkers:                         make(map[int]*WorkerInfo),
		db:                                   db,
		cfg:                                  cfg,
		rulePlans:                            make(map[int64]ruleDataplanePlan),
		rangePlans:                           make(map[int64]rangeDataplanePlan),
		egressNATPlans:                       make(map[int64]ruleDataplanePlan),
		dynamicEgressNATParents:              make(map[string]struct{}),
		managedNetworkInterfaces:             make(map[string]struct{}),
		ipv6AssignmentInterfaces:             make(map[string]struct{}),
		kernelRuntime:                        kernelRuntime,
		kernelRules:                          make(map[int64]bool),
		kernelRanges:                         make(map[int64]bool),
		kernelEgressNATs:                     make(map[int64]bool),
		kernelRuleEngines:                    make(map[int64]string),
		kernelRangeEngines:                   make(map[int64]string),
		kernelEgressNATEngines:               make(map[int64]string),
		kernelFlowOwners:                     make(map[uint32]kernelCandidateOwner),
		kernelRuleStats:                      make(map[int64]RuleStatsReport),
		kernelRangeStats:                     make(map[int64]RangeStatsReport),
		kernelEgressNATStats:                 make(map[int64]EgressNATStatsReport),
		kernelStatsSnapshot:                  emptyKernelRuleStatsSnapshot(),
		kernelNetlinkOwnerRetryCooldownUntil: make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState),
		kernelNetlinkOwnerRetryFailures:      make(map[kernelCandidateOwner]int),
	}
	controlRuntime := newPluginControlRuntime(db, cfg, pm).(*gojaPluginControlRuntime)
	controlRuntime.netAdmin = &pluginControlNetAdminTest{}
	pm.pluginControlRuntime = controlRuntime
	t.Cleanup(func() { _ = controlRuntime.Close() })

	pm.reconcilePluginsForRuntime()
	if len(kernelRuntime.lastRules) != 2 {
		t.Fatalf("kernel runtime rules after initial reconcile = %+v, want 2 synthetic egress nat rules", kernelRuntime.lastRules)
	}
	for _, rule := range kernelRuntime.lastRules {
		if !isKernelEgressNATRule(rule) || rule.OutInterface != "fwdwan0" {
			t.Fatalf("kernel runtime initial rule = %+v, want fwdwan0 egress nat synthetic rule", rule)
		}
	}
	if timers := controlRuntime.pluginTimerList("lan_core"); len(timers) != 1 {
		t.Fatalf("lan_core timers after initial reconcile = %+v, want repair timer", timers)
	}

	wanStatus.Enabled = false
	if err := store.UpdatePluginRecord(db, &wanStatus); err != nil {
		t.Fatalf("disable wan_core status: %v", err)
	}
	firePluginTimerForTest(t, controlRuntime, "lan_core", "lan_repair")
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) disabled error = %v", err)
	}
	if planRecord.Enabled || !strings.Contains(planRecord.DataJSON, `"enabled":false`) {
		t.Fatalf("lan_core egress_nat_plans/default after WAN down = %+v, want disabled fail-closed plan", planRecord)
	}
	if len(kernelRuntime.lastRules) != 0 {
		t.Fatalf("kernel runtime rules after WAN status disabled = %+v, want no synthetic egress nat rules", kernelRuntime.lastRules)
	}

	wanStatus.Enabled = true
	if err := store.UpdatePluginRecord(db, &wanStatus); err != nil {
		t.Fatalf("restore wan_core status: %v", err)
	}
	firePluginTimerForTest(t, controlRuntime, "lan_core", "lan_repair")
	planRecord, err = store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/default) restored error = %v", err)
	}
	if !planRecord.Enabled || !strings.Contains(planRecord.DataJSON, `"out_interface":"fwdwan0"`) {
		t.Fatalf("lan_core egress_nat_plans/default after WAN restore = %+v, want enabled fwdwan0 plan", planRecord)
	}
	if len(kernelRuntime.lastRules) != 2 {
		t.Fatalf("kernel runtime rules after WAN status restore = %+v, want 2 synthetic egress nat rules", kernelRuntime.lastRules)
	}
}

func TestExampleWANCoreApplySessionCreatesForwardCoreHandoff(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "apply_session" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("apply_session action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{
	  "wan_id":"default",
	  "driver":"external",
	  "driver_plugin":"wan_driver",
	  "state":"up",
	  "usable":true,
	  "real_interface":"eth0",
	  "wan_interface":"eth0",
	  "mtu":1492,
	  "ipv4":"10.0.0.2",
	  "ipv4_peer":"10.0.0.1",
	  "ipv6_link_local":"fe80::1",
	  "ipv6_peer_link_local":"fe80::2",
	  "pd_prefix":"2001:db8:1234::/56",
	  "dns_servers":["223.5.5.5"],
	  "host_interface":"fwdlocal0",
	  "vtap_interface":"fwdvtap0",
	  "host_addresses":["169.254.253.1/30"],
	  "vtap_addresses":["169.254.253.2/30"],
	  "routes":[{"dst":"0.0.0.0/0","dev":"fwdlocal0","gateway":"10.0.0.1","table":100,"metric":10}]
	}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core apply_session) error = %v", err)
	}
	sessionRecord, err := store.GetPluginRecord(db, "wan_core", "sessions", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core sessions/default) error = %v", err)
	}
	if !sessionRecord.Enabled {
		t.Fatalf("wan_core sessions/default Enabled = false, want true after action apply")
	}
	profileRecord, err := store.GetPluginRecord(db, "wan_core", "profiles", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core profiles/default) error = %v", err)
	}
	if !profileRecord.Enabled {
		t.Fatalf("wan_core profiles/default Enabled = false, want true after action apply")
	}
	for _, want := range []string{
		"ensureVeth:fwdlocal0:fwdvtap0:1492:true",
		"addrReplace:fwdlocal0:169.254.253.1/30",
		"addrReplace:fwdlocal0:10.0.0.2/32",
		"addrReplace:fwdvtap0:169.254.253.2/30",
		"routeReplace:0.0.0.0/0:fwdlocal0:10.0.0.1:100:10",
	} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	record, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"driver":"external"`, `"parent_interface":"fwdlocal0"`, `"egress_nat_parent_interface":"fwdlocal0"`, `"egress_nat_redirect_mode":"prepared_l2"`, `"pd_prefix":"2001:db8:1234::/56"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", record.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 1 || timers[0]["name"] != "wan_repair" {
		t.Fatalf("wan_core timers after action apply = %+v, want wan_repair interval", timers)
	}
}

func TestExampleWANCoreResourceApplyArmsRepairTimer(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	records := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "wan_id":"default",
		  "state":"up",
		  "usable":true,
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0"
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	timers := rt.pluginTimerList("wan_core")
	if len(timers) != 1 || timers[0]["name"] != "wan_repair" || timers[0]["kind"] != pluginControlTimerKindInterval {
		t.Fatalf("wan_core timers = %+v, want wan_repair interval", timers)
	}
}

func TestExampleWANCoreResourceApplyIsolatesInvalidSession(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	records := []PluginResourceRecord{
		{
			Key:     "bad",
			Enabled: true,
			Data:    json.RawMessage(`{"state":"up","usable":true,"host_interface":"this-interface-name-is-too-long","vtap_interface":"fwdvtap0"}`),
		},
		{
			Key:     "good",
			Enabled: true,
			Data:    json.RawMessage(`{"state":"up","usable":true,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
		},
	}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err == nil || !strings.Contains(err.Error(), "failed to apply 1 WAN session record") {
		t.Fatalf("ApplyPluginResourceData(wan_core sessions) error = %v, want partial apply error", err)
	}
	badStatus, err := store.GetPluginRecord(db, "wan_core", "status", "bad")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/bad) error = %v", err)
	}
	for _, want := range []string{`"phase":"error"`, `"wan_id":"bad"`, `"last_error":`} {
		if !strings.Contains(badStatus.DataJSON, want) {
			t.Fatalf("wan_core status/bad = %s, missing %s", badStatus.DataJSON, want)
		}
	}
	goodStatus, err := store.GetPluginRecord(db, "wan_core", "status", "good")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/good) error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"wan_id":"good"`, `"host_interface":"fwdlocal0"`, `"vtap_interface":"fwdvtap0"`} {
		if !strings.Contains(goodStatus.DataJSON, want) {
			t.Fatalf("wan_core status/good = %s, missing %s", goodStatus.DataJSON, want)
		}
	}
}

func TestExampleWANCoreDisabledSessionResourceDisablesStatus(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "wan_core",
		ResourceID: "status",
		RecordKey:  "default",
		DataJSON:   `{"phase":"applied","egress_nat_parent_interface":"fwdvtap0","forward_core":{"parent_interface":"fwdvtap0"}}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(wan_core status/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: false,
		Data:    json.RawMessage(`{"state":"down","usable":false,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core disabled session) error = %v", err)
	}
	statusRecord, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("wan_core status/default enabled = true, want false after disabled session apply")
	}
	for _, want := range []string{`"phase":"disabled"`, `"usable":false`, `"host_interface":"fwdlocal0"`, `"vtap_interface":"fwdvtap0"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 0 {
		t.Fatalf("wan_core timers after disabled session apply = %+v, want none", timers)
	}
}

func TestExampleWANCoreDisabledSessionKeepsRepairTimerForOtherEnabledSessions(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "wan_core",
		ResourceID: "sessions",
		RecordKey:  "other",
		DataJSON:   `{"state":"up","usable":true,"host_interface":"fwdlocal1","vtap_interface":"fwdvtap1"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(wan_core sessions/other) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: false,
		Data:    json.RawMessage(`{"state":"down","usable":false,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core disabled session with other enabled) error = %v", err)
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 1 || timers[0]["name"] != "wan_repair" {
		t.Fatalf("wan_core timers after disabling one of multiple sessions = %+v, want wan_repair", timers)
	}
}

func TestExampleWANCoreUnusableSessionDisablesPublishedStatus(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(`{"state":"down","usable":false,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core unusable session) error = %v", err)
	}
	statusRecord, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("wan_core status/default enabled = true, want false for unusable session")
	}
	for _, want := range []string{`"phase":"skipped"`, `"reason":"wan session is not usable"`, `"usable":false`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleWANCoreRepairTimerRecoversVethFailure(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	sessionJSON := `{"wan_id":"default","state":"up","usable":true,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0","host_addresses":["169.254.253.1/30"],"vtap_addresses":["169.254.253.2/30"],"routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "wan_core",
		ResourceID: "sessions",
		RecordKey:  "default",
		DataJSON:   sessionJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(wan_core sessions/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		ensureVethErrors: map[string]error{"fwdlocal0": fmt.Errorf("temporary veth create failure")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(sessionJSON),
	}}); err == nil || !strings.Contains(err.Error(), "failed to apply 1 WAN session record") {
		t.Fatalf("ApplyPluginResourceData(wan_core sessions) error = %v, want temporary failure", err)
	}
	statusRecord, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) failed apply error = %v", err)
	}
	for _, want := range []string{`"phase":"error"`, `"last_error":"net.link.ensureVeth: temporary veth create failure"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core failed status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if err := store.MarkPluginRuntimeError(db, "wan_core", "resource", "sessions", "api apply failed"); err != nil {
		t.Fatalf("MarkPluginRuntimeError(wan_core sessions) error = %v", err)
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 1 {
		t.Fatalf("wan_core timers after failed apply = %+v, want one repair timer", timers)
	}

	controller.ensureVethErrors = nil
	firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
	statusRecord, err = store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) recovered error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"host_interface":"fwdlocal0"`, `"vtap_interface":"fwdvtap0"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core recovered status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	runtimeStatus, err := store.PluginRuntimeStatusOrNil(db, "wan_core", "resource", "sessions")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(wan_core sessions) error = %v", err)
	}
	if runtimeStatus == nil || runtimeStatus.Status != "applied" || runtimeStatus.LastError != "" || runtimeStatus.AppliedRevision != runtimeStatus.Revision {
		t.Fatalf("wan_core sessions runtime status after repair = %+v, want applied with cleared error", runtimeStatus)
	}
}

func TestExampleWANCoreTeardownDisablesSessionAndRepairTimer(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	sessionJSON := `{"wan_id":"default","state":"up","usable":true,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "wan_core",
		ResourceID: "sessions",
		RecordKey:  "default",
		DataJSON:   sessionJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(wan_core sessions/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(sessionJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 1 {
		t.Fatalf("wan_core timers before teardown = %+v, want one repair timer", timers)
	}
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core teardown) error = %v", err)
	}
	sessionRecord, err := store.GetPluginRecord(db, "wan_core", "sessions", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core sessions/default) error = %v", err)
	}
	if sessionRecord.Enabled {
		t.Fatalf("wan_core sessions/default enabled = true, want false after teardown")
	}
	statusRecord, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("wan_core status/default enabled = true, want false after teardown")
	}
	for _, want := range []string{`"phase":"deleted"`, `"managed_link":true`, `"link_delete_skipped":false`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 0 {
		t.Fatalf("wan_core timers after teardown = %+v, want none", timers)
	}

	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("second ApplyPluginAction(wan_core teardown) error = %v", err)
	}
	if containsString(controller.calls, "delete:fwdlocal0") {
		t.Fatalf("net admin calls after repeated teardown = %+v, want no second physical delete", controller.calls)
	}
	statusRecord, err = store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) after repeated teardown error = %v", err)
	}
	for _, want := range []string{`"phase":"deleted"`, `"managed_link":true`, `"link_delete_skipped":true`, `"link_delete_skip_reason":"previous wan_core status already deleted this plugin-managed veth pair"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core status/default after repeated teardown = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleWANCoreTeardownDisablesSessionWhenDeleteFails(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	sessionJSON := `{"wan_id":"default","state":"up","usable":true,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0","host_addresses":["169.254.253.1/30"],"vtap_addresses":["169.254.253.2/30"],"routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "wan_core",
		ResourceID: "sessions",
		RecordKey:  "default",
		DataJSON:   sessionJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(wan_core sessions/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		deleteErrors: map[string]error{"fwdlocal0": fmt.Errorf("operation not permitted")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(sessionJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 1 {
		t.Fatalf("wan_core timers before teardown = %+v, want one repair timer", timers)
	}
	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core teardown) error = %v", err)
	}
	for _, want := range []string{
		"addrDelete:fwdlocal0:169.254.253.1/30",
		"addrDelete:fwdvtap0:169.254.253.2/30",
		"routeDelete:0.0.0.0/0:fwdlocal0:169.254.253.2:0:0",
		"delete:fwdlocal0",
	} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	sessionRecord, err := store.GetPluginRecord(db, "wan_core", "sessions", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core sessions/default) error = %v", err)
	}
	if sessionRecord.Enabled {
		t.Fatalf("wan_core sessions/default enabled = true, want false after failed physical delete")
	}
	statusRecord, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("wan_core status/default enabled = true, want false after failed physical delete")
	}
	for _, want := range []string{`"phase":"delete_failed"`, `"last_error":"net.link.delete: operation not permitted"`, `"host_interface":"fwdlocal0"`, `"managed_link":true`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 0 {
		t.Fatalf("wan_core timers after failed physical delete = %+v, want none", timers)
	}
}

func TestExampleWANCoreTeardownWithoutStatusDoesNotDeleteLinkOrManagedState(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	sessionJSON := `{"wan_id":"default","state":"up","usable":true,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0","host_addresses":["169.254.253.1/30"],"vtap_addresses":["169.254.253.2/30"],"routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "wan_core",
		ResourceID: "sessions",
		RecordKey:  "default",
		DataJSON:   sessionJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(wan_core sessions/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core teardown without status) error = %v", err)
	}
	for _, forbidden := range []string{
		"addrDelete:fwdlocal0:169.254.253.1/30",
		"addrDelete:fwdvtap0:169.254.253.2/30",
		"routeDelete:0.0.0.0/0:fwdlocal0:169.254.253.2:0:0",
		"delete:fwdlocal0",
	} {
		if containsString(controller.calls, forbidden) {
			t.Fatalf("net admin calls = %+v, want no unmanaged teardown call %s without prior status", controller.calls, forbidden)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"phase":"deleted"`, `"managed_link":false`, `"link_delete_skipped":true`, `"link_delete_skip_reason":"no previous wan_core status proves this veth pair was plugin-managed"`, `"cleanup_errors":[]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleWANCoreResourceApplySkipsUnchangedStatusRewrite(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	records := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(`{"state":"up","usable":true,"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err != nil {
		t.Fatalf("first ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	first, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) first error = %v", err)
	}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err != nil {
		t.Fatalf("second ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	second, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) second error = %v", err)
	}
	if second.Revision != first.Revision {
		t.Fatalf("wan_core status revision changed from %d to %d for unchanged apply\nfirst=%s\nsecond=%s", first.Revision, second.Revision, first.DataJSON, second.DataJSON)
	}
}

func TestExampleWANCoreResourceApplyDeletesRemovedManagedAddressAndRoute(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	first := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "state":"up",
		  "usable":true,
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0",
		  "host_addresses":["169.254.253.1/30","169.254.253.5/30"],
		  "vtap_addresses":["169.254.253.2/30"],
		  "routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, first); err != nil {
		t.Fatalf("first ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}

	controller.calls = nil
	second := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "state":"up",
		  "usable":true,
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0",
		  "host_addresses":["169.254.253.1/30"],
		  "vtap_addresses":[],
		  "routes":[]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, second); err != nil {
		t.Fatalf("second ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	for _, want := range []string{
		"addrDelete:fwdlocal0:169.254.253.5/30",
		"addrDelete:fwdvtap0:169.254.253.2/30",
		"routeDelete:0.0.0.0/0:fwdlocal0:169.254.253.2:0:0",
	} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"cleanup_errors":[]`, `"host_addresses":["169.254.253.1/30"]`, `"routes":[]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleWANCoreResourceApplyDeletesManagedVethWhenInterfaceChanges(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "wan_core")
	rootDir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "sessions")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	first := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "state":"up",
		  "usable":true,
		  "host_interface":"fwdold0",
		  "vtap_interface":"fwdoldtap0",
		  "host_addresses":["169.254.253.1/30"],
		  "vtap_addresses":["169.254.253.2/30"]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, first); err != nil {
		t.Fatalf("first ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}

	controller.calls = nil
	second := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "state":"up",
		  "usable":true,
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0",
		  "host_addresses":["169.254.253.1/30"],
		  "vtap_addresses":["169.254.253.2/30"]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, second); err != nil {
		t.Fatalf("second ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	for _, want := range []string{"delete:fwdold0"} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	for _, forbidden := range []string{
		"addrDelete:fwdold0:169.254.253.1/30",
		"addrDelete:fwdoldtap0:169.254.253.2/30",
	} {
		if containsString(controller.calls, forbidden) {
			t.Fatalf("net admin calls = %+v, want old veth delete instead of stale cleanup call %s", controller.calls, forbidden)
		}
	}
}

func TestExampleVToLocalResourceApplyArmsRepairTimer(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	records := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "profile_key":"default",
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0"
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err != nil {
		t.Fatalf("ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	timers := rt.pluginTimerList("vtolocal")
	if len(timers) != 1 || timers[0]["name"] != "vtolocal_repair" || timers[0]["kind"] != pluginControlTimerKindInterval {
		t.Fatalf("vtolocal timers = %+v, want vtolocal_repair interval", timers)
	}
}

func TestExampleVToLocalResourceApplyIsolatesInvalidLink(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	records := []PluginResourceRecord{
		{
			Key:     "bad",
			Enabled: true,
			Data:    json.RawMessage(`{"host_interface":"this-interface-name-is-too-long","vtap_interface":"fwdvtap0"}`),
		},
		{
			Key:     "good",
			Enabled: true,
			Data:    json.RawMessage(`{"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
		},
	}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err == nil || !strings.Contains(err.Error(), "failed to apply 1 VToLocal link record") {
		t.Fatalf("ApplyPluginResourceData(vtolocal links) error = %v, want partial apply error", err)
	}
	badStatus, err := store.GetPluginRecord(db, "vtolocal", "status", "bad")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/bad) error = %v", err)
	}
	for _, want := range []string{`"phase":"error"`, `"profile_key":"bad"`, `"last_error":`} {
		if !strings.Contains(badStatus.DataJSON, want) {
			t.Fatalf("vtolocal status/bad = %s, missing %s", badStatus.DataJSON, want)
		}
	}
	goodStatus, err := store.GetPluginRecord(db, "vtolocal", "status", "good")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/good) error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"profile_key":"good"`, `"host_interface":"fwdlocal0"`, `"vtap_interface":"fwdvtap0"`} {
		if !strings.Contains(goodStatus.DataJSON, want) {
			t.Fatalf("vtolocal status/good = %s, missing %s", goodStatus.DataJSON, want)
		}
	}
}

func TestExampleVToLocalDisabledLinkResourceDisablesStatus(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "vtolocal",
		ResourceID: "status",
		RecordKey:  "default",
		DataJSON:   `{"phase":"applied","egress_nat_parent_interface":"fwdvtap0"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(vtolocal status/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: false,
		Data:    json.RawMessage(`{"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(vtolocal disabled link) error = %v", err)
	}
	statusRecord, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("vtolocal status/default enabled = true, want false after disabled link apply")
	}
	for _, want := range []string{`"phase":"disabled"`, `"host_interface":"fwdlocal0"`, `"vtap_interface":"fwdvtap0"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 0 {
		t.Fatalf("vtolocal timers after disabled link apply = %+v, want none", timers)
	}
}

func TestExampleVToLocalDisabledLinkKeepsRepairTimerForOtherEnabledLinks(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "vtolocal",
		ResourceID: "links",
		RecordKey:  "other",
		DataJSON:   `{"host_interface":"fwdlocal1","vtap_interface":"fwdvtap1"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(vtolocal links/other) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: false,
		Data:    json.RawMessage(`{"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(vtolocal disabled link with other enabled) error = %v", err)
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 1 || timers[0]["name"] != "vtolocal_repair" {
		t.Fatalf("vtolocal timers after disabling one of multiple links = %+v, want vtolocal_repair", timers)
	}
}

func TestExampleVToLocalRepairTimerRecoversVethFailure(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	linkJSON := `{"profile_key":"default","host_interface":"fwdlocal0","vtap_interface":"fwdvtap0","host_addresses":["169.254.253.1/30"],"vtap_addresses":["169.254.253.2/30"],"routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "vtolocal",
		ResourceID: "links",
		RecordKey:  "default",
		DataJSON:   linkJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(vtolocal links/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		ensureVethErrors: map[string]error{"fwdlocal0": fmt.Errorf("temporary veth create failure")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(linkJSON),
	}}); err == nil || !strings.Contains(err.Error(), "failed to apply 1 VToLocal link record") {
		t.Fatalf("ApplyPluginResourceData(vtolocal links) error = %v, want temporary failure", err)
	}
	statusRecord, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) failed apply error = %v", err)
	}
	for _, want := range []string{`"phase":"error"`, `"last_error":"net.link.ensureVeth: temporary veth create failure"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal failed status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if err := store.MarkPluginRuntimeError(db, "vtolocal", "resource", "links", "api apply failed"); err != nil {
		t.Fatalf("MarkPluginRuntimeError(vtolocal links) error = %v", err)
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 1 {
		t.Fatalf("vtolocal timers after failed apply = %+v, want one repair timer", timers)
	}

	controller.ensureVethErrors = nil
	firePluginTimerForTest(t, rt, "vtolocal", "vtolocal_repair")
	statusRecord, err = store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) recovered error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"host_interface":"fwdlocal0"`, `"vtap_interface":"fwdvtap0"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal recovered status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	runtimeStatus, err := store.PluginRuntimeStatusOrNil(db, "vtolocal", "resource", "links")
	if err != nil {
		t.Fatalf("PluginRuntimeStatusOrNil(vtolocal links) error = %v", err)
	}
	if runtimeStatus == nil || runtimeStatus.Status != "applied" || runtimeStatus.LastError != "" || runtimeStatus.AppliedRevision != runtimeStatus.Revision {
		t.Fatalf("vtolocal links runtime status after repair = %+v, want applied with cleared error", runtimeStatus)
	}
}

func TestExampleVToLocalTeardownDisablesLinkAndRepairTimer(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	linkJSON := `{"profile_key":"default","host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "vtolocal",
		ResourceID: "links",
		RecordKey:  "default",
		DataJSON:   linkJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(vtolocal links/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(linkJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 1 {
		t.Fatalf("vtolocal timers before teardown = %+v, want one repair timer", timers)
	}
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(vtolocal teardown) error = %v", err)
	}
	linkRecord, err := store.GetPluginRecord(db, "vtolocal", "links", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal links/default) error = %v", err)
	}
	if linkRecord.Enabled {
		t.Fatalf("vtolocal links/default enabled = true, want false after teardown")
	}
	statusRecord, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("vtolocal status/default enabled = true, want false after teardown")
	}
	for _, want := range []string{`"phase":"deleted"`, `"managed_link":true`, `"link_delete_skipped":false`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 0 {
		t.Fatalf("vtolocal timers after teardown = %+v, want none", timers)
	}

	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("second ApplyPluginAction(vtolocal teardown) error = %v", err)
	}
	if containsString(controller.calls, "delete:fwdlocal0") {
		t.Fatalf("net admin calls after repeated teardown = %+v, want no second physical delete", controller.calls)
	}
	statusRecord, err = store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) after repeated teardown error = %v", err)
	}
	for _, want := range []string{`"phase":"deleted"`, `"managed_link":true`, `"link_delete_skipped":true`, `"link_delete_skip_reason":"previous vtolocal status already deleted this plugin-managed veth pair"`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal status/default after repeated teardown = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleVToLocalTeardownDisablesLinkWhenDeleteFails(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	linkJSON := `{"profile_key":"default","host_interface":"fwdlocal0","vtap_interface":"fwdvtap0","host_addresses":["169.254.253.1/30"],"vtap_addresses":["169.254.253.2/30"],"routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "vtolocal",
		ResourceID: "links",
		RecordKey:  "default",
		DataJSON:   linkJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(vtolocal links/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{
		deleteErrors: map[string]error{"fwdlocal0": fmt.Errorf("operation not permitted")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(linkJSON),
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 1 {
		t.Fatalf("vtolocal timers before teardown = %+v, want one repair timer", timers)
	}
	controller.calls = nil
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(vtolocal teardown) error = %v", err)
	}
	for _, want := range []string{
		"addrDelete:fwdlocal0:169.254.253.1/30",
		"addrDelete:fwdvtap0:169.254.253.2/30",
		"routeDelete:0.0.0.0/0:fwdlocal0:169.254.253.2:0:0",
		"delete:fwdlocal0",
	} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	linkRecord, err := store.GetPluginRecord(db, "vtolocal", "links", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal links/default) error = %v", err)
	}
	if linkRecord.Enabled {
		t.Fatalf("vtolocal links/default enabled = true, want false after failed physical delete")
	}
	statusRecord, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) error = %v", err)
	}
	if statusRecord.Enabled {
		t.Fatalf("vtolocal status/default enabled = true, want false after failed physical delete")
	}
	for _, want := range []string{`"phase":"delete_failed"`, `"last_error":"net.link.delete: operation not permitted"`, `"host_interface":"fwdlocal0"`, `"managed_link":true`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 0 {
		t.Fatalf("vtolocal timers after failed physical delete = %+v, want none", timers)
	}
}

func TestExampleVToLocalTeardownWithoutStatusDoesNotDeleteLinkOrManagedState(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	action := pluginActionByIDForTest(t, plugin, "teardown")

	db := openTestDB(t)
	linkJSON := `{"profile_key":"default","host_interface":"fwdlocal0","vtap_interface":"fwdvtap0","host_addresses":["169.254.253.1/30"],"vtap_addresses":["169.254.253.2/30"],"routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]}`
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "vtolocal",
		ResourceID: "links",
		RecordKey:  "default",
		DataJSON:   linkJSON,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(vtolocal links/default) error = %v", err)
	}

	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"key":"default"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(vtolocal teardown without status) error = %v", err)
	}
	for _, forbidden := range []string{
		"addrDelete:fwdlocal0:169.254.253.1/30",
		"addrDelete:fwdvtap0:169.254.253.2/30",
		"routeDelete:0.0.0.0/0:fwdlocal0:169.254.253.2:0:0",
		"delete:fwdlocal0",
	} {
		if containsString(controller.calls, forbidden) {
			t.Fatalf("net admin calls = %+v, want no unmanaged teardown call %s without prior status", controller.calls, forbidden)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) error = %v", err)
	}
	for _, want := range []string{`"phase":"deleted"`, `"managed_link":false`, `"link_delete_skipped":true`, `"link_delete_skip_reason":"no previous vtolocal status proves this veth pair was plugin-managed"`, `"cleanup_errors":[]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleVToLocalResourceApplySkipsUnchangedStatusRewrite(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	t.Cleanup(func() { _ = rt.Close() })

	records := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data:    json.RawMessage(`{"host_interface":"fwdlocal0","vtap_interface":"fwdvtap0"}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err != nil {
		t.Fatalf("first ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	first, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) first error = %v", err)
	}
	if err := rt.ApplyPluginResourceData(plugin, resource, records); err != nil {
		t.Fatalf("second ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	second, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) second error = %v", err)
	}
	if second.Revision != first.Revision {
		t.Fatalf("vtolocal status revision changed from %d to %d for unchanged apply\nfirst=%s\nsecond=%s", first.Revision, second.Revision, first.DataJSON, second.DataJSON)
	}
}

func TestExampleVToLocalResourceApplyDeletesRemovedManagedAddressAndRoute(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	first := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0",
		  "host_addresses":["169.254.253.1/30","169.254.253.5/30"],
		  "vtap_addresses":["169.254.253.2/30"],
		  "routes":[{"dst":"0.0.0.0/0","gateway":"169.254.253.2"}]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, first); err != nil {
		t.Fatalf("first ApplyPluginResourceData(vtolocal links) error = %v", err)
	}

	controller.calls = nil
	second := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0",
		  "host_addresses":["169.254.253.1/30"],
		  "vtap_addresses":[],
		  "routes":[]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, second); err != nil {
		t.Fatalf("second ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	for _, want := range []string{
		"addrDelete:fwdlocal0:169.254.253.5/30",
		"addrDelete:fwdvtap0:169.254.253.2/30",
		"routeDelete:0.0.0.0/0:fwdlocal0:169.254.253.2:0:0",
	} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	statusRecord, err := store.GetPluginRecord(db, "vtolocal", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal status/default) error = %v", err)
	}
	for _, want := range []string{`"cleanup_errors":[]`, `"host_addresses":["169.254.253.1/30"]`, `"routes":[]`} {
		if !strings.Contains(statusRecord.DataJSON, want) {
			t.Fatalf("vtolocal status/default = %s, missing %s", statusRecord.DataJSON, want)
		}
	}
}

func TestExampleVToLocalResourceApplyDeletesManagedVethWhenInterfaceChanges(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)
	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	resource := pluginResourceByIDForTest(t, plugin, "links")

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(rootDir)}, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	first := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "host_interface":"fwdold0",
		  "vtap_interface":"fwdoldtap0",
		  "host_addresses":["169.254.253.1/30"],
		  "vtap_addresses":["169.254.253.2/30"]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, first); err != nil {
		t.Fatalf("first ApplyPluginResourceData(vtolocal links) error = %v", err)
	}

	controller.calls = nil
	second := []PluginResourceRecord{{
		Key:     "default",
		Enabled: true,
		Data: json.RawMessage(`{
		  "host_interface":"fwdlocal0",
		  "vtap_interface":"fwdvtap0",
		  "host_addresses":["169.254.253.1/30"],
		  "vtap_addresses":["169.254.253.2/30"]
		}`),
	}}
	if err := rt.ApplyPluginResourceData(plugin, resource, second); err != nil {
		t.Fatalf("second ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	for _, want := range []string{"delete:fwdold0"} {
		if !containsString(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing %s", controller.calls, want)
		}
	}
	for _, forbidden := range []string{
		"addrDelete:fwdold0:169.254.253.1/30",
		"addrDelete:fwdoldtap0:169.254.253.2/30",
	} {
		if containsString(controller.calls, forbidden) {
			t.Fatalf("net admin calls = %+v, want old veth delete instead of stale cleanup call %s", controller.calls, forbidden)
		}
	}
}

func getPluginRecordsForTest(t *testing.T, handler http.Handler, path string) pluginRecordsResponse {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d: %s", path, rec.Code, http.StatusOK, rec.Body.String())
	}
	var listed pluginRecordsResponse
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return listed
}

func waitForPluginRecordForTest(t *testing.T, db *sql.DB, pluginID, resourceID, key string, timeout time.Duration) store.PluginRecord {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		record, err := store.GetPluginRecord(db, pluginID, resourceID, key)
		if err == nil {
			return *record
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("GetPluginRecord(%s/%s/%s) error = %v", pluginID, resourceID, key, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for plugin record %s/%s/%s", pluginID, resourceID, key)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForPluginRecordContainingForTest(t *testing.T, db *sql.DB, pluginID, resourceID, key string, timeout time.Duration, wants ...string) store.PluginRecord {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		record := waitForPluginRecordForTest(t, db, pluginID, resourceID, key, timeout)
		missing := ""
		for _, want := range wants {
			if !strings.Contains(record.DataJSON, want) {
				missing = want
				break
			}
		}
		if missing == "" {
			return record
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin record %s/%s/%s data = %s, missing %s", pluginID, resourceID, key, record.DataJSON, missing)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForPluginRuntimeStatusForTest(t *testing.T, db *sql.DB, pluginID, targetType, targetID, wantStatus string, timeout time.Duration) store.PluginRuntimeStatus {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last *store.PluginRuntimeStatus
	for {
		status, err := store.PluginRuntimeStatusOrNil(db, pluginID, targetType, targetID)
		if err != nil {
			t.Fatalf("PluginRuntimeStatusOrNil(%s/%s/%s) error = %v", pluginID, targetType, targetID, err)
		}
		if status != nil {
			last = status
			if status.Status == wantStatus {
				return *status
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for plugin runtime status %s/%s/%s = %s, last=%+v", pluginID, targetType, targetID, wantStatus, last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func firePluginTimerForTest(t *testing.T, rt *gojaPluginControlRuntime, pluginID, name string) {
	t.Helper()

	key := pluginControlTimerKey{pluginID: pluginID, name: name}
	rt.mu.Lock()
	state, ok := rt.timers[key]
	if !ok {
		rt.mu.Unlock()
		t.Fatalf("plugin timer %s/%s not found", pluginID, name)
	}
	generation := state.generation
	rt.mu.Unlock()
	rt.firePluginTimer(key, generation)
}

func assertPluginResourceMethodsForTest(t *testing.T, plugin LoadedPlugin, id string, wantMethods string, wantControlMethods string) {
	t.Helper()
	resource := pluginResourceByIDForTest(t, plugin, id)
	if got := strings.Join(resource.Methods, ","); got != wantMethods {
		t.Fatalf("plugin %s resource %s methods = %q, want %q", plugin.ID, id, got, wantMethods)
	}
	if got := strings.Join(resource.ControlMethods, ","); got != wantControlMethods {
		t.Fatalf("plugin %s resource %s control methods = %q, want %q", plugin.ID, id, got, wantControlMethods)
	}
}

func pluginResourceByIDForTest(t *testing.T, plugin LoadedPlugin, id string) PluginResource {
	t.Helper()
	for _, resource := range plugin.Resources {
		if resource.ID == id {
			return resource
		}
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	for _, resource := range plugin.Resources {
		if resource.ID == id {
			return resource
		}
	}
	t.Fatalf("plugin %s resource %s not found in %+v", plugin.ID, id, plugin.Resources)
	return PluginResource{}
}

func pluginActionByIDForTest(t *testing.T, plugin LoadedPlugin, id string) PluginAction {
	t.Helper()
	for _, action := range plugin.Actions {
		if action.ID == id {
			return action
		}
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	for _, action := range plugin.Actions {
		if action.ID == id {
			return action
		}
	}
	t.Fatalf("plugin %s action %s not found in %+v", plugin.ID, id, plugin.Actions)
	return PluginAction{}
}

func pluginWithRuntimeSurfaceForTest(t *testing.T, plugin LoadedPlugin) LoadedPlugin {
	t.Helper()
	if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.controlMainPath == "" {
		return plugin
	}
	rt := newPluginControlRuntime(nil, &Config{}, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	surface, err := rt.runPluginControlWithSurface(plugin, pluginControlEvent{Kind: "register"}, true)
	if err != nil {
		t.Fatalf("register plugin %s runtime surface: %v", plugin.ID, err)
	}
	applyPluginRuntimeSurface(&plugin, surface)
	return plugin
}

type pluginRuntimeApplyTestRuntime struct {
	resourceCalls   []pluginRuntimeApplyResourceCall
	actionCalls     []pluginRuntimeApplyActionCall
	resourceErr     error
	actionErr       error
	kernelSupported bool
	lastRules       []Rule
	assignments     map[int64]string
}

type pluginDataplaneRuntimeTest struct {
	snapshot pluginRuntimeSnapshot
}

func (rt pluginDataplaneRuntimeTest) Reconcile(PluginCatalog) pluginRuntimeSnapshot {
	return rt.snapshot
}

func (rt pluginDataplaneRuntimeTest) Snapshot() pluginRuntimeSnapshot {
	return rt.snapshot
}

func (rt pluginDataplaneRuntimeTest) Close() error {
	return nil
}

type pluginPipelineKernelRuntimeTest struct {
	kernelSupported           bool
	snapshot                  pluginRuntimeSnapshot
	lastRules                 []Rule
	lastCatalog               PluginCatalog
	assignments               map[int64]string
	reconcileCalls            int
	reconcileWithCatalogCalls int
	reconcilePluginsCalls     int
}

func (rt *pluginPipelineKernelRuntimeTest) Available() (bool, string) {
	return true, ""
}

func (rt *pluginPipelineKernelRuntimeTest) SupportsRule(Rule) (bool, string) {
	if rt.kernelSupported {
		return true, ""
	}
	return false, "test kernel support disabled"
}

func (rt *pluginPipelineKernelRuntimeTest) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	rt.reconcileCalls++
	return rt.applyRules(rules, PluginCatalog{})
}

func (rt *pluginPipelineKernelRuntimeTest) ReconcileWithPluginCatalog(rules []Rule, catalog PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	rt.reconcileWithCatalogCalls++
	return rt.applyRules(rules, catalog)
}

func (rt *pluginPipelineKernelRuntimeTest) applyRules(rules []Rule, catalog PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	rt.lastRules = append(rt.lastRules[:0], rules...)
	rt.lastCatalog = catalog
	rt.assignments = make(map[int64]string, len(rules))
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	for _, rule := range rules {
		rt.assignments[rule.ID] = kernelEngineTC
		results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
	}
	return results, nil
}

func (rt *pluginPipelineKernelRuntimeTest) ReconcilePlugins(PluginCatalog) pluginRuntimeSnapshot {
	rt.reconcilePluginsCalls++
	return rt.snapshot
}

func (rt *pluginPipelineKernelRuntimeTest) PluginSnapshot() pluginRuntimeSnapshot {
	return rt.snapshot
}

func (rt *pluginPipelineKernelRuntimeTest) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt *pluginPipelineKernelRuntimeTest) Maintain() error {
	return nil
}

func (rt *pluginPipelineKernelRuntimeTest) SnapshotAssignments() map[int64]string {
	out := make(map[int64]string, len(rt.assignments))
	for id, engine := range rt.assignments {
		out[id] = engine
	}
	return out
}

func (rt *pluginPipelineKernelRuntimeTest) Close() error {
	return nil
}

type pluginRuntimeApplyResourceCall struct {
	plugin   LoadedPlugin
	resource PluginResource
	records  []PluginResourceRecord
}

type pluginRuntimeApplyActionCall struct {
	plugin  LoadedPlugin
	action  PluginAction
	payload json.RawMessage
}

func (rt *pluginRuntimeApplyTestRuntime) Available() (bool, string) {
	return true, ""
}

func (rt *pluginRuntimeApplyTestRuntime) SupportsRule(Rule) (bool, string) {
	if rt.kernelSupported {
		return true, ""
	}
	return false, "test kernel support disabled"
}

func (rt *pluginRuntimeApplyTestRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	rt.lastRules = append(rt.lastRules[:0], rules...)
	rt.assignments = make(map[int64]string, len(rules))
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	for _, rule := range rules {
		rt.assignments[rule.ID] = kernelEngineTC
		results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
	}
	return results, nil
}

func (rt *pluginRuntimeApplyTestRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt *pluginRuntimeApplyTestRuntime) Maintain() error {
	return nil
}

func (rt *pluginRuntimeApplyTestRuntime) SnapshotAssignments() map[int64]string {
	out := make(map[int64]string, len(rt.assignments))
	for id, engine := range rt.assignments {
		out[id] = engine
	}
	return out
}

func (rt *pluginRuntimeApplyTestRuntime) Close() error {
	return nil
}

func (rt *pluginRuntimeApplyTestRuntime) ApplyPluginResourceData(plugin LoadedPlugin, resource PluginResource, records []PluginResourceRecord) error {
	copied := make([]PluginResourceRecord, len(records))
	copy(copied, records)
	rt.resourceCalls = append(rt.resourceCalls, pluginRuntimeApplyResourceCall{plugin: plugin, resource: resource, records: copied})
	return rt.resourceErr
}

func (rt *pluginRuntimeApplyTestRuntime) ApplyPluginAction(plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	copied := append(json.RawMessage(nil), payload...)
	rt.actionCalls = append(rt.actionCalls, pluginRuntimeApplyActionCall{plugin: plugin, action: action, payload: copied})
	return rt.actionErr
}

type pluginControlL2TransportTest struct {
	sends            []pluginControlL2SendRequest
	exchanges        []pluginControlL2ExchangeRequest
	recvFrame        pluginControlL2Frame
	recvFrames       []pluginControlL2Frame
	recvErr          error
	recvFunc         func(pluginControlL2RecvRequest) (pluginControlL2Frame, error)
	recvManyFunc     func(pluginControlL2RecvManyRequest) ([]pluginControlL2Frame, error)
	exchangeFunc     func(pluginControlL2ExchangeRequest) (pluginControlL2Frame, error)
	exchangeManyFunc func(pluginControlL2ExchangeManyRequest) ([]pluginControlL2Frame, error)
}

func (tr *pluginControlL2TransportTest) Send(req pluginControlL2SendRequest) error {
	tr.sends = append(tr.sends, req)
	return nil
}

func (tr *pluginControlL2TransportTest) Recv(req pluginControlL2RecvRequest) (pluginControlL2Frame, error) {
	if tr.recvFunc != nil {
		return tr.recvFunc(req)
	}
	if tr.recvErr != nil {
		return pluginControlL2Frame{}, tr.recvErr
	}
	frame := tr.nextFrame()
	if frame.Interface == "" {
		frame.Interface = req.Interface
	}
	if frame.EtherType == 0 {
		frame.EtherType = req.EtherType
	}
	return frame, nil
}

func (tr *pluginControlL2TransportTest) RecvMany(req pluginControlL2RecvManyRequest) ([]pluginControlL2Frame, error) {
	if tr.recvManyFunc != nil {
		return tr.recvManyFunc(req)
	}
	if tr.recvErr != nil {
		if errors.Is(tr.recvErr, errPluginControlL2Timeout) {
			return []pluginControlL2Frame{}, nil
		}
		return nil, tr.recvErr
	}
	maxFrames := req.MaxFrames
	if maxFrames <= 0 {
		maxFrames = 1
	}
	frames := make([]pluginControlL2Frame, 0, maxFrames)
	for len(frames) < maxFrames {
		frame := tr.nextFrame()
		if frame.Payload == nil && len(tr.recvFrames) == 0 && tr.recvFrame.Payload == nil {
			break
		}
		if frame.Interface == "" {
			frame.Interface = req.Recv.Interface
		}
		if frame.EtherType == 0 {
			frame.EtherType = req.Recv.EtherType
		}
		frames = append(frames, frame)
		if len(tr.recvFrames) == 0 {
			break
		}
	}
	return frames, nil
}

func (tr *pluginControlL2TransportTest) Exchange(req pluginControlL2ExchangeRequest) (pluginControlL2Frame, error) {
	tr.exchanges = append(tr.exchanges, req)
	if tr.exchangeFunc != nil {
		return tr.exchangeFunc(req)
	}
	if tr.recvErr != nil {
		return pluginControlL2Frame{}, tr.recvErr
	}
	frame := tr.nextFrame()
	if frame.Interface == "" {
		frame.Interface = req.Recv.Interface
	}
	if frame.EtherType == 0 {
		frame.EtherType = req.Recv.EtherType
	}
	return frame, nil
}

func (tr *pluginControlL2TransportTest) ExchangeMany(req pluginControlL2ExchangeManyRequest) ([]pluginControlL2Frame, error) {
	tr.exchanges = append(tr.exchanges, pluginControlL2ExchangeRequest{
		Send: req.Send,
		Recv: req.Recv.Recv,
	})
	if tr.exchangeManyFunc != nil {
		return tr.exchangeManyFunc(req)
	}
	if tr.exchangeFunc != nil {
		frame, err := tr.exchangeFunc(pluginControlL2ExchangeRequest{
			Send: req.Send,
			Recv: req.Recv.Recv,
		})
		if errors.Is(err, errPluginControlL2Timeout) {
			return []pluginControlL2Frame{}, nil
		}
		if err != nil {
			return nil, err
		}
		return []pluginControlL2Frame{frame}, nil
	}
	if tr.recvErr != nil {
		if errors.Is(tr.recvErr, errPluginControlL2Timeout) {
			return []pluginControlL2Frame{}, nil
		}
		return nil, tr.recvErr
	}
	maxFrames := req.Recv.MaxFrames
	if maxFrames <= 0 {
		maxFrames = 1
	}
	frames := make([]pluginControlL2Frame, 0, maxFrames)
	for len(frames) < maxFrames {
		frame := tr.nextFrame()
		if frame.Payload == nil && len(tr.recvFrames) == 0 && tr.recvFrame.Payload == nil {
			break
		}
		if frame.Interface == "" {
			frame.Interface = req.Recv.Recv.Interface
		}
		if frame.EtherType == 0 {
			frame.EtherType = req.Recv.Recv.EtherType
		}
		frames = append(frames, frame)
		if len(tr.recvFrames) == 0 {
			break
		}
	}
	return frames, nil
}

func (tr *pluginControlL2TransportTest) nextFrame() pluginControlL2Frame {
	if len(tr.recvFrames) == 0 {
		return tr.recvFrame
	}
	frame := tr.recvFrames[0]
	tr.recvFrames = tr.recvFrames[1:]
	return frame
}

func mustMACForTest(t *testing.T, value string) [6]byte {
	t.Helper()

	mac, err := parsePluginControlMAC(value)
	if err != nil {
		t.Fatalf("parsePluginControlMAC(%q) error = %v", value, err)
	}
	return mac
}

func mustHexForTest(t *testing.T, value string) []byte {
	t.Helper()

	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return data
}

func writeTestPlugin(t *testing.T, pluginsDir, name, manifest string) {
	t.Helper()

	pluginDir := filepath.Join(pluginsDir, name)
	uiDir := filepath.Join(pluginDir, "ui")
	if err := os.MkdirAll(uiDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	cleanManifest, registrationPrelude := testPluginManifestAndRegistrationPrelude(t, manifest)
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(cleanManifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	if registrationPrelude != "" {
		if err := os.WriteFile(filepath.Join(pluginDir, ".runtime-register.js"), []byte(registrationPrelude), 0o644); err != nil {
			t.Fatalf("WriteFile(.runtime-register.js) error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, "control.js"), []byte(registrationPrelude+"\nexports.onReconcile = function () {};\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(default control.js) error = %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte("plugin asset ok"), 0o644); err != nil {
		t.Fatalf("WriteFile(index.html) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(uiDir, "asset.txt"), []byte("plugin asset ok"), 0o644); err != nil {
		t.Fatalf("WriteFile(asset.txt) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "observer.o"), []byte("fake ebpf object"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
}

func testPluginManifestAndRegistrationPrelude(t *testing.T, manifest string) (string, string) {
	t.Helper()

	var doc map[string]any
	if err := json.Unmarshal([]byte(manifest), &doc); err != nil {
		t.Fatalf("decode test manifest: %v", err)
	}
	surface := make(map[string]any)
	for field := range pluginManifestRuntimeFields {
		if value, ok := doc[field]; ok {
			surface[field] = value
			delete(doc, field)
		}
	}
	if len(surface) > 0 {
		control, _ := doc["control"].(map[string]any)
		if control == nil {
			control = map[string]any{"main": "control.js"}
			doc["control"] = control
		}
		if strings.TrimSpace(fmt.Sprint(control["main"])) == "" {
			control["main"] = "control.js"
		}
		permissions := testPluginStringList(control["permissions"])
		if testPluginSurfaceNeedsGenericRegister(surface) {
			permissions = append(permissions, "plugin.register")
		}
		if _, ok := surface["objects"]; ok {
			permissions = append(permissions, "ebpf.load")
		}
		if _, ok := surface["hooks"]; ok {
			permissions = append(permissions, "hook.attach")
		}
		if _, ok := surface["ui"]; ok {
			permissions = append(permissions, "ui")
		}
		control["permissions"] = testPluginUniqueStrings(permissions)
	}
	clean, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("encode test manifest: %v", err)
	}
	if len(surface) == 0 {
		return string(clean), ""
	}
	surfaceJSON, err := json.Marshal(surface)
	if err != nil {
		t.Fatalf("encode test plugin surface: %v", err)
	}
	prelude := `(function () {
  var surface = ` + string(surfaceJSON) + `;
  if (surface.capabilities) plugin.capabilities(surface.capabilities);
  (surface.virtual_interfaces || []).forEach(function (item) { plugin.virtualInterface(item); });
  (surface.resources || []).forEach(function (item) { plugin.resource(item); });
  (surface.actions || []).forEach(function (item) { plugin.action(item); });
  (surface.objects || []).forEach(function (item) { ebpf.loadObject(item); });
  (surface.hooks || []).forEach(function (item) { hooks.attach(item); });
  if (surface.ui) {
    var uiSpec = surface.ui || {};
    ui.register(uiSpec);
  }
})();`
	return string(clean), prelude
}

func testPluginSurfaceNeedsGenericRegister(surface map[string]any) bool {
	for _, field := range []string{"capabilities", "virtual_interfaces", "resources", "actions"} {
		if _, ok := surface[field]; ok {
			return true
		}
	}
	return false
}

func testPluginStringList(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" {
			out = append(out, text)
		}
	}
	return out
}

func testPluginUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func writePluginControlScript(t *testing.T, pluginsDir, name, source string) {
	t.Helper()

	path := filepath.Join(pluginsDir, name, "control.js")
	if prelude, err := os.ReadFile(filepath.Join(pluginsDir, name, ".runtime-register.js")); err == nil && len(prelude) > 0 {
		source = string(prelude) + "\n" + source
	}
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(control.js) error = %v", err)
	}
}

func setTestPluginControlSHA(t *testing.T, pluginsDir, name string) {
	t.Helper()

	pluginDir := filepath.Join(pluginsDir, name)
	manifestPath := filepath.Join(pluginDir, pluginManifestFile)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile(plugin.json) error = %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode plugin.json: %v", err)
	}
	control, _ := doc["control"].(map[string]any)
	if control == nil {
		control = map[string]any{"main": "control.js"}
		doc["control"] = control
	}
	main := strings.TrimSpace(fmt.Sprint(control["main"]))
	if main == "" {
		main = "control.js"
		control["main"] = main
	}
	sum, err := sha256File(filepath.Join(pluginDir, filepath.FromSlash(main)))
	if err != nil {
		t.Fatalf("sha256File(%s) error = %v", main, err)
	}
	control["sha256"] = sum
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("encode plugin.json: %v", err)
	}
	if err := os.WriteFile(manifestPath, out, 0o644); err != nil {
		t.Fatalf("WriteFile(plugin.json) error = %v", err)
	}
}

func loadTestPluginByID(t *testing.T, cfg *Config, id string) LoadedPlugin {
	t.Helper()

	catalog := loadPluginCatalog(cfg)
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil)
	t.Cleanup(func() {
		_ = rt.Close()
		_ = db.Close()
	})
	applyPluginRuntimeSnapshot(&catalog, rt.Reconcile(catalog))
	for _, plugin := range catalog.Plugins {
		if plugin.ID == id {
			if plugin.Status != pluginStatusActive {
				t.Fatalf("plugin %s status = %s error=%s, want active", id, plugin.Status, plugin.Error)
			}
			return plugin
		}
	}
	t.Fatalf("plugin %s not found in catalog %+v", id, catalog.Plugins)
	return LoadedPlugin{}
}

func pluginControlVMExistsForTest(rt *gojaPluginControlRuntime, pluginID string) bool {
	if rt == nil {
		return false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	_, ok := rt.controlVMs[pluginID]
	return ok
}

type pluginControlMapControllerTest struct {
	calls []string
}

func (c *pluginControlMapControllerTest) ApplyPluginResourceReconcileFromControl(plugin LoadedPlugin, resource PluginResource) error {
	c.calls = append(c.calls, fmt.Sprintf("reconcile:%s:%s", plugin.ID, resource.ID))
	return nil
}

func (c *pluginControlMapControllerTest) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	c.calls = append(c.calls, fmt.Sprintf("put:%s:%s:%s:%x:%x", pluginID, objectID, mapName, key, value))
	return nil
}

func (c *pluginControlMapControllerTest) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	c.calls = append(c.calls, fmt.Sprintf("get:%s:%s:%s:%x", pluginID, objectID, mapName, key))
	return make([]byte, 8), nil
}

func (c *pluginControlMapControllerTest) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	c.calls = append(c.calls, fmt.Sprintf("delete:%s:%s:%s:%x", pluginID, objectID, mapName, key))
	return nil
}

func (c *pluginControlMapControllerTest) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	c.calls = append(c.calls, fmt.Sprintf("clear:%s:%s:%s", pluginID, objectID, mapName))
	return nil
}

type pluginControlMapReconcileControllerTest struct {
	pluginControlMapControllerTest
}

func (c *pluginControlMapReconcileControllerTest) ApplyPluginResourceRuntimeUpdate(plugin LoadedPlugin, resource PluginResource) error {
	c.calls = append(c.calls, fmt.Sprintf("resourceUpdate:%s:%s", plugin.ID, resource.ID))
	return nil
}

type pluginControlNetAdminTest struct {
	calls             []string
	links             map[string]pluginControlNetLinkInfo
	getErrors         map[string]error
	ensureVethErrors  map[string]error
	deleteErrors      map[string]error
	setMasterErrors   map[string]error
	clearMasterErrors map[string]error
	setOffloadErrors  map[string]error
}

func (c *pluginControlNetAdminTest) LinkGet(name string) (pluginControlNetLinkInfo, error) {
	c.calls = append(c.calls, "get:"+name)
	if c.getErrors != nil {
		if err := c.getErrors[name]; err != nil {
			return pluginControlNetLinkInfo{}, err
		}
	}
	return c.linkInfo(name), nil
}

func (c *pluginControlNetAdminTest) LinkList() ([]pluginControlNetLinkInfo, error) {
	c.calls = append(c.calls, "list")
	return []pluginControlNetLinkInfo{
		c.linkInfo("fwdlocal0"),
		c.linkInfo("fwdvtap0"),
	}, nil
}

func (c *pluginControlNetAdminTest) LinkEnsureBridge(req pluginControlNetBridgeRequest) (pluginControlNetLinkInfo, error) {
	c.calls = append(c.calls, fmt.Sprintf("ensureBridge:%s:%d:%t", req.Name, req.MTU, req.Up))
	info := c.linkInfo(req.Name)
	info.MTU = req.MTU
	info.Up = req.Up
	c.updateLinkInfo(info)
	return info, nil
}

func (c *pluginControlNetAdminTest) LinkEnsureVeth(req pluginControlNetVethRequest) (pluginControlNetVethResult, error) {
	c.calls = append(c.calls, fmt.Sprintf("ensureVeth:%s:%s:%d:%t", req.Host, req.Peer, req.MTU, req.Up))
	if c.ensureVethErrors != nil {
		if err := c.ensureVethErrors[req.Host]; err != nil {
			return pluginControlNetVethResult{}, err
		}
		if err := c.ensureVethErrors[req.Peer]; err != nil {
			return pluginControlNetVethResult{}, err
		}
	}
	host := c.linkInfo(req.Host)
	peer := c.linkInfo(req.Peer)
	host.PeerName = peer.Name
	host.PeerIfIndex = peer.IfIndex
	peer.PeerName = host.Name
	peer.PeerIfIndex = host.IfIndex
	return pluginControlNetVethResult{Host: host, Peer: peer}, nil
}

func (c *pluginControlNetAdminTest) LinkDelete(name string) error {
	c.calls = append(c.calls, "delete:"+name)
	if c.deleteErrors != nil {
		if err := c.deleteErrors[name]; err != nil {
			return err
		}
	}
	return nil
}

func (c *pluginControlNetAdminTest) LinkSetMaster(req pluginControlNetMasterRequest) (pluginControlNetLinkInfo, error) {
	c.calls = append(c.calls, fmt.Sprintf("setMaster:%s:%s:%t", req.Link, req.Master, req.Up))
	if c.setMasterErrors != nil {
		if err := c.setMasterErrors[req.Link]; err != nil {
			return pluginControlNetLinkInfo{}, err
		}
	}
	info := c.linkInfo(req.Link)
	info.MasterName = req.Master
	info.MasterIfIndex = c.linkInfo(req.Master).IfIndex
	info.Up = req.Up
	c.updateLinkInfo(info)
	return info, nil
}

func (c *pluginControlNetAdminTest) LinkClearMaster(name string) (pluginControlNetLinkInfo, error) {
	c.calls = append(c.calls, "clearMaster:"+name)
	if c.clearMasterErrors != nil {
		if err := c.clearMasterErrors[name]; err != nil {
			return pluginControlNetLinkInfo{}, err
		}
	}
	info := c.linkInfo(name)
	info.MasterName = ""
	info.MasterIfIndex = 0
	c.updateLinkInfo(info)
	return info, nil
}

func (c *pluginControlNetAdminTest) LinkSetUp(name string, up bool) error {
	c.calls = append(c.calls, fmt.Sprintf("setUp:%s:%t", name, up))
	return nil
}

func (c *pluginControlNetAdminTest) LinkSetMTU(name string, mtu int) error {
	c.calls = append(c.calls, fmt.Sprintf("setMTU:%s:%d", name, mtu))
	return nil
}

func (c *pluginControlNetAdminTest) LinkSetOffloads(req pluginControlNetOffloadRequest) error {
	features := make([]string, 0, len(req.Features))
	for feature, enabled := range req.Features {
		features = append(features, fmt.Sprintf("%s=%t", feature, enabled))
	}
	sort.Strings(features)
	c.calls = append(c.calls, fmt.Sprintf("setOffloads:%s:%s", req.Interface, strings.Join(features, ",")))
	if c.setOffloadErrors != nil {
		if err := c.setOffloadErrors[req.Interface]; err != nil {
			return err
		}
	}
	return nil
}

func (c *pluginControlNetAdminTest) AddrReplace(req pluginControlNetAddrRequest) error {
	c.calls = append(c.calls, fmt.Sprintf("addrReplace:%s:%s", req.Interface, req.CIDR))
	return nil
}

func (c *pluginControlNetAdminTest) AddrDelete(req pluginControlNetAddrRequest) error {
	c.calls = append(c.calls, fmt.Sprintf("addrDelete:%s:%s", req.Interface, req.CIDR))
	return nil
}

func (c *pluginControlNetAdminTest) RouteReplace(req pluginControlNetRouteRequest) error {
	c.calls = append(c.calls, fmt.Sprintf("routeReplace:%s:%s:%s:%d:%d", req.Dst, req.Dev, req.Gateway, req.Table, req.Metric))
	return nil
}

func (c *pluginControlNetAdminTest) RouteDelete(req pluginControlNetRouteRequest) error {
	c.calls = append(c.calls, fmt.Sprintf("routeDelete:%s:%s:%s:%d:%d", req.Dst, req.Dev, req.Gateway, req.Table, req.Metric))
	return nil
}

func (c *pluginControlNetAdminTest) linkInfo(name string) pluginControlNetLinkInfo {
	if c.links != nil {
		if info, ok := c.links[name]; ok {
			return info
		}
	}
	if name == "eth0" {
		return pluginControlNetLinkInfo{Name: name, IfIndex: 7, Kind: "device", MTU: 1500, MAC: "02:00:00:00:00:01", Up: true}
	}
	if name == "fwdlocal0" {
		return pluginControlNetLinkInfo{Name: name, IfIndex: 101, Kind: "veth", MTU: 1492, MAC: "02:00:00:00:10:01", Up: true}
	}
	if name == "brlan0" {
		return pluginControlNetLinkInfo{Name: name, IfIndex: 201, Kind: "bridge", MTU: 1500, MAC: "02:00:00:00:20:01", Up: true}
	}
	return pluginControlNetLinkInfo{Name: name, IfIndex: 102, Kind: "veth", MTU: 1492, MAC: "02:00:00:00:10:02", Up: true}
}

func (c *pluginControlNetAdminTest) updateLinkInfo(info pluginControlNetLinkInfo) {
	if c.links == nil || info.Name == "" {
		return
	}
	c.links[info.Name] = info
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsStringWithPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func insertPluginEgressNATPlanForTest(t *testing.T, db *sql.DB, pluginID, key, dataJSON string, enabled bool) {
	t.Helper()
	item := store.PluginRecord{
		PluginID:   pluginID,
		ResourceID: pluginEgressNATPlansResourceID,
		RecordKey:  key,
		DataJSON:   dataJSON,
		Enabled:    enabled,
	}
	if _, err := store.AddPluginRecord(db, &item); err != nil {
		t.Fatalf("AddPluginRecord(%s/%s) error = %v", pluginID, key, err)
	}
}

func testSHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])
}

func compileTestBPFObject(t *testing.T, dir, name string) string {
	t.Helper()

	sourcePath := filepath.Join(dir, strings.TrimSuffix(name, filepath.Ext(name))+".bpf.c")
	objectPath := filepath.Join(dir, name)
	source := `#define SEC(name) __attribute__((section(name), used))
struct __sk_buff;
SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) { return 0; }
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(bpf source) error = %v", err)
	}
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	return objectPath
}

func compileBPFObjectFromSource(t *testing.T, sourcePath, objectPath string) {
	t.Helper()

	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("clang unavailable: %v", err)
	}
	cmd := exec.Command("clang", "-O2", "-target", "bpf", "-D__TARGET_ARCH_"+testBPFTargetArch(), "-c", sourcePath, "-o", objectPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("compile test bpf object: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if strip, err := exec.LookPath("llvm-strip"); err == nil {
		cmd = exec.Command(strip, "-g", objectPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("strip test bpf object skipped: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
}

func testBPFTargetArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86"
	case "arm64":
		return "arm64"
	case "arm":
		return "arm"
	case "riscv64":
		return "riscv"
	case "s390x":
		return "s390"
	case "ppc64le":
		return "powerpc"
	default:
		return "x86"
	}
}

func copyDirForTest(t *testing.T, src, dst string) {
	t.Helper()

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", src, err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", dst, err)
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			copyDirForTest(t, srcPath, dstPath)
			continue
		}
		data, err := os.ReadFile(srcPath)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", srcPath, err)
		}
		if err := os.WriteFile(dstPath, data, 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", dstPath, err)
		}
	}
}
