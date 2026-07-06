package app

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forward/internal/store"
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
	if len(catalog.Plugins) != 1 {
		t.Fatalf("plugin count = %d, want builtin only", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[0]
	if plugin.ID != "fvtap" || plugin.Status != pluginStatusBuiltin || !plugin.Builtin {
		t.Fatalf("builtin plugin = %+v, want fvtap builtin", plugin)
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
  "capabilities": ["observe", "observe"],
  "virtual_interfaces": [{"id": "vtap0", "type": "logical"}],
  "hooks": [{
    "id": "observe-ingress",
    "engine": "tc",
    "attach": "ingress",
    "stage": "pre_forward",
    "priority": 10,
    "program": "observer.o:tc_ingress",
    "mode": "observe"
  }],
  "ui": {
    "static_dir": "ui",
    "entry": "index.html"
  }
}`)

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
	if len(catalog.Plugins) != 2 {
		t.Fatalf("plugin count = %d, want builtin + external", len(catalog.Plugins))
	}
	plugin := catalog.Plugins[1]
	if plugin.ID != "packet_observer" || plugin.Status != pluginStatusActive {
		t.Fatalf("external plugin = %+v, want active packet_observer", plugin)
	}
	if plugin.Runtime.Mode != pluginRuntimeModeManifestOnly || plugin.Runtime.Attachable || plugin.Runtime.Attached {
		t.Fatalf("external runtime = %+v, want manifest-only non-attachable runtime", plugin.Runtime)
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

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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

func TestNormalizePluginManifestDefaultsControlHook(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Hooks: []PluginHook{{
			ID:     "configure",
			Engine: "control",
			Stage:  "configure",
		}},
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest() error = %v", err)
	}
	if got := manifest.Hooks[0].Attach; got != "none" {
		t.Fatalf("control hook attach = %q, want none", got)
	}
	if got := manifest.Hooks[0].Mode; got != "control" {
		t.Fatalf("control hook mode = %q, want control", got)
	}
}

func TestNormalizePluginManifestResourcesAndActions(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Resources: []PluginResource{{
			ID:             "Bindings",
			Methods:        []string{"update", "list", "update"},
			MaxRecords:     2,
			MaxRecordBytes: 128,
			SecretFields:   []string{"Password"},
		}},
		Actions: []PluginAction{{
			ID:            "Apply",
			RuntimeUpdate: "plugin_reconcile",
		}},
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest() error = %v", err)
	}
	if got := manifest.Resources[0].ID; got != "bindings" {
		t.Fatalf("resource id = %q, want bindings", got)
	}
	if got := strings.Join(manifest.Resources[0].Methods, ","); got != "list,update" {
		t.Fatalf("resource methods = %q, want list,update", got)
	}
	if got := strings.Join(manifest.Resources[0].SecretFields, ","); got != "password" {
		t.Fatalf("secret fields = %q, want password", got)
	}
	if got := manifest.Resources[0].RuntimeUpdate; got != "none" {
		t.Fatalf("resource runtime update = %q, want none", got)
	}
	if got := manifest.Actions[0].ID; got != "apply" {
		t.Fatalf("action id = %q, want apply", got)
	}
	if got := manifest.Actions[0].MaxPayloadBytes; got != pluginActionDefaultMaxPayloadBytes {
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
			Permissions: []string{"KV", "ebpf.map_write", "secret", "crypto", "Net.Admin"},
		},
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest() error = %v", err)
	}
	if manifest.Control == nil || manifest.Control.Main != "control.js" {
		t.Fatalf("control = %+v, want normalized control.js", manifest.Control)
	}
	if got := strings.Join(manifest.Control.Permissions, ","); got != "crypto,ebpf.map_write,kv,net.admin,secret" {
		t.Fatalf("control permissions = %q, want crypto,ebpf.map_write,kv,net.admin,secret", got)
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

func TestNormalizePluginManifestRejectsInvalidResourceMethod(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "control_plugin",
		Name:       "Control Plugin",
		Version:    "0.1.0",
		Kind:       "control",
		Resources: []PluginResource{{
			ID:      "bindings",
			Methods: []string{"root"},
		}},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "method") {
		t.Fatalf("normalizePluginManifest() error = %v, want invalid method", err)
	}
}

func TestNormalizePluginManifestRejectsDuplicateHookID(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "dup_hook",
		Name:       "Duplicate Hook",
		Version:    "0.1.0",
		Kind:       "pipeline",
		Hooks: []PluginHook{
			{ID: "inspect", Engine: "control", Stage: "configure"},
			{ID: "inspect", Engine: "control", Stage: "audit"},
		},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("normalizePluginManifest() error = %v, want duplicate hook id", err)
	}
}

func TestNormalizePluginManifestRejectsInvalidHookContext(t *testing.T) {
	t.Parallel()

	manifest := PluginManifest{
		APIVersion: pluginAPIVersionV1,
		ID:         "bad_context",
		Name:       "Bad Context",
		Version:    "0.1.0",
		Kind:       "pipeline",
		Hooks: []PluginHook{{
			ID:      "inspect",
			Engine:  "control",
			Stage:   "configure",
			Context: []string{"host_memory"},
		}},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("normalizePluginManifest() error = %v, want invalid context", err)
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
  "objects": [{
    "id": "observer",
    "path": "observer.o",
    "sha256": "`+testSHA256Hex("different object")+`"
  }]
}`)

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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

func TestLoadPluginCatalogRejectsObjectPathTraversal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "bad_path", `{
  "api_version": "v1",
  "id": "bad_path",
  "name": "Bad Path",
  "version": "0.1.0",
  "kind": "pipeline",
  "objects": [{"id": "observer", "path": "../observer.o"}]
}`)

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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
  "objects": [{"id": "observer", "path": "observer.o"}]
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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
  "objects": [{
    "id": "observer",
    "path": "observer.o",
    "sha256": "` + sum + `",
    "programs": [{"id": "tc_ingress", "section": "tc/ingress", "type": "tc"}]
  }],
  "hooks": [{
    "id": "observe-ingress",
    "engine": "tc",
    "attach": "ingress",
    "stage": "pre_forward",
    "program": "observer:tc_ingress",
    "mode": "observe"
  }],
  "ui": {"static_dir": "ui", "entry": "index.html"}
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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
  "objects": [{
    "id": "observer",
    "path": "observer.o",
    "sha256": "` + sum + `",
    "programs": [{"id": "tc_ingress", "section": "tc/ingress", "type": "tc"}]
  }],
  "hooks": [{
    "id": "observe-ingress",
    "engine": "tc",
    "stage": "pre_forward",
    "program": "observer:missing",
    "mode": "observe"
  }]
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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
  "objects": [{
    "id": "observer",
    "path": "observer.o",
    "sha256": "` + sum + `",
    "programs": [{"id": "tc_ingress", "section": "tc/ingress", "type": "tc"}]
  }],
  "hooks": [{
    "id": "observe-ingress",
    "engine": "xdp",
    "stage": "pre_forward",
    "program": "observer:tc_ingress",
    "mode": "observe"
  }]
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	catalog := loadPluginCatalog(&Config{PluginsDir: dir})
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

	var catalog PluginCatalog
	if err := json.NewDecoder(rec.Body).Decode(&catalog); err != nil {
		t.Fatalf("decode /api/plugins: %v", err)
	}
	if len(catalog.Plugins) != 2 || catalog.Plugins[1].ID != "ui_plugin" {
		t.Fatalf("catalog plugins = %+v, want fvtap + ui_plugin", catalog.Plugins)
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
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "pending" || listed.RuntimeStatus.Revision != 3 {
		t.Fatalf("runtime status after delete = %+v, want pending revision 3", listed.RuntimeStatus)
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
	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, db, &ProcessManager{})

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/limited_plugin/resources/bindings", strings.NewReader(`{"key":"alpha","data":{"name":"alpha"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST first record status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
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
	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, db, &ProcessManager{kernelRuntime: applyRuntime})

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
	req = httptest.NewRequest(http.MethodPut, "/api/plugins/apply_plugin/resources/bindings/alpha", strings.NewReader(`{"data":{"name":"alpha2"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT runtime_apply resource status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	listed = getPluginRecordsForTest(t, handler, "/api/plugins/apply_plugin/resources/bindings")
	if listed.RuntimeStatus == nil || listed.RuntimeStatus.Status != "error" || listed.RuntimeStatus.Revision != 2 || listed.RuntimeStatus.AppliedRevision != 1 {
		t.Fatalf("runtime status after failed apply = %+v, want error revision 2 with applied revision 1", listed.RuntimeStatus)
	}
	if !strings.Contains(listed.RuntimeStatus.LastError, "runtime map update failed") {
		t.Fatalf("runtime status last_error = %q, want apply failure", listed.RuntimeStatus.LastError)
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
	handler := buildAPIHandler(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir,
	}, db, &ProcessManager{kernelRuntime: applyRuntime})

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/apply_plugin/actions/apply", strings.NewReader(`{"payload":{"source":"test"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST runtime_apply action status = %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
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
    "permissions": ["plugin.resource"]
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
  ebpf.mapPut('observer', 'bindings_v4', '01020304', '1112131415161718');
  ebpf.mapDelete('observer', 'bindings_v4', '01020304');
  ebpf.mapClear('observer', 'bindings_v4');
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
	if controller.calls[0] != "put:control_plugin:observer:bindings_v4:01020304:1112131415161718" {
		t.Fatalf("put call = %q", controller.calls[0])
	}
	if controller.calls[1] != "delete:control_plugin:observer:bindings_v4:01020304" {
		t.Fatalf("delete call = %q", controller.calls[1])
	}
	if controller.calls[2] != "clear:control_plugin:observer:bindings_v4" {
		t.Fatalf("clear call = %q", controller.calls[2])
	}
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
    chap_len: chap.length,
    random_len: random.length,
    random_hex: /^[0-9a-f]+$/.test(random)
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "control_plugin")
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
		`"chap_len":32`,
		`"random_len":8`,
		`"random_hex":true`,
	} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("crypto_result data = %s, want %s", record.DataJSON, want)
		}
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
	rt := newPluginControlRuntime(openTestDB(t), &Config{PluginsDir: dir}, nil)
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
  timer.setInterval('lcp_echo', 20, {kind: 'echo'});
};
exports.onTimer = function () {
  var record = kv.get('tick_count');
  var value = record ? record.data.value : 0;
  value++;
  kv.set('tick_count', {value: value});
  if (value >= 2) {
    timer.clear('lcp_echo');
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
    "permissions": ["kv", "net.l2"]
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
		t.Fatalf("send request = %+v, want eth0 pppoe discovery with src mac", send)
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
    "permissions": ["kv", "net.l2"]
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
		t.Fatalf("exchange request = %+v, want eth0 pppoe discovery request", exchange)
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

func TestPluginGojaControlPPPoEStateMachinePrimitives(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "pppoe_plugin", `{
  "api_version": "v1",
  "id": "pppoe_plugin",
  "name": "PPPoE Plugin",
  "version": "0.1.0",
  "kind": "control",
  "actions": [{
    "id": "dial",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["crypto", "ebpf.map_write", "kv", "net.l2", "secret", "timer"]
  }
}`)
	writePluginControlScript(t, dir, "pppoe_plugin", `
exports.onAction = function (ctx) {
  secret.set('password', ctx.payload.password);
  var pado = net.l2.exchange({
    interface: ctx.payload.interface,
    ethertype: '0x8863',
    dst_mac: 'ff:ff:ff:ff:ff:ff',
    payload: '11090000000401010000',
    timeout_ms: 50,
    max_bytes: 512
  });
  if (pado === null) {
    kv.set('pppoe_state', {phase: 'discovery_retry'});
    timer.setTimeout('discovery_retry', 100, {attempt: 2});
    return;
  }
  var password = secret.get('password');
  var chap = crypto.md5([1], password, {hex: '01020304'});
  ebpf.mapPut('pppoe', 'sessions', '00000010', '00000020');
  timer.setInterval('lcp_echo', 1000, {session: 16});
  kv.set('pppoe_state', {
    phase: 'session',
    peer: pado.src_mac,
    chap_len: chap.length
  });
};
`)

	plugin := loadTestPluginByID(t, &Config{PluginsDir: dir}, "pppoe_plugin")
	db := openTestDB(t)
	controller := &pluginControlMapControllerTest{}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: dir}, controller).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{
		recvFrame: pluginControlL2Frame{
			Interface: "eth0",
			IfIndex:   7,
			EtherType: 0x8863,
			DstMAC:    mustMACForTest(t, "02:00:00:00:00:01"),
			SrcMAC:    mustMACForTest(t, "02:00:00:00:00:02"),
			Payload:   []byte{0x11, 0x07, 0x00, 0x00},
			Frame:     []byte{0xff, 0xee},
		},
	}
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{"interface":"eth0","password":"secret"}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "pppoe_plugin", pluginControlKVResourceID, "pppoe_state")
	if err != nil {
		t.Fatalf("GetPluginRecord(pppoe_state) error = %v", err)
	}
	for _, want := range []string{`"phase":"session"`, `"peer":"02:00:00:00:00:02"`, `"chap_len":32`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("pppoe_state data = %s, want %s", record.DataJSON, want)
		}
	}
	if len(controller.calls) != 1 || controller.calls[0] != "put:pppoe_plugin:pppoe:sessions:00000010:00000020" {
		t.Fatalf("map calls = %+v, want session map put", controller.calls)
	}
	timers := rt.pluginTimerList("pppoe_plugin")
	if len(timers) != 1 || timers[0]["name"] != "lcp_echo" || timers[0]["kind"] != pluginControlTimerKindInterval {
		t.Fatalf("timers = %+v, want lcp_echo interval", timers)
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
    "permissions": ["kv", "net.l2"]
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
    "permissions": ["resource", "net.admin"]
  }
}`)
	writePluginControlScript(t, dir, "control_plugin", `
exports.onAction = function () {
  var pair = net.link.ensureVeth({host: 'fwdlocal0', peer: 'fwdvtap0', mtu: 1492, up: true});
  net.addr.replace({interface: 'fwdlocal0', cidr: '169.254.77.1/30'});
  net.route.replace({dst: '0.0.0.0/0', dev: 'fwdlocal0', table: 100, metric: 10});
  net.link.setMTU('fwdvtap0', 1492);
  net.link.setUp('fwdvtap0', true);
  var link = net.link.get('fwdvtap0');
  var links = net.link.list();
  resources.set('events', 'last', {
    host: pair.host.name,
    peer: pair.peer.name,
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
		"ensureVeth:fwdlocal0:fwdvtap0:1492:true",
		"addrReplace:fwdlocal0:169.254.77.1/30",
		"routeReplace:0.0.0.0/0:fwdlocal0::100:10",
		"setMTU:fwdvtap0:1492",
		"setUp:fwdvtap0:true",
		"get:fwdvtap0",
		"list",
	}
	if strings.Join(controller.calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("net admin calls = %+v, want %+v", controller.calls, wantCalls)
	}
	record, err := store.GetPluginRecord(db, "control_plugin", "events", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(events/last) error = %v", err)
	}
	for _, want := range []string{`"host":"fwdlocal0"`, `"peer":"fwdvtap0"`, `"peer_ifindex":102`, `"links":2`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("events/last data = %s, want %s", record.DataJSON, want)
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
    "permissions": ["net.admin"]
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
	if plugin.ID != "packet_observer" || plugin.Status != pluginStatusActive {
		t.Fatalf("example plugin = %+v, want active packet_observer", plugin)
	}
	if len(plugin.Hooks) != 1 || plugin.Hooks[0].Engine != kernelEngineTC {
		t.Fatalf("example plugin hooks = %+v, want one TC hook", plugin.Hooks)
	}
	if len(plugin.Objects) != 1 || plugin.Objects[0].Status != pluginObjectStatusVerified {
		t.Fatalf("example plugin objects = %+v, want one verified object", plugin.Objects)
	}
}

func TestExamplePPPoEClientPluginManifest(t *testing.T) {
	sourceDir := prepareExamplePPPoEClientPluginForTest(t)
	plugin, err := loadPluginFromDir(sourceDir, "pppoe_client")
	if err != nil {
		t.Fatalf("load pppoe example plugin: %v", err)
	}
	if plugin.ID != "pppoe_client" || plugin.Status != pluginStatusActive {
		t.Fatalf("pppoe example plugin = %+v, want active pppoe_client", plugin)
	}
	if plugin.Control == nil || plugin.Control.Main != "control.js" {
		t.Fatalf("pppoe control = %+v, want control.js", plugin.Control)
	}
	if len(plugin.Resources) != 4 || len(plugin.Actions) != 6 || plugin.UI == nil {
		t.Fatalf("pppoe resources/actions/ui = %d/%d/%+v, want complete example surface", len(plugin.Resources), len(plugin.Actions), plugin.UI)
	}
	if len(plugin.Hooks) != 2 || plugin.Hooks[0].Engine != kernelEngineTC || plugin.Hooks[0].Mode != "rewrite" || plugin.Hooks[1].Engine != kernelEngineTC || plugin.Hooks[1].Mode != "rewrite" {
		t.Fatalf("pppoe hooks = %+v, want two TC rewrite hooks", plugin.Hooks)
	}
	if len(plugin.Objects) != 1 || plugin.Objects[0].Status != pluginObjectStatusVerified || len(plugin.Objects[0].Programs) != 2 {
		t.Fatalf("pppoe objects = %+v, want one verified object with two programs", plugin.Objects)
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
	catalog := applyPluginHookBindingsFromDB(loadPluginCatalog(&Config{PluginsDir: dir}), db)
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

func TestExampleVToLocalPluginManifest(t *testing.T) {
	sourceDir := filepath.Join("..", "..", "examples", "plugins", "vtolocal")
	rootDir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, sourceDir, rootDir)

	plugin, err := loadPluginFromDir(rootDir, "vtolocal")
	if err != nil {
		t.Fatalf("load vtolocal example plugin: %v", err)
	}
	if plugin.ID != "vtolocal" || plugin.Status != pluginStatusActive {
		t.Fatalf("vtolocal example plugin = %+v, want active vtolocal", plugin)
	}
	if plugin.Control == nil || plugin.Control.Main != "control.js" {
		t.Fatalf("vtolocal control = %+v, want control.js", plugin.Control)
	}
	if len(plugin.Resources) != 2 || len(plugin.Actions) != 2 || plugin.UI == nil {
		t.Fatalf("vtolocal resources/actions/ui = %d/%d/%+v, want complete example surface", len(plugin.Resources), len(plugin.Actions), plugin.UI)
	}
	if len(plugin.Control.Permissions) != 2 || strings.Join(plugin.Control.Permissions, ",") != "net.admin,resource" {
		t.Fatalf("vtolocal permissions = %+v, want net.admin,resource", plugin.Control.Permissions)
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
	if plugin.ID != "wan_core" || plugin.Status != pluginStatusActive {
		t.Fatalf("wan_core example plugin = %+v, want active wan_core", plugin)
	}
	if plugin.Control == nil || plugin.Control.Main != "control.js" {
		t.Fatalf("wan_core control = %+v, want control.js", plugin.Control)
	}
	if len(plugin.Resources) != 3 || len(plugin.Actions) != 2 || plugin.UI == nil {
		t.Fatalf("wan_core resources/actions/ui = %d/%d/%+v, want complete example surface", len(plugin.Resources), len(plugin.Actions), plugin.UI)
	}
	if len(plugin.Control.Permissions) != 2 || strings.Join(plugin.Control.Permissions, ",") != "net.admin,resource" {
		t.Fatalf("wan_core permissions = %+v, want net.admin,resource", plugin.Control.Permissions)
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
	  "driver":"pppoe",
	  "driver_plugin":"pppoe_client",
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
	for _, want := range []string{
		"ensureVeth:fwdlocal0:fwdvtap0:1492:true",
		"addrReplace:fwdlocal0:169.254.253.1/30",
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
	for _, want := range []string{`"phase":"applied"`, `"driver":"pppoe"`, `"parent_interface":"fwdvtap0"`, `"egress_nat_parent_interface":"fwdvtap0"`, `"pd_prefix":"2001:db8:1234::/56"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", record.DataJSON, want)
		}
	}
}

func TestExamplePPPoEClientDiscoverAction(t *testing.T) {
	sourceDir := prepareExamplePPPoEClientPluginForTest(t)
	plugin, err := loadPluginFromDir(sourceDir, "pppoe_client")
	if err != nil {
		t.Fatalf("load pppoe example plugin: %v", err)
	}
	action := plugin.Actions[0]
	if action.ID != "discover" {
		t.Fatalf("first action = %q, want discover", action.ID)
	}

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(sourceDir)}, nil).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{
		recvFrame: pluginControlL2Frame{
			Interface: "eth0",
			IfIndex:   7,
			EtherType: 0x8863,
			DstMAC:    mustMACForTest(t, "02:00:00:00:00:01"),
			SrcMAC:    mustMACForTest(t, "02:00:00:00:00:02"),
			Payload:   mustHexForTest(t, "1107000000170101000001020007746573742d616301030004aabbccdd"),
		},
	}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"interface":"eth0","timeout_ms":50}`)); err != nil {
		t.Fatalf("ApplyPluginAction(discover) error = %v", err)
	}
	transport := rt.l2Transport.(*pluginControlL2TransportTest)
	if len(transport.exchanges) != 1 {
		t.Fatalf("l2 exchanges = %+v, want one PADI exchange", transport.exchanges)
	}
	if got := transport.exchanges[0].Send.EtherType; got != 0x8863 {
		t.Fatalf("PADI ethertype = 0x%x, want 0x8863", got)
	}
	if got := hex.EncodeToString(transport.exchanges[0].Send.Payload[:2]); got != "1109" {
		t.Fatalf("PADI payload prefix = %q, want 1109", got)
	}

	record, err := store.GetPluginRecord(db, "pppoe_client", "sessions", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(pppoe sessions/last) error = %v", err)
	}
	for _, want := range []string{`"phase":"pado"`, `"ac_mac":"02:00:00:00:00:02"`, `"ac_name":"test-ac"`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("pppoe sessions/last = %s, missing %s", record.DataJSON, want)
		}
	}
}

func TestExamplePPPoEClientProbeSessionNegotiatesIPv4IPv6PD(t *testing.T) {
	sourceDir := prepareExamplePPPoEClientPluginForTest(t)
	plugin, err := loadPluginFromDir(sourceDir, "pppoe_client")
	if err != nil {
		t.Fatalf("load pppoe example plugin: %v", err)
	}
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "probe_session" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("probe_session action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(sourceDir)}, nil).(*gojaPluginControlRuntime)
	rt.l2Transport = &pluginControlL2TransportTest{
		recvErr: errPluginControlL2Timeout,
		exchangeFunc: func(req pluginControlL2ExchangeRequest) (pluginControlL2Frame, error) {
			switch req.Send.EtherType {
			case 0x8863:
				payload := req.Send.Payload
				if len(payload) >= 2 && payload[1] == 0x09 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8863, "02:00:00:00:00:02", "02:00:00:00:00:01", "1107000000170101000001020007746573742d616301030004aabbccdd"), nil
				}
				if len(payload) >= 2 && payload[1] == 0x19 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8863, "02:00:00:00:00:02", "02:00:00:00:00:01", "11650010000401010000"), nil
				}
			case 0x8864:
				payload := req.Send.Payload
				if len(payload) < 12 {
					return pluginControlL2Frame{}, fmt.Errorf("short PPPoE session payload %x", payload)
				}
				proto := binary.BigEndian.Uint16(payload[6:8])
				if proto == 0xc021 || proto == 0x8021 || proto == 0x8057 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8864, "02:00:00:00:00:02", "02:00:00:00:00:01", pppoeControlAckPayloadForTest(0x0010, proto, payload[8:])), nil
				}
				if proto == 0x0057 {
					switch dhcpv6MessageTypeFromPPPoEPayloadForTest(payload) {
					case 1:
						return pppoeL2FrameForTest(req.Send.Interface, 0x8864, "02:00:00:00:00:02", "02:00:00:00:00:01", pppoeSessionPayloadForTest(0x0010, 0x0057, dhcpv6IPv6PayloadForTest(2, dhcpv6XIDFromPPPoEPayloadForTest(payload)))), nil
					case 3:
						return pppoeL2FrameForTest(req.Send.Interface, 0x8864, "02:00:00:00:00:02", "02:00:00:00:00:01", pppoeSessionPayloadForTest(0x0010, 0x0057, dhcpv6IPv6PayloadForTest(7, dhcpv6XIDFromPPPoEPayloadForTest(payload)))), nil
					default:
						return pluginControlL2Frame{}, fmt.Errorf("unexpected DHCPv6 message in payload %x", payload)
					}
				}
			}
			return pluginControlL2Frame{}, fmt.Errorf("unexpected exchange ethertype=0x%x payload=%x", req.Send.EtherType, req.Send.Payload)
		},
	}
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{"interface":"eth0","timeout_ms":50,"negotiate_ipv4":true,"negotiate_ipv6":true,"request_pd":true,"send_padt":false}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(probe_session) error = %v", err)
	}
	record, err := store.GetPluginRecord(db, "pppoe_client", "sessions", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(pppoe sessions/last) error = %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(record.DataJSON), &data); err != nil {
		t.Fatalf("Unmarshal(pppoe sessions/last) error = %v: %s", err, record.DataJSON)
	}
	if data["phase"] != "session_probe" || int(data["session_id"].(float64)) != 16 {
		t.Fatalf("pppoe sessions/last = %s, want session_probe session_id=16", record.DataJSON)
	}
	ipcp, _ := data["ipcp"].(map[string]any)
	if ipcp["phase"] != "configure_ack" || ipcp["address"] != "0.0.0.0" {
		t.Fatalf("pppoe ipcp = %#v, want configure_ack", ipcp)
	}
	ipv6cp, _ := data["ipv6cp"].(map[string]any)
	if ipv6cp["phase"] != "configure_ack" || ipv6cp["up"] != true {
		t.Fatalf("pppoe ipv6cp = %#v, want configure_ack up", ipv6cp)
	}
	dhcpv6PD, _ := data["dhcpv6_pd"].(map[string]any)
	if dhcpv6PD["phase"] != "reply" || dhcpv6PD["prefix"] != "2001:db8:1234::/56" {
		t.Fatalf("pppoe dhcpv6_pd = %#v, want reply prefix", dhcpv6PD)
	}
	wanRecord, err := store.GetPluginRecord(db, "pppoe_client", "wan_links", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(pppoe wan_links/default) error = %v", err)
	}
	for _, want := range []string{`"driver":"pppoe"`, `"driver_plugin":"pppoe_client"`, `"state":"up"`, `"usable":true`, `"pd_prefix":"2001:db8:1234::/56"`} {
		if !strings.Contains(wanRecord.DataJSON, want) {
			t.Fatalf("pppoe wan_links/default = %s, missing %s", wanRecord.DataJSON, want)
		}
	}
}

func TestExamplePPPoEClientSyncsWANCoreSessionHandoff(t *testing.T) {
	pppoeDir, _ := prepareExamplePPPoEClientAndWANCorePluginsForTest(t)
	plugin, err := loadPluginFromDir(pppoeDir, "pppoe_client")
	if err != nil {
		t.Fatalf("load pppoe example plugin: %v", err)
	}
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "probe_session" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("probe_session action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	controller := &pluginControlNetAdminTest{}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(pppoeDir)}, nil).(*gojaPluginControlRuntime)
	rt.netAdmin = controller
	rt.l2Transport = &pluginControlL2TransportTest{
		recvErr: errPluginControlL2Timeout,
		exchangeFunc: func(req pluginControlL2ExchangeRequest) (pluginControlL2Frame, error) {
			switch req.Send.EtherType {
			case 0x8863:
				payload := req.Send.Payload
				if len(payload) >= 2 && payload[1] == 0x09 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8863, "02:00:00:00:00:02", "02:00:00:00:00:01", "1107000000170101000001020007746573742d616301030004aabbccdd"), nil
				}
				if len(payload) >= 2 && payload[1] == 0x19 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8863, "02:00:00:00:00:02", "02:00:00:00:00:01", "11650010000401010000"), nil
				}
			case 0x8864:
				payload := req.Send.Payload
				if len(payload) < 12 {
					return pluginControlL2Frame{}, fmt.Errorf("short PPPoE session payload %x", payload)
				}
				proto := binary.BigEndian.Uint16(payload[6:8])
				if proto == 0xc021 || proto == 0x8021 || proto == 0x8057 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8864, "02:00:00:00:00:02", "02:00:00:00:00:01", pppoeControlAckPayloadForTest(0x0010, proto, payload[8:])), nil
				}
				if proto == 0x0057 {
					switch dhcpv6MessageTypeFromPPPoEPayloadForTest(payload) {
					case 1:
						return pppoeL2FrameForTest(req.Send.Interface, 0x8864, "02:00:00:00:00:02", "02:00:00:00:00:01", pppoeSessionPayloadForTest(0x0010, 0x0057, dhcpv6IPv6PayloadForTest(2, dhcpv6XIDFromPPPoEPayloadForTest(payload)))), nil
					case 3:
						return pppoeL2FrameForTest(req.Send.Interface, 0x8864, "02:00:00:00:00:02", "02:00:00:00:00:01", pppoeSessionPayloadForTest(0x0010, 0x0057, dhcpv6IPv6PayloadForTest(7, dhcpv6XIDFromPPPoEPayloadForTest(payload)))), nil
					default:
						return pluginControlL2Frame{}, fmt.Errorf("unexpected DHCPv6 message in payload %x", payload)
					}
				}
			}
			return pluginControlL2Frame{}, fmt.Errorf("unexpected exchange ethertype=0x%x payload=%x", req.Send.EtherType, req.Send.Payload)
		},
	}
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{"interface":"eth0","timeout_ms":50,"negotiate_ipv4":true,"negotiate_ipv6":true,"request_pd":true,"send_padt":false,"wan_core_sync":true,"wan_core_apply":true,"lan_interface":"fwdvtap0","lan_peer_interface":"fwdlocal0"}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(probe_session sync wan_core) error = %v", err)
	}
	wanLink, err := store.GetPluginRecord(db, "pppoe_client", "wan_links", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(pppoe wan_links/default) error = %v", err)
	}
	for _, want := range []string{`"wan_core_sync":`, `"applied":true`, `"plugin":"wan_core"`, `"status":"synced"`} {
		if !strings.Contains(wanLink.DataJSON, want) {
			t.Fatalf("pppoe wan_links/default = %s, missing %s", wanLink.DataJSON, want)
		}
	}
	wanSession, err := store.GetPluginRecord(db, "wan_core", "sessions", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core sessions/default) error = %v", err)
	}
	if !strings.Contains(wanSession.DataJSON, `"driver":"pppoe"`) || !strings.Contains(wanSession.DataJSON, `"usable":true`) {
		t.Fatalf("wan_core sessions/default = %s, want synced PPPoE session", wanSession.DataJSON)
	}
	wanStatus, err := store.GetPluginRecord(db, "wan_core", "status", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core status/default) error = %v", err)
	}
	for _, want := range []string{`"phase":"applied"`, `"parent_interface":"fwdvtap0"`, `"pd_prefix":"2001:db8:1234::/56"`} {
		if !strings.Contains(wanStatus.DataJSON, want) {
			t.Fatalf("wan_core status/default = %s, missing %s", wanStatus.DataJSON, want)
		}
	}
	if !containsString(controller.calls, "ensureVeth:fwdlocal0:fwdvtap0:1492:true") {
		t.Fatalf("net admin calls = %+v, missing wan_core ensureVeth", controller.calls)
	}
}

func TestExamplePPPoEClientTrafficProbeInstallsTunnelFromInterfaceNames(t *testing.T) {
	sourceDir := prepareExamplePPPoEClientPluginForTest(t)
	plugin, err := loadPluginFromDir(sourceDir, "pppoe_client")
	if err != nil {
		t.Fatalf("load pppoe example plugin: %v", err)
	}
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "traffic_probe" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("traffic_probe action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	controller := &pluginControlMapControllerTest{}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(sourceDir)}, controller).(*gojaPluginControlRuntime)
	rt.netAdmin = &pluginControlNetAdminTest{}
	rt.l2Transport = &pluginControlL2TransportTest{
		recvErr: errPluginControlL2Timeout,
		exchangeFunc: func(req pluginControlL2ExchangeRequest) (pluginControlL2Frame, error) {
			switch req.Send.EtherType {
			case 0x8863:
				payload := req.Send.Payload
				if len(payload) >= 2 && payload[1] == 0x09 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8863, "02:00:00:00:00:02", "02:00:00:00:00:01", "1107000000170101000001020007746573742d616301030004aabbccdd"), nil
				}
				if len(payload) >= 2 && payload[1] == 0x19 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8863, "02:00:00:00:00:02", "02:00:00:00:00:01", "11650010000401010000"), nil
				}
			case 0x8864:
				payload := req.Send.Payload
				if len(payload) < 12 {
					return pluginControlL2Frame{}, fmt.Errorf("short PPPoE session payload %x", payload)
				}
				proto := binary.BigEndian.Uint16(payload[6:8])
				if proto == 0xc021 {
					return pppoeL2FrameForTest(req.Send.Interface, 0x8864, "02:00:00:00:00:02", "02:00:00:00:00:01", pppoeControlAckPayloadForTest(0x0010, proto, payload[8:])), nil
				}
			}
			return pluginControlL2Frame{}, fmt.Errorf("unexpected exchange ethertype=0x%x payload=%x", req.Send.EtherType, req.Send.Payload)
		},
	}
	t.Cleanup(func() { _ = rt.Close() })

	payload := json.RawMessage(`{"interface":"eth0","lan_interface":"fwdvtap0","lan_peer_interface":"fwdlocal0","wan_interface":"eth0","timeout_ms":50,"negotiate_ipv4":false,"send_padt":false}`)
	if err := rt.ApplyPluginAction(plugin, action, payload); err != nil {
		t.Fatalf("ApplyPluginAction(traffic_probe) error = %v", err)
	}
	wantValue := "01000000660000000700000010000000020000001002020000001001020000000001020000000002"
	wantCall := "put:pppoe_client:pppoe_tunnel:pppoe_tunnel_config:00000000:" + wantValue
	if len(controller.calls) != 1 || controller.calls[0] != wantCall {
		t.Fatalf("map controller calls = %+v, want %s", controller.calls, wantCall)
	}
	record, err := store.GetPluginRecord(db, "pppoe_client", "sessions", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(pppoe sessions/last) error = %v", err)
	}
	for _, want := range []string{`"tunnel_installed":true`, `"mode":"direct_vtap"`, `"requires_kernel_tc_prepared_l2":false`, `"lan_ifindex":102`, `"wan_ifindex":7`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("pppoe sessions/last = %s, missing %s", record.DataJSON, want)
		}
	}
}

func TestExamplePPPoEClientDisconnectClearsTunnelConfig(t *testing.T) {
	sourceDir := prepareExamplePPPoEClientPluginForTest(t)
	plugin, err := loadPluginFromDir(sourceDir, "pppoe_client")
	if err != nil {
		t.Fatalf("load pppoe example plugin: %v", err)
	}
	var action PluginAction
	for _, candidate := range plugin.Actions {
		if candidate.ID == "disconnect" {
			action = candidate
			break
		}
	}
	if action.ID == "" {
		t.Fatalf("disconnect action not found in %+v", plugin.Actions)
	}

	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "pppoe_client",
		ResourceID: "sessions",
		RecordKey:  "last",
		DataJSON:   `{"phase":"session_probe","session_id":16,"ac_mac":"02:00:00:00:00:02"}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(pppoe sessions/last) error = %v", err)
	}
	controller := &pluginControlMapControllerTest{}
	rt := newPluginControlRuntime(db, &Config{PluginsDir: filepath.Dir(sourceDir)}, controller).(*gojaPluginControlRuntime)
	transport := &pluginControlL2TransportTest{}
	rt.l2Transport = transport
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"interface":"eth0"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(disconnect) error = %v", err)
	}
	if len(transport.sends) != 1 || transport.sends[0].EtherType != 0x8863 || len(transport.sends[0].Payload) < 2 || transport.sends[0].Payload[1] != 0xa7 {
		t.Fatalf("disconnect sends = %+v, want one PADT discovery frame", transport.sends)
	}
	wantClear := "put:pppoe_client:pppoe_tunnel:pppoe_tunnel_config:00000000:" + strings.Repeat("00", 40)
	if len(controller.calls) != 1 || controller.calls[0] != wantClear {
		t.Fatalf("map controller calls = %+v, want %s", controller.calls, wantClear)
	}
	record, err := store.GetPluginRecord(db, "pppoe_client", "sessions", "last")
	if err != nil {
		t.Fatalf("GetPluginRecord(pppoe sessions/last) error = %v", err)
	}
	if !strings.Contains(record.DataJSON, `"phase":"disconnected"`) || !strings.Contains(record.DataJSON, `"padt_sent":true`) {
		t.Fatalf("pppoe sessions/last = %s, want disconnected padt_sent", record.DataJSON)
	}
}

func prepareExamplePPPoEClientPluginForTest(t *testing.T) string {
	t.Helper()

	sourceDir := filepath.Join("..", "..", "examples", "plugins", "pppoe_client")
	rootDir := filepath.Join(t.TempDir(), "pppoe_client")
	copyDirForTest(t, sourceDir, rootDir)
	compileBPFObjectFromSource(t, filepath.Join(rootDir, "pppoe_tunnel.bpf.c"), filepath.Join(rootDir, "pppoe_tunnel.o"))
	return rootDir
}

func prepareExamplePPPoEClientAndWANCorePluginsForTest(t *testing.T) (string, string) {
	t.Helper()

	pluginsDir := t.TempDir()
	pppoeDir := filepath.Join(pluginsDir, "pppoe_client")
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "pppoe_client"), pppoeDir)
	compileBPFObjectFromSource(t, filepath.Join(pppoeDir, "pppoe_tunnel.bpf.c"), filepath.Join(pppoeDir, "pppoe_tunnel.o"))
	wanCoreDir := filepath.Join(pluginsDir, "wan_core")
	copyDirForTest(t, filepath.Join("..", "..", "examples", "plugins", "wan_core"), wanCoreDir)
	return pppoeDir, wanCoreDir
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

type pluginRuntimeApplyTestRuntime struct {
	resourceCalls []pluginRuntimeApplyResourceCall
	actionCalls   []pluginRuntimeApplyActionCall
	resourceErr   error
	actionErr     error
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

func (rt *pluginRuntimeApplyTestRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return nil, nil
}

func (rt *pluginRuntimeApplyTestRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt *pluginRuntimeApplyTestRuntime) Maintain() error {
	return nil
}

func (rt *pluginRuntimeApplyTestRuntime) SnapshotAssignments() map[int64]string {
	return nil
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

func pppoeL2FrameForTest(iface string, etherType uint16, srcMAC string, dstMAC string, payloadHex string) pluginControlL2Frame {
	src, _ := parsePluginControlMAC(srcMAC)
	dst, _ := parsePluginControlMAC(dstMAC)
	payload, _ := hex.DecodeString(payloadHex)
	return pluginControlL2Frame{
		Interface: iface,
		IfIndex:   7,
		EtherType: etherType,
		SrcMAC:    src,
		DstMAC:    dst,
		Payload:   payload,
	}
}

func pppoeControlAckPayloadForTest(sessionID uint16, protocol uint16, request []byte) string {
	reply := append([]byte(nil), request...)
	if len(reply) >= 1 {
		reply[0] = 2
	}
	return pppoeSessionPayloadForTest(sessionID, protocol, bytesToHexForTest(reply))
}

func pppoeSessionPayloadForTest(sessionID uint16, protocol uint16, payloadHex string) string {
	payload, _ := hex.DecodeString(payloadHex)
	frame := make([]byte, 8+len(payload))
	frame[0] = 0x11
	frame[1] = 0x00
	binary.BigEndian.PutUint16(frame[2:4], sessionID)
	binary.BigEndian.PutUint16(frame[4:6], uint16(2+len(payload)))
	binary.BigEndian.PutUint16(frame[6:8], protocol)
	copy(frame[8:], payload)
	return bytesToHexForTest(frame)
}

func dhcpv6MessageTypeFromPPPoEPayloadForTest(payload []byte) int {
	if len(payload) < 57 {
		return 0
	}
	if binary.BigEndian.Uint16(payload[6:8]) != 0x0057 {
		return 0
	}
	ipv6 := payload[8:]
	if len(ipv6) < 49 || ipv6[0]>>4 != 6 || ipv6[6] != 17 {
		return 0
	}
	if binary.BigEndian.Uint16(ipv6[40:42]) != 546 || binary.BigEndian.Uint16(ipv6[42:44]) != 547 {
		return 0
	}
	return int(ipv6[48])
}

func dhcpv6IPv6PayloadForTest(messageType int, xid []byte) string {
	dhcp := dhcpv6PayloadForTest(messageType, xid)
	udpLen := 8 + len(dhcp)
	ipv6 := make([]byte, 40+udpLen)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(udpLen))
	ipv6[6] = 17
	ipv6[7] = 1
	copy(ipv6[8:24], []byte{
		0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 2,
	})
	copy(ipv6[24:40], []byte{
		0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
	})
	binary.BigEndian.PutUint16(ipv6[40:42], 547)
	binary.BigEndian.PutUint16(ipv6[42:44], 546)
	binary.BigEndian.PutUint16(ipv6[44:46], uint16(udpLen))
	copy(ipv6[48:], dhcp)
	return bytesToHexForTest(ipv6)
}

func dhcpv6AdvertiseIPv6PayloadForTest() string {
	return dhcpv6IPv6PayloadForTest(2, nil)
}

func dhcpv6PayloadForTest(messageType int, xid []byte) []byte {
	if messageType <= 0 || messageType > 255 {
		messageType = 2
	}
	if len(xid) != 3 {
		xid = []byte{0xaa, 0xbb, 0xcc}
	}
	serverID := []byte{0, 3, 0, 1, 0x02, 0, 0, 0, 0, 2}
	prefix := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	iaprefix := make([]byte, 25)
	binary.BigEndian.PutUint32(iaprefix[0:4], 3600)
	binary.BigEndian.PutUint32(iaprefix[4:8], 7200)
	iaprefix[8] = 56
	copy(iaprefix[9:25], prefix)
	iaPDValue := make([]byte, 12)
	binary.BigEndian.PutUint32(iaPDValue[0:4], 1)
	iaPDValue = append(iaPDValue, dhcpv6OptionForTest(26, iaprefix)...)
	payload := []byte{byte(messageType), xid[0], xid[1], xid[2]}
	payload = append(payload, dhcpv6OptionForTest(2, serverID)...)
	payload = append(payload, dhcpv6OptionForTest(25, iaPDValue)...)
	return payload
}

func dhcpv6XIDFromPPPoEPayloadForTest(payload []byte) []byte {
	if len(payload) < 60 {
		return nil
	}
	return append([]byte(nil), payload[57:60]...)
}

func dhcpv6OptionForTest(code uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(out[0:2], code)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

func bytesToHexForTest(data []byte) string {
	return hex.EncodeToString(data)
}

func writeTestPlugin(t *testing.T, pluginsDir, name, manifest string) {
	t.Helper()

	pluginDir := filepath.Join(pluginsDir, name)
	uiDir := filepath.Join(pluginDir, "ui")
	if err := os.MkdirAll(uiDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
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

func writePluginControlScript(t *testing.T, pluginsDir, name, source string) {
	t.Helper()

	path := filepath.Join(pluginsDir, name, "control.js")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(control.js) error = %v", err)
	}
}

func loadTestPluginByID(t *testing.T, cfg *Config, id string) LoadedPlugin {
	t.Helper()

	catalog := loadPluginCatalog(cfg)
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

type pluginControlMapControllerTest struct {
	calls []string
}

func (c *pluginControlMapControllerTest) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	c.calls = append(c.calls, fmt.Sprintf("put:%s:%s:%s:%x:%x", pluginID, objectID, mapName, key, value))
	return nil
}

func (c *pluginControlMapControllerTest) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	c.calls = append(c.calls, fmt.Sprintf("delete:%s:%s:%s:%x", pluginID, objectID, mapName, key))
	return nil
}

func (c *pluginControlMapControllerTest) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	c.calls = append(c.calls, fmt.Sprintf("clear:%s:%s:%s", pluginID, objectID, mapName))
	return nil
}

type pluginControlNetAdminTest struct {
	calls []string
}

func (c *pluginControlNetAdminTest) LinkGet(name string) (pluginControlNetLinkInfo, error) {
	c.calls = append(c.calls, "get:"+name)
	return c.linkInfo(name), nil
}

func (c *pluginControlNetAdminTest) LinkList() ([]pluginControlNetLinkInfo, error) {
	c.calls = append(c.calls, "list")
	return []pluginControlNetLinkInfo{
		c.linkInfo("fwdlocal0"),
		c.linkInfo("fwdvtap0"),
	}, nil
}

func (c *pluginControlNetAdminTest) LinkEnsureVeth(req pluginControlNetVethRequest) (pluginControlNetVethResult, error) {
	c.calls = append(c.calls, fmt.Sprintf("ensureVeth:%s:%s:%d:%t", req.Host, req.Peer, req.MTU, req.Up))
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
	return nil
}

func (c *pluginControlNetAdminTest) LinkSetUp(name string, up bool) error {
	c.calls = append(c.calls, fmt.Sprintf("setUp:%s:%t", name, up))
	return nil
}

func (c *pluginControlNetAdminTest) LinkSetMTU(name string, mtu int) error {
	c.calls = append(c.calls, fmt.Sprintf("setMTU:%s:%d", name, mtu))
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
	if name == "eth0" {
		return pluginControlNetLinkInfo{Name: name, IfIndex: 7, Kind: "device", MTU: 1500, MAC: "02:00:00:00:00:01", Up: true}
	}
	if name == "fwdlocal0" {
		return pluginControlNetLinkInfo{Name: name, IfIndex: 101, Kind: "veth", MTU: 1492, MAC: "02:00:00:00:10:01", Up: true}
	}
	return pluginControlNetLinkInfo{Name: name, IfIndex: 102, Kind: "veth", MTU: 1492, MAC: "02:00:00:00:10:02", Up: true}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
	cmd := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", sourcePath, "-o", objectPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("compile test bpf object: %v: %s", err, strings.TrimSpace(string(out)))
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
