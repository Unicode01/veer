package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigDefaultsManagedNetworkAutoRepairEnabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !cfg.ManagedNetworkAutoRepairEnabled() {
		t.Fatal("ManagedNetworkAutoRepairEnabled() = false, want true by default")
	}
}

func TestLoadConfigAllowsDisablingManagedNetworkAutoRepair(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token",
  "managed_network_auto_repair": false
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.ManagedNetworkAutoRepairEnabled() {
		t.Fatal("ManagedNetworkAutoRepairEnabled() = true, want false when explicitly disabled")
	}
}

func TestLoadConfigDefaultsWebBindToLoopback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.WebBind != "127.0.0.1" {
		t.Fatalf("WebBind = %q, want 127.0.0.1", cfg.WebBind)
	}
}

func TestLoadConfigNormalizesWebBind(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_bind": " [::1] ",
  "web_port": 8080,
  "web_token": "test-token"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.WebBind != "::1" {
		t.Fatalf("WebBind = %q, want ::1", cfg.WebBind)
	}
}

func TestLoadConfigRequiresStrongTokensForRemoteManagement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		webToken   string
		adminToken string
		wantField  string
	}{
		{name: "weak web token", webToken: "short-token", wantField: "web_token"},
		{name: "weak plugin admin token", webToken: "0123456789abcdefghijklmn", adminToken: "short-admin", wantField: "plugin_admin_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			data := `{"web_bind":"0.0.0.0","web_token":"` + tt.webToken + `","plugin_admin_token":"` + tt.adminToken + `"}`
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), tt.wantField) || !strings.Contains(err.Error(), "24 characters") {
				t.Fatalf("loadConfig() error = %v, want strong %s error", err, tt.wantField)
			}
		})
	}
}

func TestLoadConfigAcceptsStrongTokensForRemoteManagement(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_bind": "0.0.0.0",
  "web_token": "0123456789abcdefghijklmn",
  "plugin_admin_token": "zyxwvutsrqponmlkjihgfedc"
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
}

func TestLoadConfigRejectsUnusableManagementTokens(t *testing.T) {
	t.Parallel()

	for _, data := range []string{
		`{"web_token":"token with spaces"}`,
		`{"web_token":" leading-token"}`,
		`{"web_token":"test-token","plugin_admin_token":"admin-token\u0080"}`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "whitespace or control") {
			t.Fatalf("loadConfig(%s) error = %v, want whitespace/control error", data, err)
		}
	}
}

func TestLoadConfigDefaultsWebUIEnabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !cfg.WebUIEnabled() {
		t.Fatal("WebUIEnabled() = false, want true by default")
	}
}

func TestLoadConfigAllowsDisablingWebUI(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_ui_enabled": false,
  "web_port": 8080,
  "web_token": "test-token"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.WebUIEnabled() {
		t.Fatal("WebUIEnabled() = true, want false when explicitly disabled")
	}
}

func TestLoadConfigDefaultsPluginsDisabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.PluginsEnabled() {
		t.Fatal("PluginsEnabled() = true, want false by default")
	}
	if cfg.PluginsDir != defaultPluginsDir {
		t.Fatalf("PluginsDir = %q, want %q", cfg.PluginsDir, defaultPluginsDir)
	}
	if cfg.PluginsDataplaneEnabled() {
		t.Fatal("PluginsDataplaneEnabled() = true, want false by default")
	}
	if !cfg.PluginsIsolationEnabled() {
		t.Fatal("PluginsIsolationEnabled() = false, want true by default")
	}
	if cfg.PluginMinimumSandboxLevel() != pluginSandboxLevelFull {
		t.Fatalf("PluginMinimumSandboxLevel() = %q, want full", cfg.PluginMinimumSandboxLevel())
	}
	if !cfg.PluginsRequireSignedPackages() {
		t.Fatal("PluginsRequireSignedPackages() = false, want true by default")
	}
	if cfg.PluginsMaxInstalled != 128 || cfg.PluginsMaxStaged != 32 || cfg.PluginsStorageLimitMB != 2048 {
		t.Fatalf("plugin quota defaults = installed:%d staged:%d storage:%d", cfg.PluginsMaxInstalled, cfg.PluginsMaxStaged, cfg.PluginsStorageLimitMB)
	}
	if cfg.PluginsRepositoryRefreshMinutes != 360 {
		t.Fatalf("PluginsRepositoryRefreshMinutes = %d, want 360", cfg.PluginsRepositoryRefreshMinutes)
	}
	limits := pluginResourceLimitsFromConfig(cfg)
	if limits.ObjectsPerPlugin != pluginDefaultMaxObjectsPerPlugin || limits.PluginMapMemoryBytes != uint64(pluginDefaultMaxPluginMapMemoryMB)<<20 {
		t.Fatalf("plugin resource limit defaults = %+v", limits)
	}
}

func TestLoadConfigPluginSecurityPolicy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_token": "test-token",
  "plugins_min_sandbox_level": "partial",
  "plugins_require_signed_packages": false
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PluginMinimumSandboxLevel() != pluginSandboxLevelPartial || cfg.PluginsRequireSignedPackages() {
		t.Fatalf("plugin security policy = sandbox:%q signed:%v", cfg.PluginMinimumSandboxLevel(), cfg.PluginsRequireSignedPackages())
	}
}

func TestLoadConfigRejectsInvalidPluginSandboxLevel(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"web_token":"test-token","plugins_min_sandbox_level":"best-effort"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "plugins_min_sandbox_level") {
		t.Fatalf("invalid sandbox level error = %v", err)
	}
}

func TestLoadConfigRejectsSharedPluginAdminToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_token": "same-token",
  "plugin_admin_token": "same-token"
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("shared plugin admin token error = %v", err)
	}
}

func TestLoadConfigAllowsEnablingPlugins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token",
  "plugins_enabled": true
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !cfg.PluginsEnabled() {
		t.Fatal("PluginsEnabled() = false, want true when explicitly enabled")
	}
}

func TestLoadConfigAllowsDisablingPlugins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token",
  "plugins_enabled": false,
  "plugins_dataplane_enabled": true,
  "plugins_isolation": false,
  "plugins_dir": "custom/plugins"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.PluginsEnabled() {
		t.Fatal("PluginsEnabled() = true, want false when explicitly disabled")
	}
	if cfg.PluginsDir != "custom/plugins" {
		t.Fatalf("PluginsDir = %q, want custom/plugins", cfg.PluginsDir)
	}
	if !cfg.PluginsDataplaneEnabled() {
		t.Fatal("PluginsDataplaneEnabled() = false, want true when explicitly enabled")
	}
	if cfg.PluginsIsolationEnabled() {
		t.Fatal("PluginsIsolationEnabled() = true, want false when explicitly disabled")
	}
}
