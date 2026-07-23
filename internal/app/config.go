package app

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	experimentalFeatureBridgeXDP                 = "bridge_xdp"
	experimentalFeatureXDPGeneric                = "xdp_generic"
	experimentalFeatureKernelTraffic             = "kernel_traffic_stats"
	experimentalFeatureKernelTCDiag              = "kernel_tc_diag"
	experimentalFeatureKernelTCDiagVerbose       = "kernel_tc_diag_verbose"
	experimentalFeatureKernelTCRedirectNeighFast = "kernel_tc_redirect_neigh_fast"
	experimentalFeatureKernelTCPreparedL2        = "kernel_tc_prepared_l2"
	experimentalFeatureKernelTCReplyL2Cache      = "kernel_tc_reply_l2_cache"
	insecureDefaultWebToken                      = "change-me-to-a-secure-token"
	insecureDefaultPluginAdminToken              = "change-me-to-a-separate-plugin-admin-token"
)

type Config struct {
	WebPort                         int                       `json:"web_port"`
	WebBind                         string                    `json:"web_bind"`
	WebUIEnabledSetting             *bool                     `json:"web_ui_enabled,omitempty"`
	WebToken                        string                    `json:"web_token"`
	PluginAdminToken                string                    `json:"plugin_admin_token,omitempty"`
	MaxWorkers                      int                       `json:"max_workers"`
	DrainTimeoutHours               int                       `json:"drain_timeout_hours"`
	ManagedNetworkAutoRepair        *bool                     `json:"managed_network_auto_repair,omitempty"`
	PluginsEnabledSetting           *bool                     `json:"plugins_enabled,omitempty"`
	PluginsDataplaneSetting         *bool                     `json:"plugins_dataplane_enabled,omitempty"`
	PluginsIsolationSetting         *bool                     `json:"plugins_isolation,omitempty"`
	PluginsMinSandboxLevel          string                    `json:"plugins_min_sandbox_level,omitempty"`
	PluginsRequireSigned            *bool                     `json:"plugins_require_signed_packages,omitempty"`
	PluginsDir                      string                    `json:"plugins_dir"`
	PluginsMaxInstalled             int                       `json:"plugins_max_installed"`
	PluginsMaxStaged                int                       `json:"plugins_max_staged"`
	PluginsStorageLimitMB           int                       `json:"plugins_storage_limit_mb"`
	PluginsRepositoryRefreshMinutes int                       `json:"plugins_repository_refresh_minutes"`
	PluginsResourceLimits           PluginResourceLimitConfig `json:"plugins_resource_limits,omitempty"`
	DefaultEngine                   string                    `json:"default_engine"`
	KernelEngineOrder               []string                  `json:"kernel_engine_order"`
	KernelRulesMapLimit             int                       `json:"kernel_rules_map_limit"`
	KernelFlowsMapLimit             int                       `json:"kernel_flows_map_limit"`
	KernelNATMapLimit               int                       `json:"kernel_nat_ports_map_limit"`
	KernelNATPortMin                int                       `json:"kernel_nat_port_min"`
	KernelNATPortMax                int                       `json:"kernel_nat_port_max"`
	Experimental                    map[string]bool           `json:"experimental_features"`
	Tags                            []string                  `json:"tags"`

	pluginHostTestMode bool
}

func loadConfig(path string) (*Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("config file must not be a symbolic link: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("config path is not a regular file: %s", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure config permissions: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.WebPort == 0 {
		cfg.WebPort = 8080
	}
	cfg.WebBind = normalizeWebBind(cfg.WebBind)
	cfg.WebToken = strings.TrimSpace(cfg.WebToken)
	cfg.PluginAdminToken = strings.TrimSpace(cfg.PluginAdminToken)
	if cfg.WebToken == "" {
		return nil, fmt.Errorf("web_token must not be empty")
	}
	if cfg.WebToken == insecureDefaultWebToken {
		return nil, fmt.Errorf("web_token must not use the example placeholder value")
	}
	if cfg.PluginAdminToken == insecureDefaultPluginAdminToken {
		return nil, fmt.Errorf("plugin_admin_token must not use the example placeholder value")
	}
	if cfg.PluginAdminToken != "" && cfg.PluginAdminToken == cfg.WebToken {
		return nil, fmt.Errorf("plugin_admin_token must differ from web_token")
	}
	if cfg.MaxWorkers < 0 {
		cfg.MaxWorkers = 0
	}
	if cfg.DrainTimeoutHours == 0 {
		cfg.DrainTimeoutHours = 24
	}
	cfg.PluginsDir = normalizePluginsDir(cfg.PluginsDir)
	cfg.PluginsMinSandboxLevel = strings.ToLower(strings.TrimSpace(cfg.PluginsMinSandboxLevel))
	if cfg.PluginsMinSandboxLevel == "" {
		cfg.PluginsMinSandboxLevel = pluginSandboxLevelFull
	}
	if !validPluginSandboxLevel(cfg.PluginsMinSandboxLevel) {
		return nil, fmt.Errorf("plugins_min_sandbox_level must be one of none, minimal, partial, full")
	}
	cfg.PluginsMaxInstalled = normalizeBoundedConfigValue(cfg.PluginsMaxInstalled, 128, 1, 1024)
	cfg.PluginsMaxStaged = normalizeBoundedConfigValue(cfg.PluginsMaxStaged, 32, 1, 256)
	cfg.PluginsStorageLimitMB = normalizeBoundedConfigValue(cfg.PluginsStorageLimitMB, 2048, 256, 65536)
	cfg.PluginsRepositoryRefreshMinutes = normalizeBoundedConfigValue(cfg.PluginsRepositoryRefreshMinutes, 360, 15, 10080)
	cfg.PluginsResourceLimits, err = normalizePluginResourceLimitConfig(cfg.PluginsResourceLimits)
	if err != nil {
		return nil, err
	}
	cfg.KernelRulesMapLimit = normalizeKernelRulesMapLimit(cfg.KernelRulesMapLimit)
	cfg.KernelFlowsMapLimit = normalizeKernelFlowsMapLimit(cfg.KernelFlowsMapLimit)
	cfg.KernelNATMapLimit = normalizeKernelNATMapLimit(cfg.KernelNATMapLimit)
	cfg.KernelNATPortMin, cfg.KernelNATPortMax, err = normalizeKernelNATPortRange(cfg.KernelNATPortMin, cfg.KernelNATPortMax)
	if err != nil {
		return nil, err
	}
	cfg.DefaultEngine = normalizeRuleEnginePreference(cfg.DefaultEngine)
	if !isValidRuleEnginePreference(cfg.DefaultEngine) {
		cfg.DefaultEngine = ruleEngineAuto
	}
	cfg.KernelEngineOrder = normalizeKernelEngineOrder(cfg.KernelEngineOrder)
	cfg.Experimental = normalizeExperimentalFeatures(cfg.Experimental)
	return &cfg, nil
}

func normalizeBoundedConfigValue(value, fallback, minimum, maximum int) int {
	if value == 0 {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func normalizeWebBind(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") && len(value) > 2 {
		value = value[1 : len(value)-1]
	}
	if value == "" {
		return "127.0.0.1"
	}
	return value
}

func (cfg *Config) ExperimentalFeatureEnabled(name string) bool {
	if cfg == nil {
		return false
	}
	name = normalizeExperimentalFeatureName(name)
	if name == "" || cfg.Experimental == nil {
		return false
	}
	return cfg.Experimental[name]
}

func (cfg *Config) ManagedNetworkAutoRepairEnabled() bool {
	if cfg == nil || cfg.ManagedNetworkAutoRepair == nil {
		return true
	}
	return *cfg.ManagedNetworkAutoRepair
}

func (cfg *Config) WebUIEnabled() bool {
	if cfg == nil || cfg.WebUIEnabledSetting == nil {
		return true
	}
	return *cfg.WebUIEnabledSetting
}

func (cfg *Config) PluginsEnabled() bool {
	if cfg == nil || cfg.PluginsEnabledSetting == nil {
		return false
	}
	return *cfg.PluginsEnabledSetting
}

func (cfg *Config) PluginsDataplaneEnabled() bool {
	if cfg == nil || cfg.PluginsDataplaneSetting == nil {
		return false
	}
	return *cfg.PluginsDataplaneSetting
}

func (cfg *Config) PluginsIsolationEnabled() bool {
	if cfg == nil || cfg.PluginsIsolationSetting == nil {
		return true
	}
	return *cfg.PluginsIsolationSetting
}

func (cfg *Config) PluginMinimumSandboxLevel() string {
	if cfg != nil && cfg.pluginHostTestMode {
		return pluginSandboxLevelMinimal
	}
	if cfg == nil {
		return pluginSandboxLevelFull
	}
	level := strings.ToLower(strings.TrimSpace(cfg.PluginsMinSandboxLevel))
	if level == "" {
		return pluginSandboxLevelFull
	}
	if !validPluginSandboxLevel(level) {
		return pluginSandboxLevelFull
	}
	return level
}

func (cfg *Config) PluginsRequireSignedPackages() bool {
	if cfg == nil || cfg.PluginsRequireSigned == nil {
		return true
	}
	return *cfg.PluginsRequireSigned
}

func validPluginSandboxLevel(level string) bool {
	switch level {
	case pluginSandboxLevelNone, pluginSandboxLevelMinimal, pluginSandboxLevelPartial, pluginSandboxLevelFull:
		return true
	default:
		return false
	}
}

func (cfg *Config) PluginAdminAPIEnabled() bool {
	return cfg != nil && strings.TrimSpace(cfg.PluginAdminToken) != ""
}

func normalizePluginsDir(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultPluginsDir
	}
	return value
}

func (cfg *Config) EnabledExperimentalFeatures() []string {
	if cfg == nil || len(cfg.Experimental) == 0 {
		return nil
	}

	out := make([]string, 0, len(cfg.Experimental))
	for name, enabled := range cfg.Experimental {
		if enabled {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeExperimentalFeatures(values map[string]bool) map[string]bool {
	if len(values) == 0 {
		return nil
	}

	out := make(map[string]bool, len(values))
	for raw, enabled := range values {
		name := normalizeExperimentalFeatureName(raw)
		if name == "" {
			continue
		}
		out[name] = enabled
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeExperimentalFeatureName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}
