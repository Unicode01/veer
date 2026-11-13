package app

import (
	"os"
	"strings"
)

// pluginTestExperimentalEnv switches experimental features on for the
// runtimes plugin tests build themselves, as it does for the dataplane perf
// configs, so a suite can run with a feature on. Features a test sets keep
// the test's value.
const pluginTestExperimentalEnv = "FORWARD_PERF_EXPERIMENTAL"

func pluginsEnabledTestConfig(cfg *Config) *Config {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.PluginsEnabledSetting == nil {
		enabled := true
		cfg.PluginsEnabledSetting = &enabled
	}
	if cfg.PluginsIsolationSetting == nil {
		disabled := false
		cfg.PluginsIsolationSetting = &disabled
	}
	if cfg.PluginsMinSandboxLevel == "" {
		cfg.PluginsMinSandboxLevel = pluginSandboxLevelNone
	}
	if cfg.PluginsRequireSigned == nil {
		requireSigned := false
		cfg.PluginsRequireSigned = &requireSigned
	}
	if cfg.PluginAdminToken == "" {
		cfg.PluginAdminToken = "test-plugin-admin"
	}
	for _, feature := range strings.Split(os.Getenv(pluginTestExperimentalEnv), ",") {
		name := normalizeExperimentalFeatureName(feature)
		if name == "" {
			continue
		}
		if cfg.Experimental == nil {
			cfg.Experimental = make(map[string]bool)
		}
		if _, set := cfg.Experimental[name]; !set {
			cfg.Experimental[name] = true
		}
	}
	return cfg
}
