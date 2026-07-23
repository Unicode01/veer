package app

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
	return cfg
}
