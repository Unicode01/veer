package app

func pluginsEnabledTestConfig(cfg *Config) *Config {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.PluginsEnabledSetting == nil {
		enabled := true
		cfg.PluginsEnabledSetting = &enabled
	}
	return cfg
}
