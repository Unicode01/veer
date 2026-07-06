//go:build !linux

package app

func newPluginDataplaneRuntime(cfg *Config) pluginDataplaneRuntime {
	return &unsupportedPluginDataplaneRuntime{cfg: cfg}
}

type unsupportedPluginDataplaneRuntime struct {
	cfg *Config
}

func (rt *unsupportedPluginDataplaneRuntime) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	states := make(map[string]PluginRuntimeState)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		state := externalPluginRuntimeState()
		if rt.cfg != nil && rt.cfg.PluginsDataplaneEnabled() {
			state.Reason = "external dataplane plugins are not supported on this platform"
		}
		states[plugin.ID] = state
	}
	return pluginRuntimeSnapshot{Plugins: states}
}

func (rt *unsupportedPluginDataplaneRuntime) Snapshot() pluginRuntimeSnapshot {
	return pluginRuntimeSnapshot{}
}

func (rt *unsupportedPluginDataplaneRuntime) Close() error {
	return nil
}
