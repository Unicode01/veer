package app

import (
	"log"
	"time"
)

const pluginRepositoryInitialRefreshDelay = 30 * time.Second

func (pm *ProcessManager) pluginRepositoryRefreshLoop() {
	defer close(pm.pluginRepositoryRefreshDone)
	if !pm.cfg.PluginRemoteInstallEnabled() {
		return
	}
	interval := 360 * time.Minute
	if pm.cfg != nil && pm.cfg.PluginsRepositoryRefreshMinutes > 0 {
		interval = time.Duration(pm.cfg.PluginsRepositoryRefreshMinutes) * time.Minute
	}
	initialDelay := pluginRepositoryInitialRefreshDelay
	if interval < initialDelay {
		initialDelay = interval
	}
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()
	for {
		select {
		case <-pm.shutdownCh:
			return
		case <-timer.C:
			pm.refreshPluginRepositories()
			timer.Reset(interval)
		}
	}
}

func (pm *ProcessManager) refreshPluginRepositories() {
	if pm == nil || pm.cfg == nil || !pm.cfg.PluginsEnabled() || !pm.cfg.PluginRemoteInstallEnabled() {
		return
	}
	pm.pluginPackageMu.Lock()
	defer pm.pluginPackageMu.Unlock()
	manager, err := newPluginPackageManager(pm.cfg, pm.db, pm)
	if err != nil {
		log.Printf("plugin repository refresh: initialize manager: %v", err)
		return
	}
	results := manager.RefreshAllRepositories()
	if err := pluginRepositoryRefreshResultsError(results); err != nil {
		log.Printf("plugin repository refresh: %v", err)
	}
}
