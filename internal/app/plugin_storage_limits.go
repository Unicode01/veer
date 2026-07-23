package app

import (
	"fmt"
	"math"

	"github.com/Unicode01/veer/internal/store"
)

func ensurePluginRecordStorageQuota(db store.RuleStore, pluginID string, previous *store.PluginRecord, next store.PluginRecord, limits PluginResourceLimits) error {
	delta := store.PluginRecordStorageBytes(next)
	if previous != nil {
		delta -= store.PluginRecordStorageBytes(*previous)
	}
	return ensurePluginDatabaseStorageQuota(db, pluginID, delta, limits)
}

func ensurePluginDatabaseStorageQuota(db store.RuleStore, pluginID string, delta int64, limits PluginResourceLimits) error {
	if db == nil {
		return fmt.Errorf("plugin data store is unavailable")
	}
	if delta <= 0 {
		return nil
	}
	pluginUsage, err := store.GetPluginRecordStorageUsage(db, pluginID)
	if err != nil {
		return err
	}
	globalUsage, err := store.GetGlobalPluginRecordStorageUsage(db)
	if err != nil {
		return err
	}
	if delta > limits.PluginDatabaseBytes || pluginUsage.Bytes > limits.PluginDatabaseBytes-delta {
		return fmt.Errorf("plugin database quota exceeded: plugin=%s used=%d delta=%d limit=%d bytes", pluginID, pluginUsage.Bytes, delta, limits.PluginDatabaseBytes)
	}
	if delta > limits.GlobalDatabaseBytes || globalUsage.Bytes > limits.GlobalDatabaseBytes-delta {
		return fmt.Errorf("global plugin database quota exceeded: used=%d delta=%d limit=%d bytes", globalUsage.Bytes, delta, limits.GlobalDatabaseBytes)
	}
	return nil
}

func pluginResourceLimitsForRollback() PluginResourceLimits {
	limits := pluginResourceLimitsFromConfig(nil)
	limits.PluginDatabaseBytes = math.MaxInt64
	limits.GlobalDatabaseBytes = math.MaxInt64
	return limits
}

func pluginResourceLimitsForProcessManager(pm *ProcessManager) PluginResourceLimits {
	if pm == nil {
		return pluginResourceLimitsFromConfig(nil)
	}
	return pluginResourceLimitsFromConfig(pm.cfg)
}
