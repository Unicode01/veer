//go:build linux

package app

import "fmt"

func planPluginObjectStateMigrations(pluginID, objectID string, next []PluginObjectStateMap, previous *loadedPluginObjectRef) ([]PluginEBPFStateMigration, error) {
	if previous == nil || previous.coll == nil {
		return nil, nil
	}
	previousContracts := make(map[string]PluginObjectStateMap, len(previous.StateMaps))
	for _, contract := range previous.StateMaps {
		previousContracts[contract.Name] = contract
	}
	nextContracts := make(map[string]PluginObjectStateMap, len(next))
	for _, contract := range next {
		nextContracts[contract.Name] = contract
	}
	migrations := make([]PluginEBPFStateMigration, 0)
	for _, target := range next {
		if target.Policy != pluginObjectMapMigrate {
			continue
		}
		if current, exists := previousContracts[target.Name]; exists && current.SchemaVersion == target.SchemaVersion {
			continue
		}
		source, exists := previousContracts[target.MigrateFrom]
		if !exists || source.SchemaVersion < 1 {
			return nil, fmt.Errorf("state map %q migration source %q schema is unavailable in the previous object", target.Name, target.MigrateFrom)
		}
		nextSource, exists := nextContracts[target.MigrateFrom]
		if !exists || nextSource.Policy != pluginObjectMapPreserve || nextSource.SchemaVersion != source.SchemaVersion {
			return nil, fmt.Errorf("state map %q migration source %q must preserve previous schema version %d", target.Name, target.MigrateFrom, source.SchemaVersion)
		}
		if source.SchemaVersion >= target.SchemaVersion {
			return nil, fmt.Errorf("state map %q target schema version %d must exceed source %q version %d", target.Name, target.SchemaVersion, target.MigrateFrom, source.SchemaVersion)
		}
		if previous.coll.Maps[target.MigrateFrom] == nil {
			return nil, fmt.Errorf("state map %q migration source %q is not loaded", target.Name, target.MigrateFrom)
		}
		migrations = append(migrations, PluginEBPFStateMigration{
			PluginID:          pluginID,
			ObjectID:          objectID,
			SourceMap:         target.MigrateFrom,
			TargetMap:         target.Name,
			FromSchemaVersion: source.SchemaVersion,
			ToSchemaVersion:   target.SchemaVersion,
		})
	}
	return migrations, nil
}

func pendingPluginEBPFStateMigrations(refs []loadedPluginObjectRef) []PluginEBPFStateMigration {
	seen := make(map[string]struct{})
	out := make([]PluginEBPFStateMigration, 0)
	for _, ref := range refs {
		for _, migration := range ref.Migrations {
			if _, exists := seen[migration.key()]; exists {
				continue
			}
			seen[migration.key()] = struct{}{}
			out = append(out, migration)
		}
	}
	return out
}

func completePluginEBPFStateMigrations(refs []loadedPluginObjectRef, completed []PluginEBPFStateMigration) {
	if len(completed) == 0 {
		return
	}
	done := make(map[string]struct{}, len(completed))
	for _, migration := range completed {
		done[migration.key()] = struct{}{}
	}
	for index := range refs {
		pending := refs[index].Migrations[:0]
		for _, migration := range refs[index].Migrations {
			if _, exists := done[migration.key()]; !exists {
				pending = append(pending, migration)
			}
		}
		refs[index].Migrations = pending
	}
}

func (rt *linuxKernelRuleRuntime) PendingPluginEBPFStateMigrations() []PluginEBPFStateMigration {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return pendingPluginEBPFStateMigrations(rt.pluginPipelineLoaded)
}

func (rt *linuxKernelRuleRuntime) CompletePluginEBPFStateMigrations(completed []PluginEBPFStateMigration) {
	if rt == nil || len(completed) == 0 {
		return
	}
	rt.mu.Lock()
	completePluginEBPFStateMigrations(rt.pluginPipelineLoaded, completed)
	rt.mu.Unlock()
}

func (rt *kernelXDPPluginPipelineRuntime) PendingPluginEBPFStateMigrations() []PluginEBPFStateMigration {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return pendingPluginEBPFStateMigrations(rt.loaded)
}

func (rt *kernelXDPPluginPipelineRuntime) CompletePluginEBPFStateMigrations(completed []PluginEBPFStateMigration) {
	if rt == nil || len(completed) == 0 {
		return
	}
	rt.mu.Lock()
	completePluginEBPFStateMigrations(rt.loaded, completed)
	rt.mu.Unlock()
}
