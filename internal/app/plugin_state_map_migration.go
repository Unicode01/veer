package app

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	pluginEBPFStateMigrationProtocolVersion = 1
	pluginEBPFStateMigrationMaxBatches      = 65536
	pluginEBPFStateMigrationMaxDuration     = 5 * time.Minute
)

type pluginEBPFStateMigrationResult struct {
	Done      bool   `json:"done"`
	Cursor    string `json:"cursor,omitempty"`
	Processed int    `json:"processed"`
}

type pluginEBPFStateMigrationJSONResult struct {
	Done      *bool  `json:"done"`
	Cursor    string `json:"cursor,omitempty"`
	Processed int    `json:"processed"`
}

func pluginStateMapMigrationRollbackAllowed(migrated PluginObjectStateMap, previous, next map[string]PluginObjectStateMap) bool {
	if migrated.Policy != pluginObjectMapMigrate || migrated.MigrateFrom == "" {
		return false
	}
	previousSource, previousOK := previous[migrated.MigrateFrom]
	nextSource, nextOK := next[migrated.MigrateFrom]
	return previousOK && nextOK &&
		previousSource.Policy == pluginObjectMapPreserve &&
		nextSource.Policy == pluginObjectMapPreserve &&
		previousSource.SchemaVersion == nextSource.SchemaVersion &&
		previousSource.SchemaVersion < migrated.SchemaVersion
}

type pluginControlEBPFStateMigrator interface {
	ApplyPluginEBPFStateMigrations(PluginCatalog, pluginRuntimeSnapshot, []PluginEBPFStateMigration) ([]PluginEBPFStateMigration, map[string]error)
}

type pluginEBPFStateMigrationRuntime interface {
	PendingPluginEBPFStateMigrations() []PluginEBPFStateMigration
	CompletePluginEBPFStateMigrations([]PluginEBPFStateMigration)
}

func (rt *gojaPluginControlRuntime) ApplyPluginEBPFStateMigrations(catalog PluginCatalog, snapshot pluginRuntimeSnapshot, migrations []PluginEBPFStateMigration) ([]PluginEBPFStateMigration, map[string]error) {
	if rt == nil || len(migrations) == 0 {
		return nil, nil
	}
	plugins := make(map[string]LoadedPlugin, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		plugins[plugin.ID] = plugin
	}
	ordered := append([]PluginEBPFStateMigration(nil), migrations...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].key() < ordered[j].key() })
	completed := make([]PluginEBPFStateMigration, 0, len(ordered))
	failures := make(map[string]error)
	for _, migration := range ordered {
		if failures[migration.PluginID] != nil {
			continue
		}
		plugin, exists := plugins[migration.PluginID]
		if !exists || plugin.Status != pluginStatusActive {
			failures[migration.PluginID] = fmt.Errorf("plugin is not active for eBPF state migration")
			continue
		}
		if state, exists := snapshot.stateFor(plugin.ID); !exists || state.Error != "" || !state.Attached {
			failures[migration.PluginID] = fmt.Errorf("plugin dataplane is not attached for eBPF state migration")
			continue
		}
		if err := rt.applyPluginEBPFStateMigration(plugin, migration); err != nil {
			failures[migration.PluginID] = fmt.Errorf("object %s map %s -> %s: %w", migration.ObjectID, migration.SourceMap, migration.TargetMap, err)
			continue
		}
		completed = append(completed, migration)
	}
	if len(failures) == 0 {
		failures = nil
	}
	return completed, failures
}

func (rt *gojaPluginControlRuntime) applyPluginEBPFStateMigration(plugin LoadedPlugin, migration PluginEBPFStateMigration) error {
	started := time.Now()
	cursor := ""
	for batch := 1; batch <= pluginEBPFStateMigrationMaxBatches; batch++ {
		if time.Since(started) >= pluginEBPFStateMigrationMaxDuration {
			return fmt.Errorf("migration exceeded %s", pluginEBPFStateMigrationMaxDuration)
		}
		event := pluginControlEBPFStateMigrationEvent{
			PluginEBPFStateMigration: migration,
			ProtocolVersion:          pluginEBPFStateMigrationProtocolVersion,
			Batch:                    batch,
			Cursor:                   cursor,
			MaxEntries:               pluginControlMapScanMaxEntries,
			MaxBytes:                 pluginControlMapScanMaxBytes,
		}
		result, err := rt.runPluginControlResult(plugin, pluginControlEvent{
			Kind: "ebpf_state_migrate", EBPFMigration: &event,
		}, false)
		if err != nil {
			return err
		}
		progress, err := normalizePluginEBPFStateMigrationResult(result.value)
		if err != nil {
			return fmt.Errorf("batch %d: %w", batch, err)
		}
		if progress.Done {
			return nil
		}
		if progress.Processed < 1 {
			return fmt.Errorf("batch %d made no progress", batch)
		}
		if progress.Cursor == cursor {
			return fmt.Errorf("batch %d returned an unchanged cursor", batch)
		}
		cursor = progress.Cursor
	}
	return fmt.Errorf("migration exceeded %d batches", pluginEBPFStateMigrationMaxBatches)
}

func normalizePluginEBPFStateMigrationResult(value any) (pluginEBPFStateMigrationResult, error) {
	if typed, ok := value.(pluginEBPFStateMigrationResult); ok {
		return validatePluginEBPFStateMigrationResult(typed, true)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return pluginEBPFStateMigrationResult{}, fmt.Errorf("encode migration progress: %w", err)
	}
	return decodePluginEBPFStateMigrationResult(data)
}

func decodePluginEBPFStateMigrationResult(data []byte) (pluginEBPFStateMigrationResult, error) {
	var raw pluginEBPFStateMigrationJSONResult
	if err := json.Unmarshal(data, &raw); err != nil {
		return pluginEBPFStateMigrationResult{}, fmt.Errorf("decode migration progress: %w", err)
	}
	if raw.Done == nil {
		return pluginEBPFStateMigrationResult{}, fmt.Errorf("migration progress must include done")
	}
	return validatePluginEBPFStateMigrationResult(pluginEBPFStateMigrationResult{
		Done: *raw.Done, Cursor: raw.Cursor, Processed: raw.Processed,
	}, true)
}

func validatePluginEBPFStateMigrationResult(result pluginEBPFStateMigrationResult, requireProcessed bool) (pluginEBPFStateMigrationResult, error) {
	result.Cursor = strings.TrimSpace(strings.ToLower(result.Cursor))
	if result.Processed < 0 || result.Processed > pluginControlMapScanMaxEntries {
		return pluginEBPFStateMigrationResult{}, fmt.Errorf("processed must be between 0 and %d", pluginControlMapScanMaxEntries)
	}
	if result.Cursor != "" {
		cursor, err := decodePluginControlHexBytes(result.Cursor)
		if err != nil {
			return pluginEBPFStateMigrationResult{}, fmt.Errorf("cursor: %w", err)
		}
		if len(cursor) > pluginControlMapScanMaxBytes {
			return pluginEBPFStateMigrationResult{}, fmt.Errorf("cursor exceeds %d bytes", pluginControlMapScanMaxBytes)
		}
		result.Cursor = hex.EncodeToString(cursor)
	}
	if result.Done {
		if result.Cursor != "" {
			return pluginEBPFStateMigrationResult{}, fmt.Errorf("completed migration must return an empty cursor")
		}
		return result, nil
	}
	if result.Cursor == "" {
		return pluginEBPFStateMigrationResult{}, fmt.Errorf("incomplete migration must return a cursor")
	}
	if requireProcessed && result.Processed == 0 {
		return pluginEBPFStateMigrationResult{}, fmt.Errorf("incomplete migration must report processed entries")
	}
	return result, nil
}
