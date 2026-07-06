package app

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"

	"forward/internal/store"
)

const pluginHookBindingsResourceID = "hook_bindings"

type pluginHookBindingRecordData struct {
	HookID     string   `json:"hook_id"`
	Hook       string   `json:"hook"`
	Interface  string   `json:"interface"`
	Interfaces []string `json:"interfaces"`
}

func applyPluginHookBindingsFromDB(catalog PluginCatalog, db *sql.DB) PluginCatalog {
	if db == nil {
		return catalog
	}
	for i := range catalog.Plugins {
		plugin := &catalog.Plugins[i]
		if plugin.Builtin || plugin.Status != pluginStatusActive || !pluginHasResource(*plugin, pluginHookBindingsResourceID) {
			continue
		}
		records, err := store.GetPluginRecords(db, plugin.ID, pluginHookBindingsResourceID)
		if err != nil {
			log.Printf("plugin hook bindings: load %s/%s failed: %v", plugin.ID, pluginHookBindingsResourceID, err)
			continue
		}
		bindings := pluginHookBindingsFromRecords(plugin.ID, records)
		if len(bindings) == 0 {
			continue
		}
		for hookIndex := range plugin.Hooks {
			hookID := plugin.Hooks[hookIndex].ID
			if interfaces, ok := bindings[hookID]; ok {
				plugin.Hooks[hookIndex].Interfaces = interfaces
			}
		}
	}
	return catalog
}

func pluginHasResource(plugin LoadedPlugin, resourceID string) bool {
	for _, resource := range plugin.Resources {
		if resource.ID == resourceID {
			return true
		}
	}
	return false
}

func pluginHookBindingsFromRecords(pluginID string, records []store.PluginRecord) map[string][]string {
	out := make(map[string][]string)
	for _, record := range records {
		if !record.Enabled {
			continue
		}
		var data pluginHookBindingRecordData
		if err := json.Unmarshal([]byte(record.DataJSON), &data); err != nil {
			log.Printf("plugin hook bindings: %s/%s skip invalid JSON: %v", pluginID, record.RecordKey, err)
			continue
		}
		hookID := strings.TrimSpace(strings.ToLower(data.HookID))
		if hookID == "" {
			hookID = strings.TrimSpace(strings.ToLower(data.Hook))
		}
		if hookID == "" {
			hookID = strings.TrimSpace(strings.ToLower(record.RecordKey))
		}
		if !pluginIDPattern.MatchString(hookID) {
			log.Printf("plugin hook bindings: %s/%s skip invalid hook_id %q", pluginID, record.RecordKey, hookID)
			continue
		}
		interfaces := append([]string(nil), data.Interfaces...)
		if strings.TrimSpace(data.Interface) != "" {
			interfaces = append(interfaces, data.Interface)
		}
		interfaces, err := normalizePluginInterfaceNames(interfaces)
		if err != nil {
			log.Printf("plugin hook bindings: %s/%s skip invalid interfaces: %v", pluginID, record.RecordKey, err)
			continue
		}
		if len(interfaces) == 0 {
			continue
		}
		out[hookID] = interfaces
	}
	return out
}
