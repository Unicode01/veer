package app

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const pluginHookBindingsResourceID = "hook_bindings"

type pluginHookBindingRecordData struct {
	HookID     string   `json:"hook_id"`
	Hook       string   `json:"hook"`
	Interface  string   `json:"interface"`
	Interfaces []string `json:"interfaces"`
}

type pluginHookBindingSet struct {
	Interfaces map[string][]string
	Disabled   map[string]struct{}
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
		if len(bindings.Interfaces) == 0 && len(bindings.Disabled) == 0 {
			continue
		}
		hooks := plugin.Hooks[:0]
		for _, hook := range plugin.Hooks {
			hookID := strings.TrimSpace(strings.ToLower(hook.ID))
			if _, disabled := bindings.Disabled[hookID]; disabled {
				continue
			}
			if interfaces, ok := bindings.Interfaces[hookID]; ok {
				hook.Interfaces = interfaces
			}
			hooks = append(hooks, hook)
		}
		plugin.Hooks = hooks
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

func pluginHookBindingsFromRecords(pluginID string, records []store.PluginRecord) pluginHookBindingSet {
	out := pluginHookBindingSet{
		Interfaces: make(map[string][]string),
		Disabled:   make(map[string]struct{}),
	}
	for _, record := range records {
		var data pluginHookBindingRecordData
		if err := json.Unmarshal([]byte(record.DataJSON), &data); err != nil {
			if record.Enabled {
				log.Printf("plugin hook bindings: %s/%s skip invalid JSON: %v", pluginID, record.RecordKey, err)
				continue
			}
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
		if !record.Enabled {
			out.Disabled[hookID] = struct{}{}
			delete(out.Interfaces, hookID)
			continue
		}
		if _, disabled := out.Disabled[hookID]; disabled {
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
		out.Interfaces[hookID] = interfaces
	}
	return out
}
