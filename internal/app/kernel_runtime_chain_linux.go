//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
)

type orderedKernelRuntimeEntry struct {
	name string
	rt   kernelRuleRuntime
}

type orderedKernelRuleRuntime struct {
	mu                sync.Mutex
	cfg               *Config
	entries           []orderedKernelRuntimeEntry
	assignmentLog     kernelKeyedStateLogger
	engineFallbackLog kernelKeyedStateLogger
}

func newOrderedKernelRuleRuntime(order []string, cfg *Config) kernelRuleRuntime {
	normalized := normalizeKernelEngineOrder(order)
	entries := make([]orderedKernelRuntimeEntry, 0, len(normalized))
	for _, name := range normalized {
		switch name {
		case kernelEngineXDP:
			entries = append(entries, orderedKernelRuntimeEntry{name: name, rt: newXDPKernelRuleRuntime(cfg)})
		case kernelEngineTC:
			entries = append(entries, orderedKernelRuntimeEntry{name: name, rt: newTCKernelRuleRuntime(cfg)})
		}
	}
	if len(entries) == 0 {
		return staticUnavailableKernelRuleRuntime{reason: "no supported kernel dataplane engines configured"}
	}
	return &orderedKernelRuleRuntime{
		cfg:     cfg,
		entries: entries,
	}
}

func (rt *orderedKernelRuleRuntime) Available() (bool, string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.selectLocked()
}

func (rt *orderedKernelRuleRuntime) ReconcilePlugins(catalog PluginCatalog) pluginRuntimeSnapshot {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	for _, entry := range entries {
		runtime, ok := entry.rt.(pluginPipelineRuntime)
		if !ok || runtime == nil {
			continue
		}
		return runtime.ReconcilePlugins(catalog)
	}
	return kernelPluginPipelineManifestOnlySnapshot(catalog)
}

func (rt *orderedKernelRuleRuntime) PluginSnapshot() pluginRuntimeSnapshot {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	for _, entry := range entries {
		runtime, ok := entry.rt.(pluginPipelineRuntime)
		if !ok || runtime == nil {
			continue
		}
		return runtime.PluginSnapshot()
	}
	return pluginRuntimeSnapshot{}
}

func (rt *orderedKernelRuleRuntime) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	return rt.withPluginMapController(func(controller pluginEBPFMapController) error {
		return controller.PutPluginMapValue(pluginID, objectID, mapName, key, value)
	})
}

func (rt *orderedKernelRuleRuntime) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	var out []byte
	err := rt.withPluginMapController(func(controller pluginEBPFMapController) error {
		value, err := controller.GetPluginMapValue(pluginID, objectID, mapName, key)
		if err != nil {
			return err
		}
		out = value
		return nil
	})
	return out, err
}

func (rt *orderedKernelRuleRuntime) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	return rt.withPluginMapController(func(controller pluginEBPFMapController) error {
		return controller.DeletePluginMapValue(pluginID, objectID, mapName, key)
	})
}

func (rt *orderedKernelRuleRuntime) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	return rt.withPluginMapController(func(controller pluginEBPFMapController) error {
		return controller.ClearPluginMap(pluginID, objectID, mapName)
	})
}

func (rt *orderedKernelRuleRuntime) withPluginMapController(fn func(pluginEBPFMapController) error) error {
	if rt == nil {
		return errPluginRuntimeTargetNotLoaded
	}
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	var notLoaded error
	for _, entry := range entries {
		controller, ok := entry.rt.(pluginEBPFMapController)
		if !ok || controller == nil {
			continue
		}
		err := fn(controller)
		if err == nil {
			return nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoaded = err
			continue
		}
		return err
	}
	if notLoaded != nil {
		return notLoaded
	}
	return errPluginRuntimeTargetNotLoaded
}

func (rt *orderedKernelRuleRuntime) SupportsRule(rule Rule) (bool, string) {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	reasons := make([]string, 0, len(entries))
	for _, entry := range entries {
		supporter, ok := entry.rt.(kernelRuleSupportRuntime)
		if !ok || supporter == nil {
			continue
		}
		supported, reason := supporter.SupportsRule(rule)
		if supported {
			return true, ""
		}
		reason = strings.TrimSpace(reason)
		if reason == "" {
			reason = "rule was not accepted by the engine"
		}
		reasons = append(reasons, fmt.Sprintf("%s: %s", entry.name, reason))
	}
	if len(reasons) == 0 {
		return false, "kernel dataplane could not evaluate rule eligibility"
	}
	return false, strings.Join(reasons, "; ")
}

func (rt *orderedKernelRuleRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return rt.reconcileWithOptionalPluginCatalog(rules, nil)
}

func (rt *orderedKernelRuleRuntime) ReconcileWithPluginCatalog(rules []Rule, catalog PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	return rt.reconcileWithOptionalPluginCatalog(rules, &catalog)
}

func (rt *orderedKernelRuleRuntime) reconcileWithOptionalPluginCatalog(rules []Rule, catalog *PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	entries := rt.entriesForCatalogLocked(catalog)
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	failuresByRule := make(map[int64][]string, len(rules))
	pending := append([]Rule(nil), rules...)
	assignedEntries := make(map[string]bool, len(entries))
	assignedLogKeys := make(map[string]struct{}, len(entries))
	fallbackLogKeys := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		available, reason := entry.rt.Available()
		if !available {
			if reason == "" {
				reason = "unavailable"
			}
			for _, rule := range pending {
				failuresByRule[rule.ID] = append(failuresByRule[rule.ID], fmt.Sprintf("%s unavailable: %s", entry.name, reason))
			}
			if _, err := reconcileKernelRuntimeEntryWithPluginCatalog(entry.rt, nil, catalog); err != nil {
				log.Printf("kernel dataplane engine cleanup after unavailable (%s): %v", entry.name, err)
			}
			continue
		}

		engineResults, err := reconcileKernelRuntimeEntryWithPluginCatalog(entry.rt, pending, catalog)
		nextPending := make([]Rule, 0, len(pending))
		runningCount := 0

		for _, rule := range pending {
			result, ok := engineResults[rule.ID]
			if ok && result.Running {
				if result.Engine == "" {
					result.Engine = entry.name
				}
				results[rule.ID] = result
				runningCount++
				continue
			}

			reason := kernelRuntimeReconcileFailureReason(ok, result, err)
			failuresByRule[rule.ID] = append(failuresByRule[rule.ID], fmt.Sprintf("%s: %s", entry.name, reason))
			nextPending = append(nextPending, rule)
		}

		pluginPipelineActive := kernelRuntimePluginPipelineHasActiveAttachments(entry.rt)
		if runningCount > 0 || pluginPipelineActive {
			assignedEntries[entry.name] = true
		}
		if runningCount > 0 {
			assignedLogKeys[entry.name] = struct{}{}
			rt.assignmentLog.Logf(entry.name, "kernel dataplane engine assigned: %s entries=%d", entry.name, runningCount)
		}
		if err != nil {
			fallbackLogKeys[entry.name] = struct{}{}
			rt.engineFallbackLog.Logf(entry.name, "kernel dataplane engine fallback: %s reconcile failed: %v", entry.name, err)
		}
		pending = nextPending

		if len(pending) == 0 {
			rt.assignmentLog.Retain(assignedLogKeys)
			rt.engineFallbackLog.Retain(fallbackLogKeys)
			rt.cleanupUnassignedLocked(assignedEntries)
			return results, nil
		}
	}

	rt.assignmentLog.Retain(assignedLogKeys)
	rt.engineFallbackLog.Retain(fallbackLogKeys)
	rt.cleanupUnassignedLocked(assignedEntries)

	for _, rule := range pending {
		failures := failuresByRule[rule.ID]
		reason := "no kernel dataplane engines accepted the rule"
		if len(failures) > 0 {
			reason = strings.Join(failures, "; ")
		}
		results[rule.ID] = kernelRuleApplyResult{Error: reason}
	}
	return results, nil
}

func kernelRuntimePluginPipelineHasActiveAttachments(rt kernelRuleRuntime) bool {
	runtime, ok := rt.(pluginPipelineRuntime)
	if !ok || runtime == nil {
		return false
	}
	snapshot := runtime.PluginSnapshot()
	for _, state := range snapshot.Plugins {
		if state.Mode == pluginRuntimeModeDataplane && (state.Attached || state.AttachmentCount > 0 || len(state.Attachments) > 0) {
			return true
		}
	}
	return false
}

func reconcileKernelRuntimeEntryWithPluginCatalog(rt kernelRuleRuntime, rules []Rule, catalog *PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	if catalog != nil {
		if withCatalog, ok := rt.(kernelRuleRuntimeWithPluginCatalog); ok {
			return withCatalog.ReconcileWithPluginCatalog(rules, *catalog)
		}
	}
	return rt.Reconcile(rules)
}

func (rt *orderedKernelRuleRuntime) ReconcileRetainingAssignments(retainedByEngine map[string][]Rule, newRules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return rt.reconcileRetainingAssignmentsWithOptionalPluginCatalog(retainedByEngine, newRules, nil)
}

func (rt *orderedKernelRuleRuntime) ReconcileRetainingAssignmentsWithPluginCatalog(retainedByEngine map[string][]Rule, newRules []Rule, catalog PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	return rt.reconcileRetainingAssignmentsWithOptionalPluginCatalog(retainedByEngine, newRules, &catalog)
}

func (rt *orderedKernelRuleRuntime) reconcileRetainingAssignmentsWithOptionalPluginCatalog(retainedByEngine map[string][]Rule, newRules []Rule, catalog *PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	entries := rt.entriesForCatalogLocked(catalog)
	results := make(map[int64]kernelRuleApplyResult, len(newRules))
	failuresByRule := make(map[int64][]string, len(newRules))
	pending := append([]Rule(nil), newRules...)
	assignedEntries := make(map[string]bool, len(entries))
	assignedLogKeys := make(map[string]struct{}, len(entries))
	fallbackLogKeys := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		fixed := cloneRuleSlice(retainedByEngine[entry.name])
		if len(fixed) > 0 {
			assignedEntries[entry.name] = true
			assignedLogKeys[entry.name] = struct{}{}
		}

		available, reason := entry.rt.Available()
		if !available {
			if len(fixed) > 0 {
				if strings.TrimSpace(reason) == "" {
					reason = "unavailable"
				}
				return nil, fmt.Errorf("retained %s kernel assignments became unavailable: %s", entry.name, reason)
			}
			if reason == "" {
				reason = "unavailable"
			}
			for _, rule := range pending {
				failuresByRule[rule.ID] = append(failuresByRule[rule.ID], fmt.Sprintf("%s unavailable: %s", entry.name, reason))
			}
			if _, err := reconcileKernelRuntimeEntryWithPluginCatalog(entry.rt, nil, catalog); err != nil {
				log.Printf("kernel dataplane engine cleanup after unavailable (%s): %v", entry.name, err)
			}
			continue
		}

		request := make([]Rule, 0, len(fixed)+len(pending))
		request = append(request, fixed...)
		request = append(request, pending...)
		if len(request) == 0 {
			continue
		}

		engineResults, err := reconcileKernelRuntimeEntryWithPluginCatalog(entry.rt, request, catalog)
		runningCount := 0

		for _, rule := range fixed {
			result, ok := engineResults[rule.ID]
			if ok && result.Running {
				runningCount++
				continue
			}
			return nil, fmt.Errorf("retained %s kernel rule %d could not be preserved: %s", entry.name, rule.ID, kernelRuntimeReconcileFailureReason(ok, result, err))
		}

		nextPending := make([]Rule, 0, len(pending))
		for _, rule := range pending {
			result, ok := engineResults[rule.ID]
			if ok && result.Running {
				if result.Engine == "" {
					result.Engine = entry.name
				}
				results[rule.ID] = result
				runningCount++
				continue
			}

			reason := kernelRuntimeReconcileFailureReason(ok, result, err)
			failuresByRule[rule.ID] = append(failuresByRule[rule.ID], fmt.Sprintf("%s: %s", entry.name, reason))
			nextPending = append(nextPending, rule)
		}

		if runningCount > 0 {
			assignedEntries[entry.name] = true
			assignedLogKeys[entry.name] = struct{}{}
			rt.assignmentLog.Logf(entry.name, "kernel dataplane engine assigned: %s entries=%d", entry.name, runningCount)
		}
		if err != nil {
			fallbackLogKeys[entry.name] = struct{}{}
			rt.engineFallbackLog.Logf(entry.name, "kernel dataplane engine fallback: %s reconcile failed: %v", entry.name, err)
		}
		pending = nextPending
	}

	rt.assignmentLog.Retain(assignedLogKeys)
	rt.engineFallbackLog.Retain(fallbackLogKeys)
	rt.cleanupUnassignedLocked(assignedEntries)

	for _, rule := range pending {
		failures := failuresByRule[rule.ID]
		reason := "no kernel dataplane engines accepted the rule"
		if len(failures) > 0 {
			reason = strings.Join(failures, "; ")
		}
		results[rule.ID] = kernelRuleApplyResult{Error: reason}
	}
	return results, nil
}

func (rt *orderedKernelRuleRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	out := emptyKernelRuleStatsSnapshot()
	for _, entry := range rt.entries {
		snapshot, err := entry.rt.SnapshotStats()
		if err != nil {
			return emptyKernelRuleStatsSnapshot(), err
		}
		for ruleID, stats := range snapshot.ByRuleID {
			current := out.ByRuleID[ruleID]
			current.TCPActiveConns += stats.TCPActiveConns
			current.UDPNatEntries += stats.UDPNatEntries
			current.ICMPNatEntries += stats.ICMPNatEntries
			current.TotalConns += stats.TotalConns
			current.BytesIn += stats.BytesIn
			current.BytesOut += stats.BytesOut
			out.ByRuleID[ruleID] = current
		}
	}
	return out, nil
}

func (rt *orderedKernelRuleRuntime) Maintain() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for _, entry := range rt.entries {
		if err := entry.rt.Maintain(); err != nil {
			return err
		}
	}
	return nil
}

func (rt *orderedKernelRuleRuntime) SnapshotAssignments() map[int64]string {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	out := make(map[int64]string)
	for _, entry := range rt.entries {
		for ruleID, engine := range entry.rt.SnapshotAssignments() {
			out[ruleID] = engine
		}
	}
	return out
}

func (rt *orderedKernelRuleRuntime) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	var firstErr error
	for _, entry := range rt.entries {
		if err := entry.rt.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (rt *orderedKernelRuleRuntime) cleanupUnassignedLocked(assignedEntries map[string]bool) {
	for _, entry := range rt.entries {
		if assignedEntries[entry.name] {
			continue
		}
		if _, cleanupErr := entry.rt.Reconcile(nil); cleanupErr != nil {
			log.Printf("kernel dataplane engine cleanup after assignment (%s): %v", entry.name, cleanupErr)
		}
	}
}

func (rt *orderedKernelRuleRuntime) entriesForCatalogLocked(catalog *PluginCatalog) []orderedKernelRuntimeEntry {
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	if catalog == nil || !kernelPluginPipelineCatalogHasRuntimeHooks(*catalog, rt.cfg) {
		return entries
	}
	out := make([]orderedKernelRuntimeEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.name == kernelEngineTC {
			out = append(out, entry)
		}
	}
	for _, entry := range entries {
		if entry.name != kernelEngineTC {
			out = append(out, entry)
		}
	}
	return out
}

func (rt *orderedKernelRuleRuntime) selectLocked() (bool, string) {
	failures := make([]string, 0, len(rt.entries))
	for _, entry := range rt.entries {
		available, reason := entry.rt.Available()
		if available {
			if reason == "" {
				reason = "ready"
			}
			if len(failures) > 0 {
				return true, fmt.Sprintf("selected %s kernel engine: %s (skipped: %s)", entry.name, reason, strings.Join(failures, "; "))
			}
			return true, fmt.Sprintf("selected %s kernel engine: %s", entry.name, reason)
		}
		if reason == "" {
			reason = "unavailable"
		}
		failures = append(failures, fmt.Sprintf("%s=%s", entry.name, reason))
	}
	if len(failures) == 0 {
		return false, "no kernel dataplane engines configured"
	}
	return false, "no kernel dataplane engines available: " + strings.Join(failures, "; ")
}

func kernelRuntimeReconcileFailureReason(ok bool, result kernelRuleApplyResult, err error) string {
	switch {
	case ok && result.Error != "":
		return result.Error
	case err != nil:
		return err.Error()
	default:
		return "rule was not accepted by the engine"
	}
}

func kernelRuntimeFailureResults(rules []Rule, reason string) map[int64]kernelRuleApplyResult {
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	for _, rule := range rules {
		results[rule.ID] = kernelRuleApplyResult{Error: reason}
	}
	return results
}

type staticUnavailableKernelRuleRuntime struct {
	reason string
}

func (rt staticUnavailableKernelRuleRuntime) Available() (bool, string) {
	return false, rt.reason
}

func (rt staticUnavailableKernelRuleRuntime) SupportsRule(rule Rule) (bool, string) {
	return false, rt.reason
}

func (rt staticUnavailableKernelRuleRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return kernelRuntimeFailureResults(rules, rt.reason), nil
}

func (rt staticUnavailableKernelRuleRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt staticUnavailableKernelRuleRuntime) Maintain() error {
	return nil
}

func (rt staticUnavailableKernelRuleRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (rt staticUnavailableKernelRuleRuntime) Close() error {
	return nil
}
