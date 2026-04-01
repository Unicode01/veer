//go:build linux

package app

import (
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
		entries: entries,
	}
}

func (rt *orderedKernelRuleRuntime) Available() (bool, string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.selectLocked()
}

func (rt *orderedKernelRuleRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	results := make(map[int64]kernelRuleApplyResult, len(rules))
	failuresByRule := make(map[int64][]string, len(rules))
	pending := append([]Rule(nil), rules...)
	assignedEntries := make(map[string]bool, len(rt.entries))
	assignedLogKeys := make(map[string]struct{}, len(rt.entries))
	fallbackLogKeys := make(map[string]struct{}, len(rt.entries))

	for _, entry := range rt.entries {
		available, reason := entry.rt.Available()
		if !available {
			if reason == "" {
				reason = "unavailable"
			}
			for _, rule := range pending {
				failuresByRule[rule.ID] = append(failuresByRule[rule.ID], fmt.Sprintf("%s unavailable: %s", entry.name, reason))
			}
			if _, err := entry.rt.Reconcile(nil); err != nil {
				log.Printf("kernel dataplane engine cleanup after unavailable (%s): %v", entry.name, err)
			}
			continue
		}

		engineResults, err := entry.rt.Reconcile(pending)
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

			reason := ""
			switch {
			case ok && result.Error != "":
				reason = result.Error
			case err != nil:
				reason = err.Error()
			default:
				reason = "rule was not accepted by the engine"
			}
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
