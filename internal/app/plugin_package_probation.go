package app

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

const pluginPackageProbationCheckEvery = 5 * time.Second

func (m *pluginPackageManager) startPluginPackageProbation(pluginID, version, previousHistoryID string, runtimeApplied bool) (*PluginPackageProbation, error) {
	return m.startPluginPackageProbationWithGroup(pluginID, version, previousHistoryID, "", runtimeApplied)
}

func (m *pluginPackageManager) startPluginPackageProbationWithGroup(pluginID, version, previousHistoryID, groupID string, runtimeApplied bool) (*PluginPackageProbation, error) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return nil, fmt.Errorf("invalid plugin probation id")
	}
	if _, err := normalizePluginSemanticVersion(version); err != nil {
		return nil, fmt.Errorf("invalid plugin probation version: %w", err)
	}
	if previousHistoryID != "" && !validPluginPackageHistoryID(previousHistoryID) {
		return nil, fmt.Errorf("invalid plugin probation history id")
	}
	if groupID != "" && validatePluginPackageID(groupID) != nil {
		return nil, fmt.Errorf("invalid plugin probation group id")
	}
	now := time.Now().UTC()
	record := PluginPackageProbation{
		PluginID: pluginID, Version: version, PreviousHistoryID: previousHistoryID,
		CreatedAt: now.Format(time.RFC3339Nano), GroupID: groupID, Pending: true,
	}
	if runtimeApplied && m.pluginPackageProbationCanRun(pluginID) {
		m.activatePluginPackageProbation(&record, now)
	}
	if err := m.writePluginPackageProbation(record); err != nil {
		return nil, err
	}
	copy := record
	return &copy, nil
}

func (m *pluginPackageManager) pluginPackageProbationCanRun(pluginID string) bool {
	if m == nil || m.cfg == nil || !m.cfg.PluginsEnabled() {
		return false
	}
	if m.db == nil {
		return true
	}
	state, err := store.PluginStateOrNil(m.db, pluginID)
	return err == nil && (state == nil || state.Enabled)
}

func (m *pluginPackageManager) activatePluginPackageProbation(record *PluginPackageProbation, now time.Time) {
	if record == nil {
		return
	}
	now = now.UTC()
	record.Pending = false
	record.StartedAt = now.Format(time.RFC3339Nano)
	record.ExpiresAt = now.Add(pluginPackageProbationDuration).Format(time.RFC3339Nano)
	record.BaselineRestarts = m.pluginPackageRestartCount(record.PluginID)
	record.UncleanStarts = 0
	record.CleanShutdown = false
	record.RecoveryAttempts = 0
	record.NextRecoveryAt = ""
	record.LastFailure = ""
	record.LastFailureAt = ""
}

func (m *pluginPackageManager) pluginPackageRestartCount(pluginID string) uint64 {
	if m == nil || m.pm == nil || m.pm.pluginControlRuntime == nil {
		return 0
	}
	runtime, ok := m.pm.pluginControlRuntime.(*gojaPluginControlRuntime)
	if !ok || runtime == nil {
		return 0
	}
	return runtime.pluginHostIsolationSnapshot(pluginID).RestartCount
}

func (m *pluginPackageManager) ListProbations() ([]PluginPackageProbation, error) {
	root := filepath.Join(m.stateRoot, "probation")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []PluginPackageProbation{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]PluginPackageProbation, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != pluginPackageProbationFileSuffix {
			continue
		}
		pluginID := strings.TrimSuffix(entry.Name(), pluginPackageProbationFileSuffix)
		if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
			return nil, fmt.Errorf("invalid plugin probation file %q", entry.Name())
		}
		var record PluginPackageProbation
		if err := readPluginPackageJSON(filepath.Join(root, entry.Name()), &record); err != nil {
			return nil, fmt.Errorf("read plugin probation %s: %w", pluginID, err)
		}
		if err := validatePluginPackageProbation(record); err != nil {
			return nil, fmt.Errorf("validate plugin probation %s: %w", pluginID, err)
		}
		if record.PluginID != pluginID {
			return nil, fmt.Errorf("plugin probation file identity mismatch for %s", pluginID)
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out, nil
}

func (m *pluginPackageManager) loadPluginPackageProbation(pluginID string) (PluginPackageProbation, error) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return PluginPackageProbation{}, fmt.Errorf("invalid plugin probation id")
	}
	var record PluginPackageProbation
	if err := readPluginPackageJSON(m.pluginPackageProbationPath(pluginID), &record); err != nil {
		return PluginPackageProbation{}, err
	}
	if err := validatePluginPackageProbation(record); err != nil {
		return PluginPackageProbation{}, err
	}
	if record.PluginID != pluginID {
		return PluginPackageProbation{}, fmt.Errorf("plugin probation identity mismatch")
	}
	return record, nil
}

func (m *pluginPackageManager) writePluginPackageProbation(record PluginPackageProbation) error {
	if err := validatePluginPackageProbation(record); err != nil {
		return err
	}
	return writePluginPackageJSONAtomic(m.pluginPackageProbationPath(record.PluginID), record, true)
}

func (m *pluginPackageManager) removePluginPackageProbation(pluginID string) error {
	path := m.pluginPackageProbationPath(pluginID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (m *pluginPackageManager) pluginPackageProbationPath(pluginID string) string {
	return filepath.Join(m.stateRoot, "probation", pluginID+pluginPackageProbationFileSuffix)
}

func validatePluginPackageProbation(record PluginPackageProbation) error {
	if !pluginIDPattern.MatchString(record.PluginID) || reservedBuiltinPluginID(record.PluginID) {
		return fmt.Errorf("invalid plugin id")
	}
	if normalized, err := normalizePluginSemanticVersion(record.Version); err != nil || normalized != record.Version {
		return fmt.Errorf("invalid plugin version")
	}
	if record.PreviousHistoryID != "" && !validPluginPackageHistoryID(record.PreviousHistoryID) {
		return fmt.Errorf("invalid previous history id")
	}
	if record.GroupID != "" && validatePluginPackageID(record.GroupID) != nil {
		return fmt.Errorf("invalid probation group id")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return fmt.Errorf("invalid creation time")
	}
	if record.Pending {
		if record.StartedAt != "" || record.ExpiresAt != "" {
			return fmt.Errorf("pending probation cannot have an active time window")
		}
	} else {
		startedAt, startErr := time.Parse(time.RFC3339Nano, record.StartedAt)
		expiresAt, expireErr := time.Parse(time.RFC3339Nano, record.ExpiresAt)
		if startErr != nil || expireErr != nil || startedAt.Before(createdAt) || !expiresAt.After(startedAt) {
			return fmt.Errorf("invalid probation time window")
		}
	}
	if record.UncleanStarts < 0 || record.RecoveryAttempts < 0 {
		return fmt.Errorf("invalid probation counters")
	}
	if record.NextRecoveryAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, record.NextRecoveryAt); err != nil {
			return fmt.Errorf("invalid next recovery time")
		}
	}
	if record.LastFailureAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, record.LastFailureAt); err != nil {
			return fmt.Errorf("invalid failure time")
		}
	}
	if len(record.LastFailure) > pluginControlMaxLogMessageBytes {
		return fmt.Errorf("probation failure message is too large")
	}
	return nil
}

func (m *pluginPackageManager) markPluginPackageProbationsCleanShutdown() error {
	records, err := m.ListProbations()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Pending || record.CleanShutdown {
			continue
		}
		record.CleanShutdown = true
		if err := m.writePluginPackageProbation(record); err != nil {
			return err
		}
	}
	return nil
}

func (m *pluginPackageManager) recoverPluginPackageProbationsOnStartup(now time.Time) error {
	records, err := m.ListProbations()
	if err != nil {
		return err
	}
	now = now.UTC()
	recoveredGroups := make(map[string]struct{})
	for _, record := range records {
		if record.GroupID != "" {
			if _, recovered := recoveredGroups[record.GroupID]; recovered {
				continue
			}
		}
		if record.Pending {
			continue
		}
		expiresAt, _ := time.Parse(time.RFC3339Nano, record.ExpiresAt)
		if !now.Before(expiresAt) {
			if err := m.completePluginPackageProbation(record, "probation window elapsed while service was stopped"); err != nil {
				return err
			}
			continue
		}
		if record.CleanShutdown {
			record.CleanShutdown = false
			if err := m.writePluginPackageProbation(record); err != nil {
				return err
			}
			continue
		}
		record.UncleanStarts++
		record.LastFailure = "service exited without completing plugin probation shutdown marker"
		record.LastFailureAt = now.Format(time.RFC3339Nano)
		if err := m.writePluginPackageProbation(record); err != nil {
			return err
		}
		if record.UncleanStarts < pluginPackageProbationBoots {
			continue
		}
		if record.GroupID != "" {
			recoveredGroups[record.GroupID] = struct{}{}
		}
		if _, err := m.recoverPluginPackageProbation(record, record.LastFailure, "startup"); err != nil {
			return fmt.Errorf("recover plugin probation %s on startup: %w", record.PluginID, err)
		}
	}
	return nil
}

func (m *pluginPackageManager) completePluginPackageProbation(record PluginPackageProbation, reason string) error {
	if err := m.removePluginPackageProbation(record.PluginID); err != nil {
		return err
	}
	recordPluginAudit(m.db, record.PluginID, "package.probation_passed", "system", "success", map[string]any{
		"version": record.Version, "reason": reason,
	})
	return m.completePluginPackageProbationGroupIfFinished(record.GroupID, reason)
}

func (m *pluginPackageManager) recoverPluginPackageProbation(record PluginPackageProbation, reason, actor string) (PluginPackageOperationResult, error) {
	reason = boundedPluginControlHealthError(reason)
	if record.GroupID != "" {
		group, err := m.loadPluginPackageProbationGroup(record.GroupID)
		if err != nil {
			return PluginPackageOperationResult{}, err
		}
		result, recoveryErr := m.recoverPluginPackageProbationGroup(group)
		if recoveryErr != nil {
			if writeErr := m.notePluginPackageProbationGroupRecoveryFailure(&group, reason, recoveryErr); writeErr != nil {
				return PluginPackageOperationResult{}, fmt.Errorf("%v; persist probation group recovery failure: %w", recoveryErr, writeErr)
			}
			recordPluginAudit(m.db, "", "package.probation_group_recovery", actor, "error", map[string]any{
				"group_id": group.ID, "plugin_ids": pluginPackageProbationGroupIDs(group), "reason": reason,
				"error": recoveryErr.Error(), "attempt": group.RecoveryAttempts,
			})
			return PluginPackageOperationResult{}, recoveryErr
		}
		recordPluginAudit(m.db, "", "package.probation_group_recovery", actor, "success", map[string]any{
			"group_id": group.ID, "plugin_ids": pluginPackageProbationGroupIDs(group), "reason": reason,
			"recovery_batch_id": result.ID,
		})
		return PluginPackageOperationResult{
			PluginID: record.PluginID, Version: record.Version, Operation: "batch_recovery", RuntimeApplied: result.RuntimeApplied,
		}, nil
	}
	var result PluginPackageOperationResult
	var err error
	previousRecovery := m.probationRecovery
	m.probationRecovery = true
	defer func() { m.probationRecovery = previousRecovery }()
	if record.PreviousHistoryID != "" {
		stage, stageErr := m.PrepareRollback(PluginPackageRollbackRequest{PluginID: record.PluginID, HistoryID: record.PreviousHistoryID})
		if stageErr != nil {
			err = stageErr
		} else {
			previousSuppress := m.suppressProbation
			m.suppressProbation = true
			result, err = m.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest})
			m.suppressProbation = previousSuppress
		}
	} else {
		if setErr := store.SetPluginEnabled(m.db, record.PluginID, false); setErr != nil {
			err = setErr
		} else {
			var runtimeApplied bool
			runtimeApplied, err = m.applyRuntimeChange(record.PluginID)
			result = PluginPackageOperationResult{
				PluginID: record.PluginID, Version: record.Version, Operation: "auto_disable", RuntimeApplied: runtimeApplied,
			}
		}
	}
	if err != nil {
		if writeErr := m.notePluginPackageProbationRecoveryFailure(&record, reason, err); writeErr != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("%v; persist probation recovery failure: %w", err, writeErr)
		}
		recordPluginAudit(m.db, record.PluginID, "package.probation_recovery", actor, "error", map[string]any{
			"version": record.Version, "reason": reason, "error": err.Error(), "attempt": record.RecoveryAttempts,
		})
		return PluginPackageOperationResult{}, err
	}
	if err := m.removePluginPackageProbation(record.PluginID); err != nil {
		return PluginPackageOperationResult{}, err
	}
	recordPluginAudit(m.db, record.PluginID, "package.probation_recovery", actor, "success", map[string]any{
		"version": record.Version, "reason": reason, "operation": result.Operation, "restored_version": result.Version,
	})
	return result, nil
}

func (m *pluginPackageManager) notePluginPackageProbationRecoveryFailure(record *PluginPackageProbation, reason string, recoveryErr error) error {
	if record == nil {
		return nil
	}
	record.RecoveryAttempts++
	record.LastFailure = boundedPluginControlHealthError(reason + "; recovery: " + recoveryErr.Error())
	now := time.Now().UTC()
	record.LastFailureAt = now.Format(time.RFC3339Nano)
	delay := time.Minute << min(record.RecoveryAttempts-1, 3)
	record.NextRecoveryAt = now.Add(delay).Format(time.RFC3339Nano)
	return m.writePluginPackageProbation(*record)
}

func (pm *ProcessManager) checkPluginPackageProbations(now time.Time) {
	if pm == nil || pm.cfg == nil {
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(pm.cfg, pm.db, pm)
	if err != nil {
		log.Printf("plugin probation: initialize manager: %v", err)
		return
	}
	records, err := manager.ListProbations()
	if err != nil {
		log.Printf("plugin probation: list: %v", err)
		return
	}
	now = now.UTC()
	recoveredGroups := make(map[string]struct{})
	for _, record := range records {
		if record.GroupID != "" {
			if _, recovered := recoveredGroups[record.GroupID]; recovered {
				continue
			}
		}
		current, err := manager.loadCurrentPlugin(record.PluginID)
		if err != nil {
			log.Printf("plugin probation %s: load current plugin: %v", record.PluginID, err)
			continue
		}
		if current == nil || current.Version != record.Version {
			if record.GroupID != "" {
				recoveredGroups[record.GroupID] = struct{}{}
				if _, err := manager.recoverPluginPackageProbation(record, "plugin source changed during grouped probation", "monitor"); err != nil {
					log.Printf("plugin probation group %s: recover changed source: %v", record.GroupID, err)
				}
				continue
			}
			if err := manager.removePluginPackageProbation(record.PluginID); err != nil {
				log.Printf("plugin probation %s: remove stale state: %v", record.PluginID, err)
			}
			continue
		}
		if !manager.pluginPackageProbationCanRun(record.PluginID) {
			if !record.Pending {
				record.Pending = true
				record.StartedAt = ""
				record.ExpiresAt = ""
				record.CleanShutdown = false
				if err := manager.writePluginPackageProbation(record); err != nil {
					log.Printf("plugin probation %s: pause: %v", record.PluginID, err)
				}
			}
			continue
		}
		if record.Pending {
			manager.activatePluginPackageProbation(&record, now)
			if err := manager.writePluginPackageProbation(record); err != nil {
				log.Printf("plugin probation %s: activate: %v", record.PluginID, err)
				continue
			}
			recordPluginAudit(pm.db, record.PluginID, "package.probation_started", "system", "success", map[string]any{
				"version": record.Version, "expires_at": record.ExpiresAt,
			})
		}
		if record.NextRecoveryAt != "" {
			next, _ := time.Parse(time.RFC3339Nano, record.NextRecoveryAt)
			if now.Before(next) {
				continue
			}
			if record.GroupID != "" {
				recoveredGroups[record.GroupID] = struct{}{}
			}
			if _, err := manager.recoverPluginPackageProbation(record, record.LastFailure, "monitor"); err != nil {
				log.Printf("plugin probation %s: retry recovery: %v", record.PluginID, err)
			}
			continue
		}
		expiresAt, _ := time.Parse(time.RFC3339Nano, record.ExpiresAt)
		if !now.Before(expiresAt) {
			if err := manager.completePluginPackageProbation(record, "probation window completed"); err != nil {
				log.Printf("plugin probation %s: complete: %v", record.PluginID, err)
			}
			continue
		}
		if reason := pm.pluginPackageProbationFailure(record); reason != "" {
			if record.GroupID != "" {
				recoveredGroups[record.GroupID] = struct{}{}
			}
			if _, err := manager.recoverPluginPackageProbation(record, reason, "monitor"); err != nil {
				log.Printf("plugin probation %s: automatic recovery: %v", record.PluginID, err)
			}
		}
	}
}

func (pm *ProcessManager) pluginPackageProbationFailure(record PluginPackageProbation) string {
	runtime, ok := pm.pluginControlRuntime.(*gojaPluginControlRuntime)
	if !ok || runtime == nil {
		return ""
	}
	isolation := runtime.pluginHostIsolationSnapshot(record.PluginID)
	if isolation.RestartCount >= record.BaselineRestarts+pluginPackageProbationRestarts {
		return fmt.Sprintf("isolated plugin hosts restarted %d times during probation: %s", isolation.RestartCount-record.BaselineRestarts, isolation.LastError)
	}
	startedAt, _ := time.Parse(time.RFC3339Nano, record.StartedAt)
	health := runtime.pluginControlHealthSnapshot(record.PluginID)
	for _, circuit := range health.Circuits {
		failedAt, err := time.Parse(time.RFC3339Nano, circuit.LastFailureAt)
		if err != nil || failedAt.Before(startedAt) || circuit.ConsecutiveFailures < pluginControlCircuitFailureThreshold {
			continue
		}
		if pluginPackageProbationFatalControlError(circuit.LastError) {
			return fmt.Sprintf("control circuit %s repeatedly failed during probation: %s", circuit.Key, circuit.LastError)
		}
	}
	return ""
}

func pluginPackageProbationFatalControlError(message string) bool {
	message = strings.ToLower(strings.TrimSpace(message))
	for _, marker := range []string{
		"execution timed out", "deadline exceeded", "out of memory", "memory limit", "plugin host process",
		"plugin host protocol", "protocol violation", "stack overflow", "panicked", "panic:",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (pm *ProcessManager) markPluginPackageProbationsCleanShutdown() {
	if pm == nil || pm.cfg == nil {
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(pm.cfg, pm.db, pm)
	if err != nil {
		log.Printf("plugin probation: initialize shutdown marker: %v", err)
		return
	}
	if err := manager.markPluginPackageProbationsCleanShutdown(); err != nil {
		log.Printf("plugin probation: mark clean shutdown: %v", err)
	}
}
