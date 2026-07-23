package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (m *pluginPackageManager) recoverPluginPackageProbationGroup(group PluginPackageProbationGroup) (PluginPackageBatchOperationResult, error) {
	if err := validatePluginPackageProbationGroup(group); err != nil {
		return PluginPackageBatchOperationResult{}, err
	}
	for _, member := range group.Members {
		current, err := m.loadCurrentPlugin(member.PluginID)
		if err != nil {
			return PluginPackageBatchOperationResult{}, err
		}
		if current == nil || current.Version != member.Version {
			return PluginPackageBatchOperationResult{}, fmt.Errorf("plugin %s changed during probation: expected %s", member.PluginID, member.Version)
		}
	}
	tx, err := m.preparePluginPackageProbationGroupRecovery(group)
	if err != nil {
		return PluginPackageBatchOperationResult{}, err
	}
	if err := m.validatePluginPackageProbationRecoveryCatalog(tx); err != nil {
		_ = removePluginPackageManagedPath(m.stateRoot, m.pluginPackageBatchDir(tx.ID))
		return PluginPackageBatchOperationResult{}, err
	}
	previousRecovery := m.probationRecovery
	m.probationRecovery = true
	result, err := m.executePluginPackageBatchTransaction(&tx)
	m.probationRecovery = previousRecovery
	return result, err
}

func (m *pluginPackageManager) preparePluginPackageProbationGroupRecovery(group PluginPackageProbationGroup) (pluginPackageBatchTransaction, error) {
	batchID, err := newPluginPackageID()
	if err != nil {
		return pluginPackageBatchTransaction{}, err
	}
	batchDir := m.pluginPackageBatchDir(batchID)
	if err := os.Mkdir(batchDir, 0o700); err != nil {
		return pluginPackageBatchTransaction{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removePluginPackageManagedPath(m.stateRoot, batchDir)
		}
	}()
	if err := os.MkdirAll(filepath.Join(batchDir, "candidates"), 0o700); err != nil {
		return pluginPackageBatchTransaction{}, err
	}
	if err := os.MkdirAll(filepath.Join(batchDir, "backups"), 0o700); err != nil {
		return pluginPackageBatchTransaction{}, err
	}

	createdAt := time.Now().UTC()
	tx := pluginPackageBatchTransaction{
		ID: batchID, Operation: "batch_recover", ResourceMigrationID: batchID, ProbationGroupID: group.ID,
		Phase: pluginPackageBatchPhasePrepared, CreatedAt: createdAt.Format(time.RFC3339Nano),
		Items: make([]pluginPackageBatchTransactionItem, 0, len(group.Members)),
	}
	for _, member := range group.Members {
		current, err := m.loadCurrentPlugin(member.PluginID)
		if err != nil || current == nil {
			if err == nil {
				err = fmt.Errorf("plugin is not installed")
			}
			return pluginPackageBatchTransaction{}, fmt.Errorf("load probation candidate %s: %w", member.PluginID, err)
		}
		currentProvenance, err := m.loadPluginPackageProvenance(member.PluginID)
		if err != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("load probation candidate %s provenance: %w", member.PluginID, err)
		}
		if err := validatePluginPackageProvenanceForPackage(currentProvenance, member.PluginID, current.Version); err != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("validate probation candidate %s provenance: %w", member.PluginID, err)
		}
		transactionID, err := newPluginPackageID()
		if err != nil {
			return pluginPackageBatchTransaction{}, err
		}
		currentFingerprint, err := buildPluginDirectoryFingerprint(filepath.Join(m.pluginsRoot, member.PluginID))
		if err != nil {
			return pluginPackageBatchTransaction{}, err
		}
		_, currentPrivilegeDigest := pluginPrivilegeSummary(*current)
		item := pluginPackageBatchTransactionItem{
			TransactionID:           transactionID,
			HistoryID:               pluginPackageHistoryID(createdAt, transactionID),
			PluginID:                member.PluginID,
			Version:                 current.Version,
			PreviousVersion:         current.Version,
			PreviousPrivilegeDigest: currentPrivilegeDigest,
			PreviousFingerprint:     currentFingerprint,
			TargetDir:               filepath.Join(m.pluginsRoot, member.PluginID),
			BackupDir:               filepath.Join(batchDir, "backups", member.PluginID),
			PreviousProvenance:      clonePluginPackageProvenance(currentProvenance),
		}
		if member.PreviousHistoryID == "" {
			item.Operation = "uninstall"
			tx.Items = append(tx.Items, item)
			continue
		}
		history, err := m.ListHistory(member.PluginID)
		if err != nil {
			return pluginPackageBatchTransaction{}, err
		}
		var selected *PluginPackageHistoryEntry
		for i := range history {
			if history[i].ID == member.PreviousHistoryID {
				selected = &history[i]
				break
			}
		}
		if selected == nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("probation rollback history %s for %s is unavailable", member.PreviousHistoryID, member.PluginID)
		}
		candidateDir := filepath.Join(batchDir, "candidates", member.PluginID)
		if err := copyPluginDirectoryStrict(selected.pluginDir, candidateDir); err != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("copy probation rollback candidate %s: %w", member.PluginID, err)
		}
		candidate, _, _, err := m.validateCandidateDirectoryWithOptions(candidateDir, true)
		if err != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("validate probation rollback candidate %s: %w", member.PluginID, err)
		}
		if candidate.ID != member.PluginID || candidate.Version != selected.Version {
			return pluginPackageBatchTransaction{}, fmt.Errorf("probation rollback history identity mismatch for %s", member.PluginID)
		}
		candidateFingerprint, err := buildPluginDirectoryFingerprint(candidateDir)
		if err != nil {
			return pluginPackageBatchTransaction{}, err
		}
		item.Operation = "rollback"
		item.Version = candidate.Version
		item.CandidateDir = candidateDir
		item.CandidateFingerprint = candidateFingerprint
		item.CandidateProvenance = clonePluginPackageProvenance(selected.Provenance)
		tx.Items = append(tx.Items, item)
	}
	if err := m.writePluginPackageBatchTransaction(tx); err != nil {
		return pluginPackageBatchTransaction{}, err
	}
	cleanup = false
	return tx, nil
}

func (m *pluginPackageManager) validatePluginPackageProbationRecoveryCatalog(tx pluginPackageBatchTransaction) error {
	if tx.Operation != "batch_recover" {
		return fmt.Errorf("invalid probation recovery transaction")
	}
	validationCfg := pluginPackageValidationConfig(m.cfg, m.pluginsRoot)
	baseline := loadPluginCatalogWithControlRegistrationAndState(validationCfg, m.db)
	baselineStatus := make(map[string]string, len(baseline.Plugins))
	for _, plugin := range baseline.Plugins {
		baselineStatus[plugin.ID] = plugin.Status
	}
	for _, item := range tx.Items {
		if item.Operation == "uninstall" {
			filtered := baseline.Plugins[:0]
			for _, plugin := range baseline.Plugins {
				if plugin.ID != item.PluginID {
					filtered = append(filtered, plugin)
				}
			}
			baseline.Plugins = filtered
			continue
		}
		candidate, err := loadPluginFromDir(item.CandidateDir, item.PluginID)
		if err != nil {
			return err
		}
		candidate, err = registerPluginPackageCandidate(candidate, validationCfg)
		if err != nil {
			return err
		}
		candidate.Enabled = true
		candidate.Status = pluginStatusActive
		candidate.Runtime = externalPluginRuntimeState()
		candidate.Error = ""
		candidate.resolutionError = false
		found := false
		for i := range baseline.Plugins {
			if baseline.Plugins[i].ID == item.PluginID {
				baseline.Plugins[i] = candidate
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("probation recovery candidate %s is missing from the current catalog", item.PluginID)
		}
	}
	resolved := resolvePluginCatalogRelationships(baseline, currentPluginHostEnvironment())
	issues := make([]string, 0)
	for _, plugin := range resolved.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusError || baselineStatus[plugin.ID] == pluginStatusError {
			continue
		}
		issues = append(issues, plugin.ID+": "+plugin.Error)
	}
	if len(issues) > 0 {
		sort.Strings(issues)
		return fmt.Errorf("probation group recovery would leave plugins unavailable: %s", strings.Join(issues, "; "))
	}
	return nil
}
