package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	pluginPackageBatchPhasePrepared         = "prepared"
	pluginPackageBatchPhaseSourcesApplying  = "sources_applying"
	pluginPackageBatchPhaseSourcesApplied   = "sources_applied"
	pluginPackageBatchPhaseRuntimePreparing = "runtime_preparing"
	pluginPackageBatchPhaseRuntimePrepared  = "runtime_prepared"
	pluginPackageBatchPhaseRuntimeApplied   = "runtime_applied"
)

type pluginPackageBatchCandidate struct {
	request   PluginPackageApplyRequest
	stage     PluginPackageStage
	current   *LoadedPlugin
	candidate LoadedPlugin
}

func (m *pluginPackageManager) ApplyBatch(request PluginPackageBatchApplyRequest) (PluginPackageBatchOperationResult, error) {
	candidates, err := m.validatePluginPackageBatchRequest(request)
	if err != nil {
		return PluginPackageBatchOperationResult{}, err
	}
	pluginIDs := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		pluginIDs = append(pluginIDs, candidate.stage.PluginID)
	}
	if err := m.ensurePluginPackageMutationAllowed(pluginIDs); err != nil {
		return PluginPackageBatchOperationResult{}, err
	}
	if err := m.validatePluginPackageBatchCatalog(candidates); err != nil {
		return PluginPackageBatchOperationResult{}, err
	}
	tx, err := m.preparePluginPackageBatchTransaction(candidates)
	if err != nil {
		return PluginPackageBatchOperationResult{}, err
	}
	result, err := m.executePluginPackageBatchTransaction(&tx)
	if err != nil {
		return PluginPackageBatchOperationResult{}, err
	}
	return result, nil
}

func (m *pluginPackageManager) validatePluginPackageBatchRequest(request PluginPackageBatchApplyRequest) ([]pluginPackageBatchCandidate, error) {
	if len(request.Stages) == 0 || len(request.Stages) > pluginPackageBatchMaxStages {
		return nil, fmt.Errorf("plugin package batch must contain between 1 and %d stages", pluginPackageBatchMaxStages)
	}
	seenStages := make(map[string]struct{}, len(request.Stages))
	seenPlugins := make(map[string]struct{}, len(request.Stages))
	candidates := make([]pluginPackageBatchCandidate, 0, len(request.Stages))
	for _, applyRequest := range request.Stages {
		applyRequest.StageID = strings.TrimSpace(strings.ToLower(applyRequest.StageID))
		if _, duplicate := seenStages[applyRequest.StageID]; duplicate {
			return nil, fmt.Errorf("plugin package batch contains duplicate stage %s", applyRequest.StageID)
		}
		seenStages[applyRequest.StageID] = struct{}{}
		stage, err := m.LoadStage(applyRequest.StageID)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenPlugins[stage.PluginID]; duplicate {
			return nil, fmt.Errorf("plugin package batch contains more than one candidate for %s", stage.PluginID)
		}
		seenPlugins[stage.PluginID] = struct{}{}
		if stage.RequiresTrustedPublisher && !stage.Trusted {
			return nil, fmt.Errorf("dataplane plugin package %s requires a trusted publisher or TUF repository", stage.PluginID)
		}
		if !stage.Trusted && m.cfg.PluginsRequireSignedPackages() {
			return nil, fmt.Errorf("plugin package %s is unsigned and plugins_require_signed_packages is enabled", stage.PluginID)
		}
		if !stage.Trusted && !applyRequest.AllowUnsigned {
			return nil, fmt.Errorf("plugin package %s is unsigned; explicit allow_unsigned approval is required", stage.PluginID)
		}
		if len(stage.PrivilegeAdditions) > 0 && strings.TrimSpace(applyRequest.ApprovedPrivilegeDigest) != stage.PrivilegeDigest {
			return nil, fmt.Errorf("plugin %s privilege expansion requires approval digest %s", stage.PluginID, stage.PrivilegeDigest)
		}

		current, err := m.loadCurrentPlugin(stage.PluginID)
		if err != nil {
			return nil, err
		}
		currentVersion := ""
		currentFingerprint := ""
		var currentPrivileges []string
		if current != nil {
			currentVersion = current.Version
			currentPrivileges, _ = pluginPrivilegeSummary(*current)
			currentFingerprint, err = buildPluginDirectoryFingerprint(filepath.Join(m.pluginsRoot, current.ID))
			if err != nil {
				return nil, fmt.Errorf("fingerprint current plugin %s: %w", current.ID, err)
			}
		}
		if currentVersion != stage.ExistingVersion || currentFingerprint != stage.ExistingFingerprint {
			return nil, fmt.Errorf("plugin %s source changed after staging: expected version %q, found %q", stage.PluginID, stage.ExistingVersion, currentVersion)
		}
		candidate, _, _, err := m.validateCandidateDirectoryWithOptions(stage.candidateDir, true)
		if err != nil {
			return nil, err
		}
		candidatePrivileges, candidateDigest := pluginPrivilegeSummary(candidate)
		if candidateDigest != stage.PrivilegeDigest || !equalPluginPackageStrings(pluginPrivilegeAdditions(currentPrivileges, candidatePrivileges), stage.PrivilegeAdditions) {
			return nil, fmt.Errorf("plugin %s privilege set changed after staging", stage.PluginID)
		}
		if pluginRuntimeSurfaceDigest(pluginRuntimeSurfaceFromLoaded(candidate)) != stage.RuntimeSurfaceDigest {
			return nil, fmt.Errorf("plugin %s runtime surface changed after staging", stage.PluginID)
		}
		candidates = append(candidates, pluginPackageBatchCandidate{request: applyRequest, stage: stage, current: current, candidate: candidate})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].stage.PluginID < candidates[j].stage.PluginID })
	return candidates, nil
}

func (m *pluginPackageManager) validatePluginPackageBatchCatalog(candidates []pluginPackageBatchCandidate) error {
	validationCfg := pluginPackageValidationConfig(m.cfg, m.pluginsRoot)
	baseline := loadPluginCatalogWithControlRegistrationAndState(validationCfg, m.db)
	baselineStatus := make(map[string]string, len(baseline.Plugins))
	for _, plugin := range baseline.Plugins {
		baselineStatus[plugin.ID] = plugin.Status
	}
	for _, item := range candidates {
		candidate := item.candidate
		candidate.Enabled = true
		candidate.Status = pluginStatusActive
		candidate.Runtime = externalPluginRuntimeState()
		candidate.Error = ""
		candidate.resolutionError = false
		replaced := false
		for i := range baseline.Plugins {
			if baseline.Plugins[i].ID == candidate.ID {
				baseline.Plugins[i] = candidate
				replaced = true
				break
			}
		}
		if !replaced {
			baseline.Plugins = append(baseline.Plugins, candidate)
		}
	}
	resolved := resolvePluginCatalogRelationships(baseline, currentPluginHostEnvironment())
	if err := m.validatePluginPackageCatalogQuota(resolved); err != nil {
		return err
	}
	candidateIDs := make(map[string]struct{}, len(candidates))
	for _, item := range candidates {
		candidateIDs[item.stage.PluginID] = struct{}{}
		plugin := relationshipPluginByIDValue(resolved, item.stage.PluginID)
		if plugin == nil || plugin.Status != pluginStatusActive {
			if plugin == nil {
				return fmt.Errorf("plugin candidate %s disappeared during batch validation", item.stage.PluginID)
			}
			return fmt.Errorf("plugin candidate %s is incompatible: %s", item.stage.PluginID, plugin.Error)
		}
	}
	for _, plugin := range resolved.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusError {
			continue
		}
		if _, candidate := candidateIDs[plugin.ID]; candidate || baselineStatus[plugin.ID] != pluginStatusError {
			return fmt.Errorf("plugin package batch would make %s unavailable: %s", plugin.ID, plugin.Error)
		}
	}
	var reserve int64
	for _, item := range candidates {
		usage, err := measurePluginPackageManagedUsage(item.stage.candidateDir)
		if err != nil {
			return err
		}
		if reserve > m.pluginPackageStorageLimit()-usage.Bytes {
			return fmt.Errorf("plugin package batch storage reserve overflow")
		}
		reserve += usage.Bytes
	}
	if err := m.enforcePluginPackageStorageQuota(reserve); err != nil {
		return err
	}
	return nil
}

func (m *pluginPackageManager) preparePluginPackageBatchTransaction(candidates []pluginPackageBatchCandidate) (pluginPackageBatchTransaction, error) {
	batchID, err := newPluginPackageID()
	if err != nil {
		return pluginPackageBatchTransaction{}, err
	}
	batchDir := filepath.Join(m.stateRoot, "batches", batchID)
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
		ID: batchID, Operation: "batch_apply", ResourceMigrationID: batchID,
		Phase: pluginPackageBatchPhasePrepared, CreatedAt: createdAt.Format(time.RFC3339Nano),
		Items: make([]pluginPackageBatchTransactionItem, 0, len(candidates)),
	}
	for _, candidate := range candidates {
		previousProvenance, err := m.loadPluginPackageProvenance(candidate.stage.PluginID)
		if err != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("load current plugin %s provenance: %w", candidate.stage.PluginID, err)
		}
		if candidate.current == nil && previousProvenance != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("plugin %s has provenance but is not installed", candidate.stage.PluginID)
		}
		if candidate.current != nil {
			if err := validatePluginPackageProvenanceForPackage(previousProvenance, candidate.stage.PluginID, candidate.current.Version); err != nil {
				return pluginPackageBatchTransaction{}, fmt.Errorf("validate current plugin %s provenance: %w", candidate.stage.PluginID, err)
			}
		}
		candidateProvenance := clonePluginPackageProvenance(candidate.stage.Provenance)
		if err := validatePluginPackageProvenanceForPackage(candidateProvenance, candidate.stage.PluginID, candidate.stage.Version); err != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("validate candidate plugin %s provenance: %w", candidate.stage.PluginID, err)
		}
		transactionID, err := newPluginPackageID()
		if err != nil {
			return pluginPackageBatchTransaction{}, err
		}
		candidateDir := filepath.Join(batchDir, "candidates", candidate.stage.PluginID)
		if err := m.injectPluginPackageBatchFault("copy." + candidate.stage.PluginID); err != nil {
			return pluginPackageBatchTransaction{}, err
		}
		if err := copyPluginDirectoryStrict(candidate.stage.candidateDir, candidateDir); err != nil {
			return pluginPackageBatchTransaction{}, fmt.Errorf("copy staged plugin candidate %s: %w", candidate.stage.PluginID, err)
		}
		operation := "install"
		if candidate.current != nil {
			operation = "update"
		}
		if candidate.stage.HistoryID != "" {
			operation = "rollback"
		}
		item := pluginPackageBatchTransactionItem{
			TransactionID:        transactionID,
			HistoryID:            pluginPackageHistoryID(createdAt, transactionID),
			StageID:              candidate.stage.ID,
			Operation:            operation,
			PluginID:             candidate.stage.PluginID,
			Version:              candidate.stage.Version,
			ArchiveSHA256:        candidate.stage.ArchiveSHA256,
			CandidateFingerprint: candidate.stage.CandidateFingerprint,
			TargetDir:            filepath.Join(m.pluginsRoot, candidate.stage.PluginID),
			CandidateDir:         candidateDir,
			BackupDir:            filepath.Join(batchDir, "backups", candidate.stage.PluginID),
			StageDir:             candidate.stage.stageDir,
			PreviousProvenance:   clonePluginPackageProvenance(previousProvenance),
			CandidateProvenance:  candidateProvenance,
		}
		if candidate.current != nil {
			item.PreviousVersion = candidate.current.Version
			_, item.PreviousPrivilegeDigest = pluginPrivilegeSummary(*candidate.current)
			item.PreviousFingerprint = candidate.stage.ExistingFingerprint
		}
		tx.Items = append(tx.Items, item)
	}
	if err := m.writePluginPackageBatchTransaction(tx); err != nil {
		return pluginPackageBatchTransaction{}, err
	}
	cleanup = false
	return tx, nil
}

func (m *pluginPackageManager) executePluginPackageBatchTransaction(tx *pluginPackageBatchTransaction) (PluginPackageBatchOperationResult, error) {
	if err := m.verifyPluginPackageBatchSources(*tx); err != nil {
		_ = removePluginPackageManagedPath(m.stateRoot, m.pluginPackageBatchDir(tx.ID))
		return PluginPackageBatchOperationResult{}, err
	}
	tx.Phase = pluginPackageBatchPhaseSourcesApplying
	if err := m.writePluginPackageBatchTransaction(*tx); err != nil {
		return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, err, false)
	}
	for _, item := range tx.Items {
		if item.PreviousVersion != "" {
			if err := os.Rename(item.TargetDir, item.BackupDir); err != nil {
				return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, fmt.Errorf("move current plugin %s to batch backup: %w", item.PluginID, err), false)
			}
		}
		if item.CandidateDir != "" {
			if err := os.Rename(item.CandidateDir, item.TargetDir); err != nil {
				return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, fmt.Errorf("activate plugin candidate %s: %w", item.PluginID, err), false)
			}
		}
	}
	tx.Phase = pluginPackageBatchPhaseSourcesApplied
	if err := m.writePluginPackageBatchTransaction(*tx); err != nil {
		return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, err, false)
	}
	tx.Phase = pluginPackageBatchPhaseRuntimePreparing
	if err := m.writePluginPackageBatchTransaction(*tx); err != nil {
		return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, err, false)
	}
	if err := m.beginPluginPackageBatchResourceMigration(*tx); err != nil {
		return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, err, false)
	}
	runtimeApplied, err := m.applyRuntimeChanges(pluginPackageBatchIDs(*tx))
	if err != nil {
		return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, err, true)
	}
	tx.Phase = pluginPackageBatchPhaseRuntimePrepared
	if err := m.writePluginPackageBatchTransaction(*tx); err != nil {
		return PluginPackageBatchOperationResult{}, m.rollbackPluginPackageBatchTransaction(*tx, err, true)
	}
	if err := m.commitPluginPackageBatchResourceMigration(*tx); err != nil {
		return PluginPackageBatchOperationResult{}, fmt.Errorf("plugin batch runtime prepared but resource migration commit failed; recovery will retry: %w", err)
	}
	if err := m.applyPluginPackageBatchProvenance(*tx, true); err != nil {
		return PluginPackageBatchOperationResult{}, fmt.Errorf("plugin batch runtime prepared but provenance commit failed; recovery will retry: %w", err)
	}
	tx.Phase = pluginPackageBatchPhaseRuntimeApplied
	if err := m.writePluginPackageBatchTransaction(*tx); err != nil {
		return PluginPackageBatchOperationResult{}, fmt.Errorf("plugin batch runtime applied but journal update failed: %w", err)
	}
	return m.finalizePluginPackageBatchTransaction(*tx, runtimeApplied)
}

func (m *pluginPackageManager) verifyPluginPackageBatchSources(tx pluginPackageBatchTransaction) error {
	for _, item := range tx.Items {
		exists, err := regularPluginDirectoryExists(item.TargetDir)
		if err != nil {
			return err
		}
		if item.PreviousVersion == "" {
			if exists {
				return fmt.Errorf("plugin %s was installed after batch staging", item.PluginID)
			}
			continue
		}
		if !exists {
			return fmt.Errorf("plugin %s was removed after batch staging", item.PluginID)
		}
		fingerprint, err := buildPluginDirectoryFingerprint(item.TargetDir)
		if err != nil {
			return err
		}
		if fingerprint != item.PreviousFingerprint {
			return fmt.Errorf("plugin %s source changed after batch staging", item.PluginID)
		}
	}
	return nil
}

func (m *pluginPackageManager) beginPluginPackageBatchResourceMigration(tx pluginPackageBatchTransaction) error {
	if m == nil || m.pm == nil || m.pm.pluginControlRuntime == nil {
		return nil
	}
	runtime, ok := m.pm.pluginControlRuntime.(pluginResourceMigrationTransactionRuntime)
	if !ok {
		return nil
	}
	return runtime.BeginPluginResourceMigrationTransactionWithID(tx.ResourceMigrationID)
}

func (m *pluginPackageManager) commitPluginPackageBatchResourceMigration(tx pluginPackageBatchTransaction) error {
	if m != nil && m.pm != nil && m.pm.pluginControlRuntime != nil {
		if runtime, ok := m.pm.pluginControlRuntime.(pluginResourceMigrationTransactionRuntime); ok && runtime.PluginResourceMigrationTransactionID() == tx.ResourceMigrationID {
			return runtime.CommitPluginResourceMigrationTransaction()
		}
	}
	return commitPluginResourceMigrationTransaction(m.db, tx.ResourceMigrationID)
}

func (m *pluginPackageManager) rollbackPluginPackageBatchResourceMigration(tx pluginPackageBatchTransaction) error {
	if m != nil && m.pm != nil && m.pm.pluginControlRuntime != nil {
		if runtime, ok := m.pm.pluginControlRuntime.(pluginResourceMigrationTransactionRuntime); ok && runtime.PluginResourceMigrationTransactionID() == tx.ResourceMigrationID {
			return runtime.RollbackPluginResourceMigrationTransaction()
		}
	}
	return rollbackPluginResourceMigrationTransaction(m.db, tx.ResourceMigrationID)
}

func (m *pluginPackageManager) rollbackPluginPackageBatchTransaction(tx pluginPackageBatchTransaction, cause error, runtimeAttempted bool) error {
	if err := m.rollbackPluginPackageBatchResourceMigration(tx); err != nil {
		cause = fmt.Errorf("%v; rollback resource migration: %w", cause, err)
	}
	if err := m.restorePluginPackageBatchSources(tx); err != nil {
		return fmt.Errorf("%v; restore plugin sources: %w", cause, err)
	}
	if err := m.applyPluginPackageBatchProvenance(tx, false); err != nil {
		return fmt.Errorf("%v; restore plugin provenance: %w", cause, err)
	}
	if runtimeAttempted {
		if _, err := m.applyRuntimeChanges(pluginPackageBatchIDs(tx)); err != nil {
			return fmt.Errorf("%v; restore previous plugin runtime: %w", cause, err)
		}
	}
	if err := removePluginPackageManagedPath(m.stateRoot, m.pluginPackageBatchDir(tx.ID)); err != nil {
		return fmt.Errorf("%v; clean plugin batch transaction: %w", cause, err)
	}
	return cause
}

func (m *pluginPackageManager) restorePluginPackageBatchSources(tx pluginPackageBatchTransaction) error {
	failedRoot := filepath.Join(m.pluginPackageBatchDir(tx.ID), "failed")
	if err := os.MkdirAll(failedRoot, 0o700); err != nil {
		return err
	}
	for _, item := range tx.Items {
		targetExists, targetErr := regularPluginDirectoryExists(item.TargetDir)
		backupExists, backupErr := regularPluginDirectoryExists(item.BackupDir)
		candidateExists := false
		var candidateErr error
		if item.CandidateDir != "" {
			candidateExists, candidateErr = regularPluginDirectoryExists(item.CandidateDir)
		}
		if targetErr != nil {
			return targetErr
		}
		if backupErr != nil {
			return backupErr
		}
		if candidateErr != nil {
			return candidateErr
		}
		if backupExists {
			if targetExists {
				if err := m.movePluginPackageBatchTargetAside(tx, item); err != nil {
					return err
				}
			}
			if err := os.Rename(item.BackupDir, item.TargetDir); err != nil {
				return fmt.Errorf("restore previous plugin %s: %w", item.PluginID, err)
			}
			continue
		}
		if item.PreviousVersion != "" {
			if !targetExists {
				return fmt.Errorf("previous plugin source %s is missing", item.PluginID)
			}
			fingerprint, err := buildPluginDirectoryFingerprint(item.TargetDir)
			if err != nil {
				return err
			}
			if fingerprint != item.PreviousFingerprint {
				return fmt.Errorf("plugin %s has neither its expected backup nor previous source", item.PluginID)
			}
			continue
		}
		if !targetExists {
			continue
		}
		if candidateExists {
			return fmt.Errorf("new plugin path %s appeared before its batch candidate was activated", item.PluginID)
		}
		fingerprint, err := buildPluginDirectoryFingerprint(item.TargetDir)
		if err != nil {
			return err
		}
		if fingerprint != item.CandidateFingerprint {
			return fmt.Errorf("new plugin path %s does not match the batch candidate", item.PluginID)
		}
		if err := m.movePluginPackageBatchTargetAside(tx, item); err != nil {
			return err
		}
	}
	return nil
}

func (m *pluginPackageManager) movePluginPackageBatchTargetAside(tx pluginPackageBatchTransaction, item pluginPackageBatchTransactionItem) error {
	failedDir := filepath.Join(m.pluginPackageBatchDir(tx.ID), "failed", item.PluginID)
	if err := removePluginPackageManagedPath(m.stateRoot, failedDir); err != nil {
		return err
	}
	if err := os.Rename(item.TargetDir, failedDir); err != nil {
		return fmt.Errorf("move failed plugin candidate %s aside: %w", item.PluginID, err)
	}
	return nil
}

func (m *pluginPackageManager) finalizePluginPackageBatchTransaction(tx pluginPackageBatchTransaction, runtimeApplied bool) (PluginPackageBatchOperationResult, error) {
	result := PluginPackageBatchOperationResult{ID: tx.ID, Operation: tx.Operation, RuntimeApplied: runtimeApplied}
	for _, item := range tx.Items {
		single := item.pluginPackageTransaction(tx)
		if err := m.injectPluginPackageBatchFault("history." + item.PluginID); err != nil {
			return PluginPackageBatchOperationResult{}, err
		}
		historyID, err := m.finalizeTransactionHistory(single, pluginPackageTransactionHistoryReason(single))
		if err != nil {
			return PluginPackageBatchOperationResult{}, fmt.Errorf("finalize plugin %s history: %w", item.PluginID, err)
		}
		operationResult := PluginPackageOperationResult{
			PluginID: item.PluginID, Version: item.Version, Operation: item.Operation,
			HistoryID: historyID, RuntimeApplied: runtimeApplied,
		}
		result.Plugins = append(result.Plugins, operationResult)
	}
	if tx.Operation == "batch_apply" && !m.suppressProbation {
		group := PluginPackageProbationGroup{ID: tx.ID, CreatedAt: tx.CreatedAt, Members: make([]PluginPackageProbationGroupMember, 0, len(tx.Items))}
		for i, item := range tx.Items {
			fallbackHistoryID := result.Plugins[i].HistoryID
			group.Members = append(group.Members, PluginPackageProbationGroupMember{
				PluginID: item.PluginID, Version: item.Version, Operation: item.Operation, PreviousHistoryID: fallbackHistoryID,
			})
		}
		if _, err := m.ensurePluginPackageProbationGroup(group); err != nil {
			return PluginPackageBatchOperationResult{}, fmt.Errorf("create plugin probation group: %w", err)
		}
		for i, item := range tx.Items {
			if err := m.injectPluginPackageBatchFault("probation." + item.PluginID); err != nil {
				return PluginPackageBatchOperationResult{}, err
			}
			member := group.Members[i]
			probation, err := m.ensurePluginPackageBatchProbation(item.PluginID, item.Version, member.PreviousHistoryID, group.ID, runtimeApplied)
			if err != nil {
				return PluginPackageBatchOperationResult{}, fmt.Errorf("start plugin %s probation: %w", item.PluginID, err)
			}
			result.Plugins[i].Probation = probation
		}
	}
	if tx.Operation == "batch_recover" {
		group, err := m.loadPluginPackageProbationGroup(tx.ProbationGroupID)
		if err != nil && !os.IsNotExist(err) {
			return PluginPackageBatchOperationResult{}, fmt.Errorf("load recovered probation group: %w", err)
		}
		if err == nil {
			if err := m.removePluginPackageProbationGroupState(group); err != nil {
				return PluginPackageBatchOperationResult{}, fmt.Errorf("clean recovered probation group: %w", err)
			}
		}
	}
	for _, item := range tx.Items {
		if item.StageDir != "" {
			if err := removePluginPackageManagedPath(m.stateRoot, item.StageDir); err != nil {
				return PluginPackageBatchOperationResult{}, fmt.Errorf("clean plugin %s stage: %w", item.PluginID, err)
			}
		}
	}
	if m.pm != nil {
		catalog := m.pm.pluginCatalogWithConfig(m.cfg)
		result.Catalog = &catalog
	}
	for _, plugin := range result.Plugins {
		recordPluginAudit(m.db, plugin.PluginID, "package."+plugin.Operation, "system", "success", map[string]any{
			"batch_id": tx.ID, "version": plugin.Version, "history_id": plugin.HistoryID, "runtime_applied": runtimeApplied,
		})
	}
	recordPluginAudit(m.db, "", "package."+tx.Operation, "system", "success", map[string]any{
		"batch_id": tx.ID, "plugin_ids": pluginPackageBatchIDs(tx), "runtime_applied": runtimeApplied,
	})
	if err := removePluginPackageManagedPath(m.stateRoot, m.pluginPackageBatchDir(tx.ID)); err != nil {
		return PluginPackageBatchOperationResult{}, fmt.Errorf("plugin batch applied but transaction cleanup failed: %w", err)
	}
	return result, nil
}

func (m *pluginPackageManager) ensurePluginPackageBatchProbation(pluginID, version, historyID, groupID string, runtimeApplied bool) (*PluginPackageProbation, error) {
	existing, err := m.loadPluginPackageProbation(pluginID)
	if err == nil && existing.Version == version && existing.PreviousHistoryID == historyID && existing.GroupID == groupID {
		copy := existing
		return &copy, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return m.startPluginPackageProbationWithGroup(pluginID, version, historyID, groupID, runtimeApplied)
}

func (item pluginPackageBatchTransactionItem) pluginPackageTransaction(batch pluginPackageBatchTransaction) pluginPackageTransaction {
	return pluginPackageTransaction{
		ID: item.TransactionID, HistoryID: item.HistoryID, Operation: item.Operation,
		PluginID: item.PluginID, Version: item.Version, PreviousVersion: item.PreviousVersion,
		PreviousPrivilegeDigest: item.PreviousPrivilegeDigest, PreviousFingerprint: item.PreviousFingerprint,
		ArchiveSHA256: item.ArchiveSHA256, ResourceMigrationID: batch.ResourceMigrationID,
		Phase: "runtime_applied", TargetDir: item.TargetDir, CandidateDir: item.CandidateDir,
		BackupDir: item.BackupDir, StageDir: item.StageDir, CreatedAt: batch.CreatedAt,
		PreviousProvenance:  clonePluginPackageProvenance(item.PreviousProvenance),
		CandidateProvenance: clonePluginPackageProvenance(item.CandidateProvenance),
	}
}

func (m *pluginPackageManager) writePluginPackageBatchTransaction(tx pluginPackageBatchTransaction) error {
	if err := m.validatePluginPackageBatchTransaction(tx); err != nil {
		return err
	}
	if err := m.injectPluginPackageBatchFault("journal." + tx.Phase); err != nil {
		return err
	}
	return writePluginPackageJSONAtomic(filepath.Join(m.pluginPackageBatchDir(tx.ID), pluginPackageBatchMetadataFile), tx, true)
}

func (m *pluginPackageManager) injectPluginPackageBatchFault(point string) error {
	if m == nil || m.batchFault == nil {
		return nil
	}
	return m.batchFault(point)
}

func (m *pluginPackageManager) validatePluginPackageBatchTransaction(tx pluginPackageBatchTransaction) error {
	if validatePluginPackageID(tx.ID) != nil || tx.ResourceMigrationID != tx.ID {
		return fmt.Errorf("invalid plugin package batch identity")
	}
	switch tx.Operation {
	case "batch_apply":
		if tx.ProbationGroupID != "" {
			return fmt.Errorf("plugin apply batch cannot reference a probation group")
		}
	case "batch_recover":
		if validatePluginPackageID(tx.ProbationGroupID) != nil {
			return fmt.Errorf("plugin recovery batch requires a probation group")
		}
	default:
		return fmt.Errorf("invalid plugin package batch operation %q", tx.Operation)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, tx.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return fmt.Errorf("invalid plugin package batch creation time")
	}
	switch tx.Phase {
	case pluginPackageBatchPhasePrepared, pluginPackageBatchPhaseSourcesApplying, pluginPackageBatchPhaseSourcesApplied,
		pluginPackageBatchPhaseRuntimePreparing, pluginPackageBatchPhaseRuntimePrepared, pluginPackageBatchPhaseRuntimeApplied:
	default:
		return fmt.Errorf("invalid plugin package batch phase %q", tx.Phase)
	}
	if len(tx.Items) == 0 || len(tx.Items) > pluginPackageBatchMaxStages {
		return fmt.Errorf("invalid plugin package batch item count")
	}
	batchRoot := m.pluginPackageBatchDir(tx.ID)
	seenPlugins := make(map[string]struct{}, len(tx.Items))
	seenTransactions := make(map[string]struct{}, len(tx.Items))
	for _, item := range tx.Items {
		if !pluginIDPattern.MatchString(item.PluginID) || reservedBuiltinPluginID(item.PluginID) || validatePluginPackageID(item.TransactionID) != nil {
			return fmt.Errorf("invalid plugin package batch item identity")
		}
		if tx.Operation == "batch_apply" {
			if validatePluginPackageID(item.StageID) != nil {
				return fmt.Errorf("invalid plugin package batch stage identity")
			}
		} else if item.StageID != "" || item.StageDir != "" {
			return fmt.Errorf("plugin recovery batch cannot reference a package stage")
		}
		if _, duplicate := seenPlugins[item.PluginID]; duplicate {
			return fmt.Errorf("duplicate plugin %s in package batch", item.PluginID)
		}
		seenPlugins[item.PluginID] = struct{}{}
		if _, duplicate := seenTransactions[item.TransactionID]; duplicate {
			return fmt.Errorf("duplicate package transaction in batch")
		}
		seenTransactions[item.TransactionID] = struct{}{}
		if item.HistoryID != pluginPackageHistoryID(createdAt, item.TransactionID) {
			return fmt.Errorf("invalid plugin package batch history identity")
		}
		if normalized, versionErr := normalizePluginSemanticVersion(item.Version); versionErr != nil || normalized != item.Version {
			return fmt.Errorf("invalid plugin package batch version for %s", item.PluginID)
		}
		if tx.Operation == "batch_apply" {
			switch item.Operation {
			case "install":
				if item.PreviousVersion != "" {
					return fmt.Errorf("install batch item %s has a previous version", item.PluginID)
				}
			case "update", "rollback":
				if item.PreviousVersion == "" || item.PreviousFingerprint == "" {
					return fmt.Errorf("replacement batch item %s is missing previous source metadata", item.PluginID)
				}
			default:
				return fmt.Errorf("invalid plugin package batch operation %q", item.Operation)
			}
		} else {
			if item.PreviousVersion == "" || item.PreviousFingerprint == "" {
				return fmt.Errorf("recovery batch item %s is missing current source metadata", item.PluginID)
			}
			if item.Operation != "rollback" && item.Operation != "uninstall" {
				return fmt.Errorf("invalid plugin recovery operation %q", item.Operation)
			}
		}
		if filepath.Clean(item.TargetDir) != filepath.Join(m.pluginsRoot, item.PluginID) {
			return fmt.Errorf("invalid plugin package batch target for %s", item.PluginID)
		}
		expectedCandidate := filepath.Join(batchRoot, "candidates", item.PluginID)
		if item.Operation == "uninstall" {
			if item.CandidateDir != "" || item.CandidateFingerprint != "" {
				return fmt.Errorf("uninstall recovery item %s cannot have a candidate", item.PluginID)
			}
		} else if item.CandidateFingerprint == "" || filepath.Clean(item.CandidateDir) != expectedCandidate {
			return fmt.Errorf("invalid plugin package batch candidate for %s", item.PluginID)
		}
		if filepath.Clean(item.BackupDir) != filepath.Join(batchRoot, "backups", item.PluginID) {
			return fmt.Errorf("invalid plugin package batch managed path for %s", item.PluginID)
		}
		if tx.Operation == "batch_apply" && filepath.Clean(item.StageDir) != filepath.Join(m.stateRoot, "staging", item.StageID) {
			return fmt.Errorf("invalid plugin package batch stage path for %s", item.PluginID)
		}
		if item.PreviousVersion == "" && item.PreviousProvenance != nil {
			return fmt.Errorf("new plugin batch item %s cannot have previous provenance", item.PluginID)
		}
		if item.PreviousVersion != "" {
			if err := validatePluginPackageProvenanceForPackage(item.PreviousProvenance, item.PluginID, item.PreviousVersion); err != nil {
				return fmt.Errorf("invalid previous plugin provenance for %s: %w", item.PluginID, err)
			}
		}
		if item.Operation == "uninstall" {
			if item.CandidateProvenance != nil {
				return fmt.Errorf("uninstall batch item %s cannot have candidate provenance", item.PluginID)
			}
		} else if err := validatePluginPackageProvenanceForPackage(item.CandidateProvenance, item.PluginID, item.Version); err != nil {
			return fmt.Errorf("invalid candidate plugin provenance for %s: %w", item.PluginID, err)
		}
	}
	return nil
}

func (m *pluginPackageManager) recoverBatchTransactions() error {
	root := filepath.Join(m.stateRoot, "batches")
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read plugin package batch transactions: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || validatePluginPackageID(entry.Name()) != nil {
			continue
		}
		var tx pluginPackageBatchTransaction
		if err := readPluginPackageJSON(filepath.Join(root, entry.Name(), pluginPackageBatchMetadataFile), &tx); err != nil {
			return fmt.Errorf("read plugin package batch transaction %s: %w", entry.Name(), err)
		}
		if tx.ID != entry.Name() {
			return fmt.Errorf("plugin package batch directory identity mismatch")
		}
		if err := m.validatePluginPackageBatchTransaction(tx); err != nil {
			return err
		}
		if tx.Phase == pluginPackageBatchPhaseRuntimePrepared || tx.Phase == pluginPackageBatchPhaseRuntimeApplied {
			if err := m.commitPluginPackageBatchResourceMigration(tx); err != nil {
				return fmt.Errorf("recover plugin batch resource migration %s: %w", tx.ID, err)
			}
			if err := m.applyPluginPackageBatchProvenance(tx, true); err != nil {
				return fmt.Errorf("recover plugin batch provenance %s: %w", tx.ID, err)
			}
			if tx.Phase == pluginPackageBatchPhaseRuntimePrepared {
				tx.Phase = pluginPackageBatchPhaseRuntimeApplied
				if err := m.writePluginPackageBatchTransaction(tx); err != nil {
					return err
				}
			}
			if _, err := m.finalizePluginPackageBatchTransaction(tx, false); err != nil {
				return err
			}
			continue
		}
		if err := m.rollbackPluginPackageBatchResourceMigration(tx); err != nil {
			return fmt.Errorf("rollback recovered plugin batch resource migration %s: %w", tx.ID, err)
		}
		if err := m.restorePluginPackageBatchSources(tx); err != nil {
			return fmt.Errorf("restore recovered plugin batch sources %s: %w", tx.ID, err)
		}
		if err := m.applyPluginPackageBatchProvenance(tx, false); err != nil {
			return fmt.Errorf("restore recovered plugin batch provenance %s: %w", tx.ID, err)
		}
		if tx.Phase == pluginPackageBatchPhaseRuntimePreparing {
			if _, err := m.applyRuntimeChanges(pluginPackageBatchIDs(tx)); err != nil {
				return fmt.Errorf("restore recovered plugin batch runtime %s: %w", tx.ID, err)
			}
		}
		if err := removePluginPackageManagedPath(m.stateRoot, m.pluginPackageBatchDir(tx.ID)); err != nil {
			return err
		}
	}
	return nil
}

func (m *pluginPackageManager) pluginPackageBatchDir(id string) string {
	return filepath.Join(m.stateRoot, "batches", id)
}

func pluginPackageBatchIDs(tx pluginPackageBatchTransaction) []string {
	ids := make([]string, 0, len(tx.Items))
	for _, item := range tx.Items {
		ids = append(ids, item.PluginID)
	}
	return normalizePluginPackageBatchPluginIDs(ids)
}

func normalizePluginPackageBatchPluginIDs(pluginIDs []string) []string {
	seen := make(map[string]struct{}, len(pluginIDs))
	out := make([]string, 0, len(pluginIDs))
	for _, pluginID := range pluginIDs {
		pluginID = strings.TrimSpace(strings.ToLower(pluginID))
		if pluginID == "" {
			continue
		}
		if _, exists := seen[pluginID]; exists {
			continue
		}
		seen[pluginID] = struct{}{}
		out = append(out, pluginID)
	}
	sort.Strings(out)
	return out
}
