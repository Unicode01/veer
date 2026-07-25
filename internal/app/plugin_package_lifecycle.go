package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

func (m *pluginPackageManager) PrepareRollback(request PluginPackageRollbackRequest) (PluginPackageStage, error) {
	if err := m.enforcePluginPackageStageQuota(); err != nil {
		return PluginPackageStage{}, err
	}
	pluginID := strings.TrimSpace(strings.ToLower(request.PluginID))
	historyID := strings.TrimSpace(request.HistoryID)
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) || !validPluginPackageHistoryID(historyID) {
		return PluginPackageStage{}, fmt.Errorf("invalid plugin rollback request")
	}
	if err := m.ensurePluginPackageMutationAllowed([]string{pluginID}); err != nil {
		return PluginPackageStage{}, err
	}
	history, err := m.ListHistory(pluginID)
	if err != nil {
		return PluginPackageStage{}, err
	}
	var selected *PluginPackageHistoryEntry
	for i := range history {
		if history[i].ID == historyID {
			selected = &history[i]
			break
		}
	}
	if selected == nil {
		return PluginPackageStage{}, fmt.Errorf("plugin history %s not found", historyID)
	}
	stageID, err := newPluginPackageID()
	if err != nil {
		return PluginPackageStage{}, err
	}
	stageDir := filepath.Join(m.stateRoot, "staging", stageID)
	candidateDir := filepath.Join(stageDir, "extracted", pluginID)
	if err := os.MkdirAll(filepath.Dir(candidateDir), 0o700); err != nil {
		return PluginPackageStage{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removePluginPackageManagedPath(m.stateRoot, stageDir)
		}
	}()
	if err := copyPluginDirectoryStrict(selected.pluginDir, candidateDir); err != nil {
		return PluginPackageStage{}, err
	}
	candidate, previous, affected, err := m.validateCandidateDirectory(candidateDir)
	if err != nil {
		return PluginPackageStage{}, err
	}
	if candidate.ID != pluginID || candidate.Version != selected.Version {
		return PluginPackageStage{}, fmt.Errorf("plugin history content does not match history metadata")
	}
	fingerprint, err := buildPluginDirectoryFingerprint(candidateDir)
	if err != nil {
		return PluginPackageStage{}, err
	}
	privileges, privilegeDigest := pluginPrivilegeSummary(candidate)
	runtimeSurface := pluginRuntimeSurfaceFromLoaded(candidate)
	var previousPrivileges []string
	existingVersion := ""
	existingFingerprint := ""
	if previous != nil {
		existingVersion = previous.Version
		previousPrivileges, _ = pluginPrivilegeSummary(*previous)
		existingFingerprint, _ = buildPluginDirectoryFingerprint(filepath.Join(m.pluginsRoot, previous.ID))
	}
	now := time.Now().UTC()
	stage := PluginPackageStage{
		ID:                   stageID,
		PluginID:             candidate.ID,
		Name:                 candidate.Name,
		Version:              candidate.Version,
		ExistingVersion:      existingVersion,
		ExistingFingerprint:  existingFingerprint,
		ArchiveSHA256:        fingerprint,
		CandidateFingerprint: fingerprint,
		Trusted:              true,
		PublisherStatus:      pluginPackagePublisherNone,
		ExecutionTier:        pluginPackageExecutionTier(candidate),
		Stability:            candidate.Stability,
		PrivilegeDigest:      privilegeDigest,
		PrivilegeAdditions:   pluginPrivilegeAdditions(previousPrivileges, privileges),
		AffectedPlugins:      affected,
		HistoryID:            historyID,
		TrustSource:          "history",
		Provenance:           clonePluginPackageProvenance(selected.Provenance),
		CreatedAt:            now.Format(time.RFC3339Nano),
		ExpiresAt:            now.Add(pluginPackageStageLifetime).Format(time.RFC3339Nano),
		Compatibility:        clonePluginCompatibility(candidate.Compatibility),
		Dependencies:         append([]PluginDependency(nil), candidate.Dependencies...),
		Conflicts:            append([]PluginConflict(nil), candidate.Conflicts...),
		RuntimeSurface:       runtimeSurface,
		RuntimeSurfaceDigest: pluginRuntimeSurfaceDigest(runtimeSurface),
		candidateDir:         candidateDir,
		stageDir:             stageDir,
	}
	if candidate.Control != nil {
		stage.Permissions = append([]string(nil), candidate.Control.Permissions...)
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(stageDir, pluginPackageStageMetadataFile), pluginPackageStageRecord{Stage: stage}, false); err != nil {
		return PluginPackageStage{}, err
	}
	cleanup = false
	recordPluginAudit(m.db, stage.PluginID, "package.rollback_stage", "system", "success", map[string]any{
		"stage_id": stage.ID, "history_id": stage.HistoryID, "version": stage.Version,
	})
	return stage, nil
}

func (m *pluginPackageManager) Uninstall(request PluginPackageUninstallRequest) (PluginPackageOperationResult, error) {
	pluginID := strings.TrimSpace(strings.ToLower(request.PluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return PluginPackageOperationResult{}, fmt.Errorf("invalid plugin id")
	}
	if err := m.ensurePluginPackageMutationAllowed([]string{pluginID}); err != nil {
		return PluginPackageOperationResult{}, err
	}
	current, err := m.loadCurrentPlugin(pluginID)
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	if current == nil {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin %s is not installed", pluginID)
	}
	previousProvenance, err := m.loadPluginPackageProvenance(pluginID)
	if err != nil {
		return PluginPackageOperationResult{}, fmt.Errorf("load current plugin provenance: %w", err)
	}
	if err := validatePluginPackageProvenanceForPackage(previousProvenance, pluginID, current.Version); err != nil {
		return PluginPackageOperationResult{}, fmt.Errorf("validate current plugin provenance: %w", err)
	}
	dependents, err := m.uninstallDependents(pluginID)
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	if len(dependents) > 0 && !request.Force {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin %s is required by: %s", pluginID, strings.Join(dependents, ", "))
	}
	txID, err := newPluginPackageID()
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	txDir := filepath.Join(m.stateRoot, "transactions", txID)
	if err := os.Mkdir(txDir, 0o700); err != nil {
		return PluginPackageOperationResult{}, err
	}
	_, privilegeDigest := pluginPrivilegeSummary(*current)
	previousFingerprint, _ := buildPluginDirectoryFingerprint(filepath.Join(m.pluginsRoot, pluginID))
	createdAt := time.Now().UTC()
	tx := pluginPackageTransaction{
		ID:                      txID,
		HistoryID:               pluginPackageHistoryID(createdAt, txID),
		Operation:               "uninstall",
		PluginID:                pluginID,
		PreviousVersion:         current.Version,
		PreviousPrivilegeDigest: privilegeDigest,
		PreviousFingerprint:     previousFingerprint,
		Phase:                   "prepared",
		TargetDir:               filepath.Join(m.pluginsRoot, pluginID),
		BackupDir:               filepath.Join(txDir, "backup"),
		PurgeData:               request.PurgeData,
		CreatedAt:               createdAt.Format(time.RFC3339Nano),
		PreviousProvenance:      clonePluginPackageProvenance(previousProvenance),
	}
	if err := m.writeTransaction(tx); err != nil {
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		return PluginPackageOperationResult{}, err
	}
	if err := os.Rename(tx.TargetDir, tx.BackupDir); err != nil {
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		return PluginPackageOperationResult{}, err
	}
	tx.Phase = "old_moved"
	if err := m.writeTransaction(tx); err != nil {
		_ = os.Rename(tx.BackupDir, tx.TargetDir)
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		return PluginPackageOperationResult{}, err
	}
	runtimeApplied, err := m.applyRuntimeChange(pluginID)
	if err != nil {
		if restoreErr := os.Rename(tx.BackupDir, tx.TargetDir); restoreErr != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("%v; restore uninstalled plugin source: %w", err, restoreErr)
		}
		_, runtimeRestoreErr := m.applyRuntimeChange(pluginID)
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		if runtimeRestoreErr != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("%v; restore plugin runtime: %w", err, runtimeRestoreErr)
		}
		return PluginPackageOperationResult{}, err
	}
	if err := cleanupPluginOwnedResources(m.db, newPluginControlNetAdmin(), pluginID); err != nil {
		if restoreErr := os.Rename(tx.BackupDir, tx.TargetDir); restoreErr != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("cleanup plugin-owned resources: %v; restore uninstalled plugin source: %w", err, restoreErr)
		}
		_, runtimeRestoreErr := m.applyRuntimeChange(pluginID)
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		if runtimeRestoreErr != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("cleanup plugin-owned resources: %v; restore plugin runtime: %w", err, runtimeRestoreErr)
		}
		return PluginPackageOperationResult{}, fmt.Errorf("cleanup plugin-owned resources: %w", err)
	}
	tx.Phase = "runtime_prepared"
	if err := m.writeTransaction(tx); err != nil {
		if restoreErr := os.Rename(tx.BackupDir, tx.TargetDir); restoreErr != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("write uninstall commit state: %v; restore plugin source: %w", err, restoreErr)
		}
		_, runtimeRestoreErr := m.applyRuntimeChange(pluginID)
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		if runtimeRestoreErr != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("write uninstall commit state: %v; restore plugin runtime: %w", err, runtimeRestoreErr)
		}
		return PluginPackageOperationResult{}, err
	}
	if err := m.applyPluginPackageTransactionProvenance(tx); err != nil {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin runtime prepared but provenance commit failed; recovery will retry: %w", err)
	}
	tx.Phase = "runtime_applied"
	if err := m.writeTransaction(tx); err != nil {
		return PluginPackageOperationResult{}, err
	}
	historyID, err := m.finalizeTransactionHistory(tx, pluginPackageTransactionHistoryReason(tx))
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	if request.PurgeData {
		if err := purgePluginBlobDataForRuntime(m.pm, m.stateRoot, pluginID); err != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("plugin uninstalled but blob purge failed: %w", err)
		}
		if err := store.DeletePluginData(m.db, pluginID); err != nil {
			return PluginPackageOperationResult{}, fmt.Errorf("plugin uninstalled but data purge failed: %w", err)
		}
	}
	if err := removePluginPackageManagedPath(m.stateRoot, txDir); err != nil {
		return PluginPackageOperationResult{}, err
	}
	result := PluginPackageOperationResult{
		PluginID:       pluginID,
		Version:        current.Version,
		Operation:      "uninstall",
		HistoryID:      historyID,
		RuntimeApplied: runtimeApplied,
	}
	if err := m.removePluginPackageProbation(pluginID); err != nil {
		result.Warnings = append(result.Warnings, "plugin uninstalled but probation cleanup failed: "+err.Error())
	}
	if m.pm != nil {
		catalog := m.pm.pluginCatalogWithConfig(m.cfg)
		result.Catalog = &catalog
	}
	recordPluginAudit(m.db, pluginID, "package.uninstall", "system", "success", map[string]any{
		"version": current.Version, "history_id": historyID, "purge_data": request.PurgeData, "runtime_applied": runtimeApplied,
	})
	return result, nil
}

func (m *pluginPackageManager) uninstallDependents(pluginID string) ([]string, error) {
	validationCfg := pluginPackageValidationConfig(m.cfg, m.pluginsRoot)
	catalog := loadPluginCatalogWithControlRegistrationAndState(validationCfg, m.db)
	before := make(map[string]string, len(catalog.Plugins))
	filtered := make([]LoadedPlugin, 0, len(catalog.Plugins))
	found := false
	for _, plugin := range catalog.Plugins {
		before[plugin.ID] = plugin.Status
		if plugin.ID == pluginID {
			found = true
			continue
		}
		filtered = append(filtered, plugin)
	}
	if !found {
		return nil, fmt.Errorf("plugin %s is not present in the catalog", pluginID)
	}
	catalog.Plugins = filtered
	catalog = resolvePluginCatalogRelationships(catalog, currentPluginHostEnvironment())
	dependents := make([]string, 0)
	for _, plugin := range catalog.Plugins {
		if before[plugin.ID] != pluginStatusError && plugin.Status == pluginStatusError && strings.Contains(plugin.Error, "required dependency "+pluginID) {
			dependents = append(dependents, plugin.ID)
		}
	}
	sort.Strings(dependents)
	return dependents, nil
}
