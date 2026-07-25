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

func (m *pluginPackageManager) ApplyStage(request PluginPackageApplyRequest) (PluginPackageOperationResult, error) {
	stage, err := m.LoadStage(strings.TrimSpace(strings.ToLower(request.StageID)))
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	if stage.DeferredRelationships {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin stage defers relationship validation and must be applied as part of a batch")
	}
	if err := m.ensurePluginPackageMutationAllowed([]string{stage.PluginID}); err != nil {
		return PluginPackageOperationResult{}, err
	}
	if err := m.validatePluginPackageSourceApproval(stage, request); err != nil {
		return PluginPackageOperationResult{}, err
	}
	if len(stage.PrivilegeAdditions) > 0 && strings.TrimSpace(request.ApprovedPrivilegeDigest) != stage.PrivilegeDigest {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin privilege expansion requires approval digest %s", stage.PrivilegeDigest)
	}
	current, err := m.loadCurrentPlugin(stage.PluginID)
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	if current == nil {
		if err := m.enforcePluginPackageInstalledQuota(1); err != nil {
			return PluginPackageOperationResult{}, err
		}
	}
	if usage, err := measurePluginPackageManagedUsage(stage.candidateDir); err != nil {
		return PluginPackageOperationResult{}, err
	} else if err := m.enforcePluginPackageStorageQuota(usage.Bytes); err != nil {
		return PluginPackageOperationResult{}, err
	}
	currentVersion := ""
	currentFingerprint := ""
	var currentPrivileges []string
	if current != nil {
		currentVersion = current.Version
		currentPrivileges, _ = pluginPrivilegeSummary(*current)
		currentFingerprint, _ = buildPluginDirectoryFingerprint(filepath.Join(m.pluginsRoot, current.ID))
	}
	if currentVersion != stage.ExistingVersion || currentFingerprint != stage.ExistingFingerprint {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin source changed after staging: expected version %q, found %q", stage.ExistingVersion, currentVersion)
	}
	candidate, _, _, err := m.validateCandidateDirectory(stage.candidateDir)
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	candidatePrivileges, candidateDigest := pluginPrivilegeSummary(candidate)
	if candidateDigest != stage.PrivilegeDigest || !equalPluginPackageStrings(pluginPrivilegeAdditions(currentPrivileges, candidatePrivileges), stage.PrivilegeAdditions) {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin privilege set changed after staging")
	}
	if pluginRuntimeSurfaceDigest(pluginRuntimeSurfaceFromLoaded(candidate)) != stage.RuntimeSurfaceDigest {
		return PluginPackageOperationResult{}, fmt.Errorf("plugin runtime surface changed after staging")
	}
	rememberedPublishers, err := m.rememberPluginPackagePublishers([]pluginPackagePublisherApproval{{stage: stage, request: request}})
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	keepRememberedPublishers := false
	defer func() {
		if !keepRememberedPublishers {
			m.rollbackRememberedPluginPublishers(rememberedPublishers, "plugin package apply failed")
		}
	}()

	tx, err := m.prepareInstallTransaction(stage, current)
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	historyID, runtimeApplied, err := m.executeInstallTransaction(&tx)
	if err != nil {
		return PluginPackageOperationResult{}, err
	}
	keepRememberedPublishers = true
	_ = removePluginPackageManagedPath(m.stateRoot, stage.stageDir)
	result := PluginPackageOperationResult{
		PluginID:       stage.PluginID,
		Version:        stage.Version,
		Operation:      tx.Operation,
		HistoryID:      historyID,
		RuntimeApplied: runtimeApplied,
	}
	if !m.suppressProbation {
		fallbackHistoryID := result.HistoryID
		if result.Operation == "rollback" {
			fallbackHistoryID = ""
		}
		probation, probationErr := m.startPluginPackageProbation(result.PluginID, result.Version, fallbackHistoryID, result.RuntimeApplied)
		if probationErr != nil {
			warning := "plugin installed but probation could not be started: " + probationErr.Error()
			result.Warnings = append(result.Warnings, warning)
			recordPluginAudit(m.db, result.PluginID, "package.probation_started", "system", "error", map[string]any{
				"version": result.Version, "error": probationErr.Error(),
			})
		} else {
			result.Probation = probation
			recordPluginAudit(m.db, result.PluginID, "package.probation_started", "system", "success", map[string]any{
				"version": result.Version, "pending": probation.Pending, "expires_at": probation.ExpiresAt,
			})
		}
	}
	if m.pm != nil {
		catalog := m.pm.pluginCatalogWithConfig(m.cfg)
		result.Catalog = &catalog
	}
	recordPluginAudit(m.db, result.PluginID, "package."+result.Operation, "system", "success", map[string]any{
		"version": result.Version, "history_id": result.HistoryID, "runtime_applied": result.RuntimeApplied,
	})
	return result, nil
}

func (m *pluginPackageManager) prepareInstallTransaction(stage PluginPackageStage, current *LoadedPlugin) (pluginPackageTransaction, error) {
	previousProvenance, err := m.loadPluginPackageProvenance(stage.PluginID)
	if err != nil {
		return pluginPackageTransaction{}, fmt.Errorf("load current plugin provenance: %w", err)
	}
	if current == nil && previousProvenance != nil {
		return pluginPackageTransaction{}, fmt.Errorf("plugin %s has provenance but is not installed", stage.PluginID)
	}
	if current != nil {
		if err := validatePluginPackageProvenanceForPackage(previousProvenance, current.ID, current.Version); err != nil {
			return pluginPackageTransaction{}, fmt.Errorf("validate current plugin provenance: %w", err)
		}
	}
	candidateProvenance := clonePluginPackageProvenance(stage.Provenance)
	if err := validatePluginPackageProvenanceForPackage(candidateProvenance, stage.PluginID, stage.Version); err != nil {
		return pluginPackageTransaction{}, fmt.Errorf("validate candidate plugin provenance: %w", err)
	}
	txID, err := newPluginPackageID()
	if err != nil {
		return pluginPackageTransaction{}, err
	}
	txDir := filepath.Join(m.stateRoot, "transactions", txID)
	if err := os.Mkdir(txDir, 0o700); err != nil {
		return pluginPackageTransaction{}, err
	}
	candidateDir := filepath.Join(txDir, "candidate")
	if err := copyPluginDirectoryStrict(stage.candidateDir, candidateDir); err != nil {
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		return pluginPackageTransaction{}, fmt.Errorf("copy staged plugin candidate: %w", err)
	}
	targetDir := filepath.Join(m.pluginsRoot, stage.PluginID)
	operation := "install"
	if current != nil {
		operation = "update"
	}
	if stage.HistoryID != "" {
		operation = "rollback"
	}
	createdAt := time.Now().UTC()
	tx := pluginPackageTransaction{
		ID:                  txID,
		HistoryID:           pluginPackageHistoryID(createdAt, txID),
		Operation:           operation,
		PluginID:            stage.PluginID,
		Version:             stage.Version,
		ArchiveSHA256:       stage.ArchiveSHA256,
		ResourceMigrationID: txID,
		Phase:               "prepared",
		TargetDir:           targetDir,
		CandidateDir:        candidateDir,
		BackupDir:           filepath.Join(txDir, "backup"),
		StageDir:            stage.stageDir,
		CreatedAt:           createdAt.Format(time.RFC3339Nano),
		PreviousProvenance:  clonePluginPackageProvenance(previousProvenance),
		CandidateProvenance: candidateProvenance,
	}
	if current != nil {
		tx.PreviousVersion = current.Version
		_, tx.PreviousPrivilegeDigest = pluginPrivilegeSummary(*current)
		tx.PreviousFingerprint, _ = buildPluginDirectoryFingerprint(tx.TargetDir)
	}
	if err := m.writeTransaction(tx); err != nil {
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		return pluginPackageTransaction{}, err
	}
	return tx, nil
}

func (m *pluginPackageManager) executeInstallTransaction(tx *pluginPackageTransaction) (string, bool, error) {
	txDir := filepath.Dir(tx.CandidateDir)
	targetExists, err := regularPluginDirectoryExists(tx.TargetDir)
	if err != nil {
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		return "", false, err
	}
	if targetExists {
		if err := os.Rename(tx.TargetDir, tx.BackupDir); err != nil {
			_ = removePluginPackageManagedPath(m.stateRoot, txDir)
			return "", false, fmt.Errorf("move current plugin to transaction backup: %w", err)
		}
		tx.Phase = "old_moved"
		if err := m.writeTransaction(*tx); err != nil {
			rollbackErr := os.Rename(tx.BackupDir, tx.TargetDir)
			_ = removePluginPackageManagedPath(m.stateRoot, txDir)
			if rollbackErr != nil {
				return "", false, fmt.Errorf("write transaction state: %v; restore backup: %w", err, rollbackErr)
			}
			return "", false, err
		}
	}
	if err := os.Rename(tx.CandidateDir, tx.TargetDir); err != nil {
		if targetExists {
			_ = os.Rename(tx.BackupDir, tx.TargetDir)
		}
		_ = removePluginPackageManagedPath(m.stateRoot, txDir)
		return "", false, fmt.Errorf("activate plugin candidate: %w", err)
	}
	tx.Phase = "new_moved"
	if err := m.writeTransaction(*tx); err != nil {
		return "", false, m.rollbackInstallTransaction(*tx, err, false)
	}
	if err := m.beginPackageResourceMigration(*tx); err != nil {
		return "", false, m.rollbackInstallTransaction(*tx, err, false)
	}
	runtimeApplied, err := m.applyRuntimeChange(tx.PluginID)
	if err != nil {
		return "", false, m.rollbackInstallTransaction(*tx, err, true)
	}
	tx.Phase = "runtime_prepared"
	if err := m.writeTransaction(*tx); err != nil {
		return "", runtimeApplied, m.rollbackInstallTransaction(*tx, err, true)
	}
	if err := m.commitPackageResourceMigration(*tx); err != nil {
		return "", runtimeApplied, fmt.Errorf("plugin runtime prepared but resource migration commit failed; recovery will retry: %w", err)
	}
	if err := m.applyPluginPackageTransactionProvenance(*tx); err != nil {
		return "", runtimeApplied, fmt.Errorf("plugin runtime prepared but provenance commit failed; recovery will retry: %w", err)
	}
	tx.Phase = "runtime_applied"
	if err := m.writeTransaction(*tx); err != nil {
		return "", runtimeApplied, fmt.Errorf("plugin runtime applied but transaction journal update failed: %w", err)
	}
	historyID, err := m.finalizeTransactionHistory(*tx, pluginPackageTransactionHistoryReason(*tx))
	if err != nil {
		return "", runtimeApplied, fmt.Errorf("plugin runtime applied but history finalization failed: %w", err)
	}
	if err := removePluginPackageManagedPath(m.stateRoot, txDir); err != nil {
		return historyID, runtimeApplied, fmt.Errorf("plugin installed but transaction cleanup failed: %w", err)
	}
	return historyID, runtimeApplied, nil
}

func (m *pluginPackageManager) rollbackInstallTransaction(tx pluginPackageTransaction, cause error, runtimeAttempted bool) error {
	if err := m.rollbackPackageResourceMigration(tx); err != nil {
		cause = fmt.Errorf("%v; rollback resource migration: %w", cause, err)
	}
	txDir := filepath.Dir(tx.BackupDir)
	failedDir := filepath.Join(txDir, "failed-candidate")
	if exists, _ := regularPluginDirectoryExists(tx.TargetDir); exists {
		if err := os.Rename(tx.TargetDir, failedDir); err != nil {
			return fmt.Errorf("%v; move failed candidate for rollback: %w", cause, err)
		}
	}
	if exists, _ := regularPluginDirectoryExists(tx.BackupDir); exists {
		if err := os.Rename(tx.BackupDir, tx.TargetDir); err != nil {
			return fmt.Errorf("%v; restore previous plugin source: %w", cause, err)
		}
	}
	if err := m.restorePluginPackageTransactionProvenance(tx); err != nil {
		return fmt.Errorf("%v; restore previous plugin provenance: %w", cause, err)
	}
	var restoreErr error
	if runtimeAttempted {
		_, restoreErr = m.applyRuntimeChange(tx.PluginID)
	}
	_ = removePluginPackageManagedPath(m.stateRoot, txDir)
	if restoreErr != nil {
		return fmt.Errorf("%v; restore previous plugin runtime: %w", cause, restoreErr)
	}
	return cause
}

func (m *pluginPackageManager) beginPackageResourceMigration(tx pluginPackageTransaction) error {
	if m == nil || m.pm == nil || m.pm.pluginControlRuntime == nil || tx.ResourceMigrationID == "" {
		return nil
	}
	runtime, ok := m.pm.pluginControlRuntime.(pluginResourceMigrationTransactionRuntime)
	if !ok {
		return nil
	}
	return runtime.BeginPluginResourceMigrationTransactionWithID(tx.ResourceMigrationID)
}

func (m *pluginPackageManager) commitPackageResourceMigration(tx pluginPackageTransaction) error {
	if m != nil && m.pm != nil && m.pm.pluginControlRuntime != nil {
		if runtime, ok := m.pm.pluginControlRuntime.(pluginResourceMigrationTransactionRuntime); ok &&
			runtime.PluginResourceMigrationTransactionID() == tx.ResourceMigrationID {
			return runtime.CommitPluginResourceMigrationTransaction()
		}
	}
	return commitPluginResourceMigrationTransaction(m.db, tx.ResourceMigrationID)
}

func (m *pluginPackageManager) rollbackPackageResourceMigration(tx pluginPackageTransaction) error {
	if m != nil && m.pm != nil && m.pm.pluginControlRuntime != nil {
		if runtime, ok := m.pm.pluginControlRuntime.(pluginResourceMigrationTransactionRuntime); ok &&
			runtime.PluginResourceMigrationTransactionID() == tx.ResourceMigrationID {
			return runtime.RollbackPluginResourceMigrationTransaction()
		}
	}
	return rollbackPluginResourceMigrationTransaction(m.db, tx.ResourceMigrationID)
}

func (m *pluginPackageManager) applyRuntimeChange(pluginID string) (bool, error) {
	if m.runtimeApply != nil {
		return m.runtimeApply(pluginID)
	}
	if m.pm == nil || m.cfg == nil || !m.cfg.PluginsEnabled() {
		return false, nil
	}
	if err := m.pm.applyPluginCatalogUpdateSelection([]string{pluginID}); err != nil {
		return false, err
	}
	m.pm.redistributeWorkers()
	return true, nil
}

func (m *pluginPackageManager) applyRuntimeChanges(pluginIDs []string) (bool, error) {
	pluginIDs = normalizePluginPackageBatchPluginIDs(pluginIDs)
	if len(pluginIDs) == 0 {
		return false, nil
	}
	if m.runtimeApplyBatch != nil {
		return m.runtimeApplyBatch(pluginIDs)
	}
	if m.runtimeApply != nil {
		if len(pluginIDs) != 1 {
			return false, fmt.Errorf("batch runtime test hook is unavailable")
		}
		return m.runtimeApply(pluginIDs[0])
	}
	if m.pm == nil || m.cfg == nil || !m.cfg.PluginsEnabled() {
		return false, nil
	}
	if err := m.pm.applyPluginCatalogUpdateSelection(pluginIDs); err != nil {
		return false, err
	}
	m.pm.redistributeWorkers()
	return true, nil
}

func (m *pluginPackageManager) loadCurrentPlugin(pluginID string) (*LoadedPlugin, error) {
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return nil, fmt.Errorf("invalid plugin id")
	}
	root := filepath.Join(m.pluginsRoot, pluginID)
	exists, err := regularPluginDirectoryExists(root)
	if err != nil || !exists {
		return nil, err
	}
	plugin, err := loadPluginFromDir(root, pluginID)
	if err != nil {
		return nil, err
	}
	registered, registerErr := registerPluginPackageCandidate(plugin, pluginPackageValidationConfig(m.cfg, m.pluginsRoot))
	if registerErr == nil {
		plugin = registered
	}
	if plugin.ID != pluginID {
		return nil, fmt.Errorf("plugin directory %s contains manifest id %s", pluginID, plugin.ID)
	}
	return &plugin, nil
}

func regularPluginDirectoryExists(path string) (bool, error) {
	info, err := os.Lstat(path) // #nosec G703 -- callers pass validated plugin IDs or journal paths constrained to manager roots.
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("managed plugin path %s is not a regular directory", path)
	}
	return true, nil
}

func (m *pluginPackageManager) writeTransaction(tx pluginPackageTransaction) error {
	if err := m.validateTransactionPaths(tx); err != nil {
		return err
	}
	return writePluginPackageJSONAtomic(filepath.Join(m.stateRoot, "transactions", tx.ID, pluginPackageTransactionFile), tx, true)
}

func (m *pluginPackageManager) validateTransactionPaths(tx pluginPackageTransaction) error {
	if validatePluginPackageID(tx.ID) != nil || !pluginIDPattern.MatchString(tx.PluginID) || reservedBuiltinPluginID(tx.PluginID) {
		return fmt.Errorf("invalid plugin package transaction identity")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, tx.CreatedAt)
	if err != nil || tx.HistoryID != pluginPackageHistoryID(createdAt, tx.ID) {
		return fmt.Errorf("invalid plugin package transaction history identity")
	}
	switch tx.Operation {
	case "install", "update", "rollback", "uninstall":
	default:
		return fmt.Errorf("invalid plugin package transaction operation %q", tx.Operation)
	}
	if tx.PurgeData && tx.Operation != "uninstall" {
		return fmt.Errorf("plugin data purge is only valid for uninstall transactions")
	}
	if tx.ResourceMigrationID != "" && validatePluginPackageID(tx.ResourceMigrationID) != nil {
		return fmt.Errorf("invalid plugin package resource migration identity")
	}
	switch tx.Phase {
	case "prepared", "old_moved", "new_moved", "runtime_prepared", "runtime_applied":
	default:
		return fmt.Errorf("invalid plugin package transaction phase %q", tx.Phase)
	}
	expectedTarget := filepath.Join(m.pluginsRoot, tx.PluginID)
	if filepath.Clean(tx.TargetDir) != filepath.Clean(expectedTarget) {
		return fmt.Errorf("plugin package transaction target is invalid")
	}
	txRoot := filepath.Join(m.stateRoot, "transactions", tx.ID)
	for _, path := range []string{tx.CandidateDir, tx.BackupDir} {
		if path != "" && (filepath.Clean(path) == filepath.Clean(txRoot) || !pathWithinRoot(txRoot, path)) {
			return fmt.Errorf("plugin package transaction path escapes transaction root")
		}
	}
	if tx.StageDir != "" && !pathWithinRoot(filepath.Join(m.stateRoot, "staging"), tx.StageDir) {
		return fmt.Errorf("plugin package transaction stage path is invalid")
	}
	if tx.PreviousVersion == "" && tx.PreviousProvenance != nil {
		return fmt.Errorf("new plugin transaction cannot have previous provenance")
	}
	if tx.PreviousVersion != "" {
		if err := validatePluginPackageProvenanceForPackage(tx.PreviousProvenance, tx.PluginID, tx.PreviousVersion); err != nil {
			return fmt.Errorf("invalid previous plugin provenance: %w", err)
		}
	}
	if tx.Operation == "uninstall" {
		if tx.CandidateProvenance != nil {
			return fmt.Errorf("uninstall transaction cannot have candidate provenance")
		}
	} else if err := validatePluginPackageProvenanceForPackage(tx.CandidateProvenance, tx.PluginID, tx.Version); err != nil {
		return fmt.Errorf("invalid candidate plugin provenance: %w", err)
	}
	return nil
}

func (m *pluginPackageManager) recoverTransactions() error {
	root := filepath.Join(m.stateRoot, "transactions")
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read plugin package transactions: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || validatePluginPackageID(entry.Name()) != nil {
			continue
		}
		txDir := filepath.Join(root, entry.Name())
		var tx pluginPackageTransaction
		if err := readPluginPackageJSON(filepath.Join(txDir, pluginPackageTransactionFile), &tx); err != nil {
			return fmt.Errorf("read plugin package transaction %s: %w", entry.Name(), err)
		}
		if err := m.validateTransactionPaths(tx); err != nil {
			return err
		}
		if tx.Phase == "runtime_prepared" || tx.Phase == "runtime_applied" {
			if err := commitPluginResourceMigrationTransaction(m.db, tx.ResourceMigrationID); err != nil {
				return fmt.Errorf("recover plugin resource migration %s: %w", tx.PluginID, err)
			}
			if err := m.applyPluginPackageTransactionProvenance(tx); err != nil {
				return fmt.Errorf("recover plugin provenance %s: %w", tx.PluginID, err)
			}
			if tx.Phase == "runtime_prepared" {
				tx.Phase = "runtime_applied"
				if err := m.writeTransaction(tx); err != nil {
					return err
				}
			}
			if tx.Operation == "uninstall" {
				if err := cleanupPluginOwnedResources(m.db, newPluginControlNetAdmin(), tx.PluginID); err != nil {
					return fmt.Errorf("recover plugin-owned resource cleanup %s: %w", tx.PluginID, err)
				}
			}
			if _, err := m.finalizeTransactionHistory(tx, pluginPackageTransactionHistoryReason(tx)); err != nil {
				return err
			}
			if tx.PurgeData {
				if err := purgePluginBlobDataForRuntime(m.pm, m.stateRoot, tx.PluginID); err != nil {
					return fmt.Errorf("recover plugin blob purge %s: %w", tx.PluginID, err)
				}
				if err := store.DeletePluginData(m.db, tx.PluginID); err != nil {
					return fmt.Errorf("recover plugin data purge %s: %w", tx.PluginID, err)
				}
			}
			if err := removePluginPackageManagedPath(m.stateRoot, txDir); err != nil {
				return err
			}
			continue
		}
		if err := rollbackPluginResourceMigrationTransaction(m.db, tx.ResourceMigrationID); err != nil {
			return fmt.Errorf("rollback recovered plugin resource migration %s: %w", tx.PluginID, err)
		}
		targetExists, targetErr := regularPluginDirectoryExists(tx.TargetDir)
		backupExists, backupErr := regularPluginDirectoryExists(tx.BackupDir)
		if targetErr != nil || backupErr != nil {
			if targetErr != nil {
				return targetErr
			}
			return backupErr
		}
		if backupExists {
			if targetExists {
				failedDir := filepath.Join(txDir, "recovered-candidate")
				if err := os.Rename(tx.TargetDir, failedDir); err != nil {
					return err
				}
			}
			if err := os.Rename(tx.BackupDir, tx.TargetDir); err != nil {
				return err
			}
		} else if targetExists && tx.Phase == "new_moved" && tx.PreviousVersion == "" {
			failedDir := filepath.Join(txDir, "recovered-candidate")
			if err := os.Rename(tx.TargetDir, failedDir); err != nil {
				return err
			}
		}
		if err := m.restorePluginPackageTransactionProvenance(tx); err != nil {
			return fmt.Errorf("restore recovered plugin provenance %s: %w", tx.PluginID, err)
		}
		if _, err := m.applyRuntimeChange(tx.PluginID); err != nil {
			return fmt.Errorf("restore recovered plugin runtime %s: %w", tx.PluginID, err)
		}
		if err := removePluginPackageManagedPath(m.stateRoot, txDir); err != nil {
			return err
		}
	}
	return nil
}

func (m *pluginPackageManager) finalizeTransactionHistory(tx pluginPackageTransaction, reason string) (string, error) {
	backupExists, err := regularPluginDirectoryExists(tx.BackupDir)
	if err != nil {
		return "", err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, tx.CreatedAt)
	if err != nil {
		return "", fmt.Errorf("parse plugin transaction creation time: %w", err)
	}
	historyID := pluginPackageHistoryID(createdAt, tx.ID)
	if tx.HistoryID != historyID {
		return "", fmt.Errorf("plugin transaction history identity changed")
	}
	historyDir := filepath.Join(m.stateRoot, "history", tx.PluginID, historyID)
	pluginDir := filepath.Join(historyDir, "plugin")
	historyPluginExists, err := regularPluginDirectoryExists(pluginDir)
	if err != nil {
		return "", err
	}
	if !backupExists && !historyPluginExists {
		if tx.PreviousVersion == "" {
			return "", nil
		}
		return "", fmt.Errorf("plugin history source is missing for transaction %s", tx.ID)
	}
	if backupExists && historyPluginExists {
		return "", fmt.Errorf("plugin history contains both transaction backup and finalized source")
	}
	entry := PluginPackageHistoryEntry{
		ID:                historyID,
		PluginID:          tx.PluginID,
		Version:           tx.PreviousVersion,
		SourceFingerprint: tx.PreviousFingerprint,
		PrivilegeDigest:   tx.PreviousPrivilegeDigest,
		CreatedAt:         createdAt.UTC().Format(time.RFC3339Nano),
		Reason:            reason,
		Provenance:        clonePluginPackageProvenance(tx.PreviousProvenance),
	}
	metadataPath := filepath.Join(historyDir, pluginPackageHistoryMetadataFile)
	if historyPluginExists {
		if err := validatePluginPackageHistoryMetadata(metadataPath, entry); err != nil {
			return "", err
		}
		if err := m.pruneHistory(tx.PluginID); err != nil {
			return historyID, err
		}
		return historyID, nil
	}
	if err := ensurePluginPackageDirectory(historyDir, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Lstat(metadataPath); err == nil {
		if err := validatePluginPackageHistoryMetadata(metadataPath, entry); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	} else if err := writePluginPackageJSONAtomic(metadataPath, entry, false); err != nil {
		return "", err
	}
	if err := os.Rename(tx.BackupDir, pluginDir); err != nil {
		return "", err
	}
	if err := m.pruneHistory(tx.PluginID); err != nil {
		return historyID, err
	}
	return historyID, nil
}

func validatePluginPackageHistoryMetadata(path string, expected PluginPackageHistoryEntry) error {
	var actual PluginPackageHistoryEntry
	if err := readPluginPackageJSON(path, &actual); err != nil {
		return fmt.Errorf("read plugin history metadata: %w", err)
	}
	if actual.ID != expected.ID || actual.PluginID != expected.PluginID || actual.Version != expected.Version ||
		actual.ArchiveSHA256 != expected.ArchiveSHA256 || actual.SourceFingerprint != expected.SourceFingerprint ||
		actual.PrivilegeDigest != expected.PrivilegeDigest || actual.CreatedAt != expected.CreatedAt || actual.Reason != expected.Reason ||
		!equalPluginPackageProvenance(actual.Provenance, expected.Provenance) {
		return fmt.Errorf("plugin history metadata failed transaction validation")
	}
	if err := validatePluginPackageProvenanceForPackage(actual.Provenance, actual.PluginID, actual.Version); err != nil {
		return fmt.Errorf("plugin history provenance validation failed: %w", err)
	}
	return nil
}

func pluginPackageHistoryID(createdAt time.Time, transactionID string) string {
	return createdAt.UTC().Format("20060102T150405.000000000Z") + "-" + transactionID[:8]
}

func pluginPackageTransactionHistoryReason(tx pluginPackageTransaction) string {
	if tx.Operation == "uninstall" {
		return "uninstalled"
	}
	return "replaced by " + tx.Version
}

func (m *pluginPackageManager) ListHistory(pluginID string) ([]PluginPackageHistoryEntry, error) {
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return nil, fmt.Errorf("invalid plugin id")
	}
	root := filepath.Join(m.stateRoot, "history", pluginID)
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []PluginPackageHistoryEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	history := make([]PluginPackageHistoryEntry, 0, len(entries))
	for _, dirEntry := range entries {
		if !dirEntry.IsDir() || !validPluginPackageHistoryID(dirEntry.Name()) {
			continue
		}
		historyDir := filepath.Join(root, dirEntry.Name())
		var entry PluginPackageHistoryEntry
		if err := readPluginPackageJSON(filepath.Join(historyDir, pluginPackageHistoryMetadataFile), &entry); err != nil {
			return nil, err
		}
		if entry.ID != dirEntry.Name() || entry.PluginID != pluginID {
			return nil, fmt.Errorf("plugin history %s failed identity validation", dirEntry.Name())
		}
		if err := validatePluginPackageProvenanceForPackage(entry.Provenance, entry.PluginID, entry.Version); err != nil {
			return nil, fmt.Errorf("plugin history %s provenance: %w", dirEntry.Name(), err)
		}
		pluginDir := filepath.Join(historyDir, "plugin")
		if exists, err := regularPluginDirectoryExists(pluginDir); err != nil || !exists {
			if err == nil {
				err = fmt.Errorf("plugin history content is missing")
			}
			return nil, err
		}
		entry.pluginDir = pluginDir
		history = append(history, entry)
	}
	sort.Slice(history, func(i, j int) bool { return history[i].CreatedAt > history[j].CreatedAt })
	return history, nil
}

func (m *pluginPackageManager) pruneHistory(pluginID string) error {
	history, err := m.ListHistory(pluginID)
	if err != nil {
		return err
	}
	if len(history) <= pluginPackageHistoryLimit {
		return nil
	}
	for _, entry := range history[pluginPackageHistoryLimit:] {
		if err := removePluginPackageManagedPath(m.stateRoot, filepath.Dir(entry.pluginDir)); err != nil {
			return err
		}
	}
	return nil
}

func validPluginPackageHistoryID(value string) bool {
	if len(value) < 20 || len(value) > 64 || strings.ContainsAny(value, "/\\\x00") {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || r == 'T' || r == 'Z' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func equalPluginPackageStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
