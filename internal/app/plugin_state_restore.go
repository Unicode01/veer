package app

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	storepkg "github.com/Unicode01/veer/internal/store"
)

const (
	pluginStateRestoreFormatVersion  = 1
	pluginStateRestoreJournalSuffix  = ".veer-restore.json"
	pluginStateRestoreStagePrefix    = ".veer-restore-"
	pluginStateRestoreManifestMax    = 8 << 20
	pluginStateRestoreArchiveMaxOver = 64 << 20
)

const (
	pluginStateRestorePhaseStaged   = "staged"
	pluginStateRestorePhaseApplying = "applying"
	pluginStateRestorePhaseApplied  = "applied"
	pluginStateRestorePhaseFailed   = "failed"

	pluginStateRestoreItemPending    = "pending"
	pluginStateRestoreItemPrepared   = "prepared"
	pluginStateRestoreItemBackingUp  = "backing_up"
	pluginStateRestoreItemBackedUp   = "backed_up"
	pluginStateRestoreItemInstalling = "installing"
	pluginStateRestoreItemInstalled  = "installed"
)

type pluginStateRestoreJournal struct {
	FormatVersion int                      `json:"format_version"`
	ID            string                   `json:"id"`
	CreatedAt     string                   `json:"created_at"`
	ArchiveSHA256 string                   `json:"archive_sha256"`
	DatabasePath  string                   `json:"database_path"`
	PluginsRoot   string                   `json:"plugins_root"`
	StageRoot     string                   `json:"stage_root"`
	Phase         string                   `json:"phase"`
	LastError     string                   `json:"last_error,omitempty"`
	Items         []pluginStateRestoreItem `json:"items"`
}

type pluginStateRestoreItem struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	Candidate     string `json:"candidate"`
	Backup        string `json:"backup"`
	Desired       bool   `json:"desired"`
	OriginalKnown bool   `json:"original_known,omitempty"`
	HadOriginal   bool   `json:"had_original,omitempty"`
	Phase         string `json:"phase"`
}

type pluginStateRestoreStageResult struct {
	ID              string `json:"id"`
	ArchiveSHA256   string `json:"archive_sha256"`
	DatabasePath    string `json:"database_path"`
	PluginsRoot     string `json:"plugins_root"`
	JournalPath     string `json:"journal_path"`
	RestartRequired bool   `json:"restart_required"`
}

type pluginStateRestoreCommandResult struct {
	ID          string `json:"id,omitempty"`
	Phase       string `json:"phase,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	Pending     bool   `json:"pending"`
	RetryStaged bool   `json:"retry_staged,omitempty"`
	Cancelled   bool   `json:"cancelled,omitempty"`
}

type pluginStateRestoreStartupResult struct {
	ID      string
	Applied bool
	Failed  bool
	Error   string
}

func runPluginStateRestoreCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	archive := flags.String("archive", "", "Veer plugin state backup .tar.gz")
	databasePath := flags.String("database", "forward.db", "Veer SQLite database path")
	pluginsDir := flags.String("plugins-dir", defaultPluginsDir, "managed plugins directory")
	status := flags.Bool("status", false, "show the pending restore request")
	retry := flags.Bool("retry", false, "retry a failed restore request on next startup")
	cancel := flags.Bool("cancel", false, "cancel a staged or failed restore request")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("plugin restore does not accept positional arguments")
	}
	modeCount := 0
	for _, enabled := range []bool{*status, *retry, *cancel} {
		if enabled {
			modeCount++
		}
	}
	if modeCount > 1 || (modeCount > 0 && strings.TrimSpace(*archive) != "") {
		return fmt.Errorf("plugin restore accepts exactly one of --archive, --status, --retry, or --cancel")
	}
	if modeCount > 0 {
		result, err := managePluginStateRestore(*databasePath, *pluginsDir, *status, *retry, *cancel)
		if err != nil {
			return err
		}
		return writePluginPackageCLIJSON(stdout, result)
	}
	if strings.TrimSpace(*archive) == "" {
		return fmt.Errorf("plugin restore requires --archive, --status, --retry, or --cancel")
	}
	result, err := stagePluginStateRestore(*archive, *databasePath, *pluginsDir)
	if err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, result)
}

func managePluginStateRestore(databasePath, pluginsDir string, status, retry, cancel bool) (pluginStateRestoreCommandResult, error) {
	database, err := filepath.Abs(strings.TrimSpace(databasePath))
	if err != nil {
		return pluginStateRestoreCommandResult{}, err
	}
	pluginsRoot, err := filepath.Abs(normalizePluginsDir(pluginsDir))
	if err != nil {
		return pluginStateRestoreCommandResult{}, err
	}
	journalPath := database + pluginStateRestoreJournalSuffix
	if _, err := os.Lstat(journalPath); os.IsNotExist(err) {
		return pluginStateRestoreCommandResult{Pending: false}, nil
	} else if err != nil {
		return pluginStateRestoreCommandResult{}, err
	}
	var journal pluginStateRestoreJournal
	if err := readPluginPackageJSON(journalPath, &journal); err != nil {
		return pluginStateRestoreCommandResult{}, err
	}
	if err := validatePluginStateRestoreJournal(journal, database, pluginsRoot); err != nil {
		return pluginStateRestoreCommandResult{}, err
	}
	result := pluginStateRestoreCommandResult{ID: journal.ID, Phase: journal.Phase, LastError: journal.LastError, Pending: true}
	if status {
		return result, nil
	}
	if journal.Phase != pluginStateRestorePhaseStaged && journal.Phase != pluginStateRestorePhaseFailed {
		return pluginStateRestoreCommandResult{}, fmt.Errorf("restore request %s is %s and cannot be changed", journal.ID, journal.Phase)
	}
	if err := ensurePluginStateRestoreHasNoBackups(journal); err != nil {
		return pluginStateRestoreCommandResult{}, err
	}
	if cancel {
		for _, item := range journal.Items {
			if err := removePluginStateRestoreTypedPath(item.Candidate, item.Kind); err != nil {
				return pluginStateRestoreCommandResult{}, err
			}
		}
		if err := os.RemoveAll(journal.StageRoot); err != nil {
			return pluginStateRestoreCommandResult{}, err
		}
		if err := os.Remove(journalPath); err != nil {
			return pluginStateRestoreCommandResult{}, err
		}
		result.Pending = false
		result.Cancelled = true
		return result, nil
	}
	if retry {
		if journal.Phase != pluginStateRestorePhaseFailed {
			return pluginStateRestoreCommandResult{}, fmt.Errorf("only a failed restore request can be retried")
		}
		if err := refreshPluginStateRestorePayload(journal); err != nil {
			return pluginStateRestoreCommandResult{}, fmt.Errorf("verify retry payload: %w", err)
		}
		for index := range journal.Items {
			item := &journal.Items[index]
			if err := removePluginStateRestoreTypedPath(item.Candidate, item.Kind); err != nil {
				return pluginStateRestoreCommandResult{}, err
			}
			item.Phase = pluginStateRestoreItemPending
			item.OriginalKnown = false
			item.HadOriginal = false
		}
		journal.Phase = pluginStateRestorePhaseStaged
		journal.LastError = ""
		if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
			return pluginStateRestoreCommandResult{}, err
		}
		result.Phase = journal.Phase
		result.LastError = ""
		result.RetryStaged = true
		return result, nil
	}
	return pluginStateRestoreCommandResult{}, fmt.Errorf("restore management mode is required")
}

func ensurePluginStateRestoreHasNoBackups(journal pluginStateRestoreJournal) error {
	for _, item := range journal.Items {
		exists, err := pluginStateRestorePathExists(item.Backup, item.Kind)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("restore request %s still has an active rollback backup for %s", journal.ID, item.Name)
		}
	}
	return nil
}

func stagePluginStateRestore(archivePath, databasePath, pluginsDir string) (pluginStateRestoreStageResult, error) {
	archive, err := filepath.Abs(strings.TrimSpace(archivePath))
	if err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	archiveInfo, err := os.Lstat(archive)
	if err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	if archiveInfo.Mode()&os.ModeSymlink != 0 || !archiveInfo.Mode().IsRegular() || archiveInfo.Size() <= 0 || archiveInfo.Size() > pluginStateBackupMaxTotalBytes+pluginStateRestoreArchiveMaxOver {
		return pluginStateRestoreStageResult{}, fmt.Errorf("restore archive must be a bounded regular file")
	}
	database, err := filepath.Abs(strings.TrimSpace(databasePath))
	if err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	pluginsRoot, err := filepath.Abs(normalizePluginsDir(pluginsDir))
	if err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	if err := validatePluginStateRestoreTargets(database, pluginsRoot); err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	journalPath := database + pluginStateRestoreJournalSuffix
	if _, err := os.Lstat(journalPath); err == nil {
		return pluginStateRestoreStageResult{}, fmt.Errorf("a plugin state restore request is already pending")
	} else if !os.IsNotExist(err) {
		return pluginStateRestoreStageResult{}, err
	}
	id, err := newPluginPackageID()
	if err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	stageRoot := filepath.Join(filepath.Dir(database), pluginStateRestoreStagePrefix+id)
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stageRoot)
		}
	}()
	stagedArchive := filepath.Join(stageRoot, "backup.tar.gz")
	if err := copyPluginStateRestoreFile(archive, stagedArchive, pluginStateBackupMaxTotalBytes+pluginStateRestoreArchiveMaxOver); err != nil {
		return pluginStateRestoreStageResult{}, fmt.Errorf("stage restore archive: %w", err)
	}
	payloadRoot := filepath.Join(stageRoot, "payload")
	_, archiveDigest, err := extractPluginStateBackupArchive(stagedArchive, payloadRoot)
	if err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	if err := validatePluginStateRestorePayload(payloadRoot); err != nil {
		return pluginStateRestoreStageResult{}, fmt.Errorf("validate plugin state backup: %w", err)
	}
	journal := newPluginStateRestoreJournal(id, archiveDigest, database, pluginsRoot, stageRoot, payloadRoot)
	if err := validatePluginStateRestoreJournal(journal, database, pluginsRoot); err != nil {
		return pluginStateRestoreStageResult{}, err
	}
	if err := writePluginPackageJSONAtomic(journalPath, journal, false); err != nil {
		return pluginStateRestoreStageResult{}, fmt.Errorf("write restore journal: %w", err)
	}
	cleanup = false
	return pluginStateRestoreStageResult{
		ID: id, ArchiveSHA256: archiveDigest, DatabasePath: database, PluginsRoot: pluginsRoot,
		JournalPath: journalPath, RestartRequired: true,
	}, nil
}

func newPluginStateRestoreJournal(id, archiveDigest, database, pluginsRoot, stageRoot, payloadRoot string) pluginStateRestoreJournal {
	dbParent := filepath.Dir(database)
	pluginParent := filepath.Dir(pluginsRoot)
	keySource := filepath.Join(payloadRoot, "database", "forward.db"+pluginSecretKeyFileSuffix)
	keyDesired, _ := boundedRegularFileExists(keySource, pluginSecretKeyringMaxBytes)
	items := []pluginStateRestoreItem{
		newPluginStateRestoreItem(id, "plugins", "directory", filepath.Join(payloadRoot, "plugins"), pluginsRoot, pluginParent, true),
		newPluginStateRestoreItem(id, "state", "directory", filepath.Join(payloadRoot, "state"), pluginsRoot+pluginPackageStateSuffix, pluginParent, true),
		newPluginStateRestoreItem(id, "secret_key", "file", keySource, database+pluginSecretKeyFileSuffix, dbParent, keyDesired),
		newPluginStateRestoreItem(id, "database", "file", filepath.Join(payloadRoot, "database", "forward.db"), database, dbParent, true),
	}
	return pluginStateRestoreJournal{
		FormatVersion: pluginStateRestoreFormatVersion,
		ID:            id, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ArchiveSHA256: archiveDigest,
		DatabasePath: database, PluginsRoot: pluginsRoot, StageRoot: stageRoot,
		Phase: pluginStateRestorePhaseStaged, Items: items,
	}
}

func newPluginStateRestoreItem(id, name, kind, source, target, parent string, desired bool) pluginStateRestoreItem {
	base := pluginStateRestoreStagePrefix + id + "-" + name
	return pluginStateRestoreItem{
		Name: name, Kind: kind, Source: source, Target: target,
		Candidate: filepath.Join(parent, base+"-candidate"),
		Backup:    filepath.Join(parent, base+"-backup"),
		Desired:   desired, Phase: pluginStateRestoreItemPending,
	}
}

func recoverPendingPluginStateRestore(databasePath, pluginsDir string) (pluginStateRestoreStartupResult, error) {
	database, err := filepath.Abs(strings.TrimSpace(databasePath))
	if err != nil {
		return pluginStateRestoreStartupResult{}, err
	}
	pluginsRoot, err := filepath.Abs(normalizePluginsDir(pluginsDir))
	if err != nil {
		return pluginStateRestoreStartupResult{}, err
	}
	journalPath := database + pluginStateRestoreJournalSuffix
	if _, err := os.Lstat(journalPath); os.IsNotExist(err) {
		return pluginStateRestoreStartupResult{}, nil
	} else if err != nil {
		return pluginStateRestoreStartupResult{}, err
	}
	var journal pluginStateRestoreJournal
	if err := readPluginPackageJSON(journalPath, &journal); err != nil {
		return pluginStateRestoreStartupResult{}, fmt.Errorf("read plugin restore journal: %w", err)
	}
	if err := validatePluginStateRestoreJournal(journal, database, pluginsRoot); err != nil {
		return pluginStateRestoreStartupResult{}, fmt.Errorf("validate plugin restore journal: %w", err)
	}
	result := pluginStateRestoreStartupResult{ID: journal.ID}
	if journal.Phase == pluginStateRestorePhaseFailed {
		result.Failed = true
		result.Error = journal.LastError
		return result, nil
	}
	if journal.Phase == pluginStateRestorePhaseApplied {
		if err := validatePluginStateRestoreTargetsInstalled(journal); err != nil {
			return result, fmt.Errorf("validate applied plugin restore %s: %w", journal.ID, err)
		}
		if err := cleanupPluginStateRestore(journalPath, journal); err != nil {
			return result, err
		}
		result.Applied = true
		return result, nil
	}
	return applyPluginStateRestore(journalPath, journal)
}

func applyPluginStateRestore(journalPath string, journal pluginStateRestoreJournal) (pluginStateRestoreStartupResult, error) {
	result := pluginStateRestoreStartupResult{ID: journal.ID}
	if err := refreshPluginStateRestorePayload(journal); err != nil {
		return failPluginStateRestore(journalPath, &journal, fmt.Errorf("verify staged restore: %w", err))
	}
	journal.Phase = pluginStateRestorePhaseApplying
	journal.LastError = ""
	if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
		return result, err
	}
	for index := range journal.Items {
		if err := preparePluginStateRestoreItem(&journal.Items[index]); err != nil {
			return failPluginStateRestore(journalPath, &journal, fmt.Errorf("prepare %s: %w", journal.Items[index].Name, err))
		}
		if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
			return result, err
		}
	}
	for index := range journal.Items {
		if err := installPluginStateRestoreItem(journalPath, &journal, index); err != nil {
			return failPluginStateRestore(journalPath, &journal, fmt.Errorf("install %s: %w", journal.Items[index].Name, err))
		}
	}
	if err := validatePluginStateRestoreTargetsInstalled(journal); err != nil {
		return failPluginStateRestore(journalPath, &journal, fmt.Errorf("validate restored state: %w", err))
	}
	journal.Phase = pluginStateRestorePhaseApplied
	if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
		return result, err
	}
	if err := cleanupPluginStateRestore(journalPath, journal); err != nil {
		return result, err
	}
	result.Applied = true
	return result, nil
}

func refreshPluginStateRestorePayload(journal pluginStateRestoreJournal) error {
	stagedArchive := filepath.Join(journal.StageRoot, "backup.tar.gz")
	digest, err := sha256File(stagedArchive)
	if err != nil {
		return err
	}
	if digest != journal.ArchiveSHA256 {
		return fmt.Errorf("staged restore archive failed SHA256 validation")
	}
	payloadRoot := filepath.Join(journal.StageRoot, "payload")
	tempPayload := filepath.Join(journal.StageRoot, "payload.verify")
	if err := os.RemoveAll(tempPayload); err != nil {
		return err
	}
	_, extractedDigest, err := extractPluginStateBackupArchive(stagedArchive, tempPayload)
	if err != nil {
		return err
	}
	if extractedDigest != journal.ArchiveSHA256 {
		_ = os.RemoveAll(tempPayload)
		return fmt.Errorf("staged restore archive digest changed while reading")
	}
	if err := validatePluginStateRestorePayload(tempPayload); err != nil {
		_ = os.RemoveAll(tempPayload)
		return err
	}
	if err := os.RemoveAll(payloadRoot); err != nil {
		_ = os.RemoveAll(tempPayload)
		return err
	}
	if err := os.Rename(tempPayload, payloadRoot); err != nil {
		return err
	}
	keyPath := filepath.Join(payloadRoot, "database", "forward.db"+pluginSecretKeyFileSuffix)
	keyExists, err := boundedRegularFileExists(keyPath, pluginSecretKeyringMaxBytes)
	if err != nil {
		return err
	}
	for _, item := range journal.Items {
		if item.Name == "secret_key" && item.Desired != keyExists {
			return fmt.Errorf("restore journal keyring presence does not match the staged archive")
		}
	}
	return nil
}

func preparePluginStateRestoreItem(item *pluginStateRestoreItem) error {
	if item == nil || item.Phase != pluginStateRestoreItemPending {
		return nil
	}
	if err := removePluginStateRestoreCandidate(*item); err != nil {
		return err
	}
	if item.Desired {
		if item.Kind == "file" {
			if err := copyPluginStateRestoreFile(item.Source, item.Candidate, pluginStateBackupMaxFileBytes); err != nil {
				return err
			}
		} else if err := copyPluginStateRestoreDirectory(item.Source, item.Candidate); err != nil {
			return err
		}
	}
	item.Phase = pluginStateRestoreItemPrepared
	return nil
}

func installPluginStateRestoreItem(journalPath string, journal *pluginStateRestoreJournal, index int) error {
	item := &journal.Items[index]
	if item.Phase == pluginStateRestoreItemInstalled {
		return nil
	}
	if item.Phase == pluginStateRestoreItemPrepared {
		targetExists, err := pluginStateRestorePathExists(item.Target, item.Kind)
		if err != nil {
			return err
		}
		backupExists, err := pluginStateRestorePathExists(item.Backup, item.Kind)
		if err != nil {
			return err
		}
		if backupExists {
			return fmt.Errorf("unexpected restore backup already exists")
		}
		item.OriginalKnown = true
		item.HadOriginal = targetExists
		item.Phase = pluginStateRestoreItemBackingUp
		if err := writePluginPackageJSONAtomic(journalPath, *journal, true); err != nil {
			return err
		}
	}
	if item.Phase == pluginStateRestoreItemBackingUp {
		if item.HadOriginal {
			targetExists, err := pluginStateRestorePathExists(item.Target, item.Kind)
			if err != nil {
				return err
			}
			backupExists, err := pluginStateRestorePathExists(item.Backup, item.Kind)
			if err != nil {
				return err
			}
			switch {
			case targetExists && !backupExists:
				if err := os.Rename(item.Target, item.Backup); err != nil {
					return err
				}
			case !targetExists && backupExists:
			case targetExists && backupExists:
				return fmt.Errorf("both target and backup exist while backing up")
			default:
				return fmt.Errorf("both target and backup are missing while backing up")
			}
		} else if exists, err := pluginStateRestorePathExists(item.Target, item.Kind); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("target appeared after restore preparation")
		}
		item.Phase = pluginStateRestoreItemBackedUp
		if err := writePluginPackageJSONAtomic(journalPath, *journal, true); err != nil {
			return err
		}
	}
	if item.Phase == pluginStateRestoreItemBackedUp {
		item.Phase = pluginStateRestoreItemInstalling
		if err := writePluginPackageJSONAtomic(journalPath, *journal, true); err != nil {
			return err
		}
	}
	if item.Phase == pluginStateRestoreItemInstalling {
		if item.Desired {
			candidateExists, err := pluginStateRestorePathExists(item.Candidate, item.Kind)
			if err != nil {
				return err
			}
			targetExists, err := pluginStateRestorePathExists(item.Target, item.Kind)
			if err != nil {
				return err
			}
			switch {
			case candidateExists && !targetExists:
				if err := os.Rename(item.Candidate, item.Target); err != nil {
					return err
				}
			case !candidateExists && targetExists:
			case candidateExists && targetExists:
				return fmt.Errorf("both candidate and target exist while installing")
			default:
				return fmt.Errorf("both candidate and target are missing while installing")
			}
		} else if exists, err := pluginStateRestorePathExists(item.Target, item.Kind); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("target exists for absent restored item")
		}
		item.Phase = pluginStateRestoreItemInstalled
		if err := writePluginPackageJSONAtomic(journalPath, *journal, true); err != nil {
			return err
		}
	}
	return nil
}

func failPluginStateRestore(journalPath string, journal *pluginStateRestoreJournal, cause error) (pluginStateRestoreStartupResult, error) {
	result := pluginStateRestoreStartupResult{ID: journal.ID, Failed: true, Error: cause.Error()}
	if rollbackErr := rollbackPluginStateRestore(*journal); rollbackErr != nil {
		return result, fmt.Errorf("plugin state restore failed: %v; rollback failed: %w", cause, rollbackErr)
	}
	journal.Phase = pluginStateRestorePhaseFailed
	journal.LastError = cause.Error()
	if err := writePluginPackageJSONAtomic(journalPath, *journal, true); err != nil {
		return result, fmt.Errorf("plugin state restore failed: %v; persist failure: %w", cause, err)
	}
	return result, nil
}

func rollbackPluginStateRestore(journal pluginStateRestoreJournal) error {
	var rollbackErrors []string
	for index := len(journal.Items) - 1; index >= 0; index-- {
		item := journal.Items[index]
		backupExists, backupErr := pluginStateRestorePathExists(item.Backup, item.Kind)
		if backupErr != nil {
			rollbackErrors = append(rollbackErrors, item.Name+": "+backupErr.Error())
			continue
		}
		targetExists, targetErr := pluginStateRestorePathExists(item.Target, item.Kind)
		if targetErr != nil {
			rollbackErrors = append(rollbackErrors, item.Name+": "+targetErr.Error())
			continue
		}
		if backupExists {
			if targetExists {
				if err := removePluginStateRestoreTypedPath(item.Target, item.Kind); err != nil {
					rollbackErrors = append(rollbackErrors, item.Name+": "+err.Error())
					continue
				}
			}
			if err := os.Rename(item.Backup, item.Target); err != nil {
				rollbackErrors = append(rollbackErrors, item.Name+": "+err.Error())
			}
			continue
		}
		if item.OriginalKnown && !item.HadOriginal && targetExists && (item.Phase == pluginStateRestoreItemInstalling || item.Phase == pluginStateRestoreItemInstalled) {
			if err := removePluginStateRestoreTypedPath(item.Target, item.Kind); err != nil {
				rollbackErrors = append(rollbackErrors, item.Name+": "+err.Error())
			}
		}
	}
	if len(rollbackErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(rollbackErrors, "; "))
	}
	return nil
}

func cleanupPluginStateRestore(journalPath string, journal pluginStateRestoreJournal) error {
	for _, item := range journal.Items {
		for _, path := range []string{item.Candidate, item.Backup} {
			if err := removePluginStateRestoreTypedPath(path, item.Kind); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	if err := os.RemoveAll(journal.StageRoot); err != nil {
		return err
	}
	return os.Remove(journalPath)
}

func validatePluginStateRestoreTargets(database, pluginsRoot string) error {
	if strings.TrimSpace(database) == "" || strings.TrimSpace(pluginsRoot) == "" {
		return fmt.Errorf("database and plugins paths are required")
	}
	if sameFilePath(database, pluginsRoot) || pathWithinRoot(pluginsRoot, database) || pathWithinRoot(database, pluginsRoot) {
		return fmt.Errorf("database and plugins paths must not overlap")
	}
	for _, parent := range []string{filepath.Dir(database), filepath.Dir(pluginsRoot)} {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("restore target parent %s must be a regular directory", parent)
		}
	}
	for _, target := range []string{database, database + pluginSecretKeyFileSuffix, pluginsRoot, pluginsRoot + pluginPackageStateSuffix} {
		info, err := os.Lstat(target)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("restore target %s must not be a symbolic link", target)
		}
	}
	return nil
}

func validatePluginStateRestoreJournal(journal pluginStateRestoreJournal, database, pluginsRoot string) error {
	if journal.FormatVersion != pluginStateRestoreFormatVersion || !validPluginPackageID(journal.ID) {
		return fmt.Errorf("unsupported or invalid restore journal")
	}
	if _, err := time.Parse(time.RFC3339Nano, journal.CreatedAt); err != nil {
		return fmt.Errorf("invalid restore creation time")
	}
	if !validSHA256Hex(journal.ArchiveSHA256) || !sameFilePath(journal.DatabasePath, database) || !sameFilePath(journal.PluginsRoot, pluginsRoot) {
		return fmt.Errorf("restore journal does not match the requested targets")
	}
	expectedStage := filepath.Join(filepath.Dir(database), pluginStateRestoreStagePrefix+journal.ID)
	if !sameFilePath(journal.StageRoot, expectedStage) {
		return fmt.Errorf("restore staging path is invalid")
	}
	payloadRoot := filepath.Join(expectedStage, "payload")
	expected := newPluginStateRestoreJournal(journal.ID, journal.ArchiveSHA256, database, pluginsRoot, expectedStage, payloadRoot)
	if len(journal.Items) != len(expected.Items) {
		return fmt.Errorf("restore journal item count is invalid")
	}
	for index := range expected.Items {
		actual, want := journal.Items[index], expected.Items[index]
		if actual.Name != want.Name || actual.Kind != want.Kind ||
			!sameFilePath(actual.Source, want.Source) || !sameFilePath(actual.Target, want.Target) ||
			!sameFilePath(actual.Candidate, want.Candidate) || !sameFilePath(actual.Backup, want.Backup) {
			return fmt.Errorf("restore journal item %d is invalid", index)
		}
		if actual.Name != "secret_key" && !actual.Desired {
			return fmt.Errorf("restore journal item %s must be present", actual.Name)
		}
		switch actual.Phase {
		case pluginStateRestoreItemPending, pluginStateRestoreItemPrepared, pluginStateRestoreItemBackingUp,
			pluginStateRestoreItemBackedUp, pluginStateRestoreItemInstalling, pluginStateRestoreItemInstalled:
		default:
			return fmt.Errorf("restore journal item %s has invalid phase", actual.Name)
		}
	}
	switch journal.Phase {
	case pluginStateRestorePhaseStaged, pluginStateRestorePhaseApplying, pluginStateRestorePhaseApplied, pluginStateRestorePhaseFailed:
	default:
		return fmt.Errorf("restore journal phase is invalid")
	}
	return nil
}

func validPluginPackageID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sameFilePath(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func extractPluginStateBackupArchive(archivePath, destination string) (pluginStateBackupManifest, string, error) {
	absArchive, err := filepath.Abs(archivePath)
	if err != nil {
		return pluginStateBackupManifest{}, "", err
	}
	info, err := os.Lstat(absArchive)
	if err != nil {
		return pluginStateBackupManifest{}, "", err
	}
	maxArchiveBytes := pluginStateBackupMaxTotalBytes + pluginStateRestoreArchiveMaxOver
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		return pluginStateBackupManifest{}, "", fmt.Errorf("backup archive must be a bounded regular file")
	}
	digest, err := sha256File(absArchive)
	if err != nil {
		return pluginStateBackupManifest{}, "", err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return pluginStateBackupManifest{}, "", err
	}
	archive, err := os.Open(absArchive) // #nosec G304 -- archive was bounded and checked with Lstat.
	if err != nil {
		return pluginStateBackupManifest{}, "", err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return pluginStateBackupManifest{}, "", err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	header, err := tarReader.Next()
	if err != nil {
		return pluginStateBackupManifest{}, "", fmt.Errorf("read backup manifest: %w", err)
	}
	if header.Name != pluginStateBackupManifestPath || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > pluginStateRestoreManifestMax {
		return pluginStateBackupManifest{}, "", fmt.Errorf("backup manifest must be the first bounded regular entry")
	}
	manifestData, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
	if err != nil || int64(len(manifestData)) != header.Size {
		return pluginStateBackupManifest{}, "", fmt.Errorf("read backup manifest: %w", firstError(err, io.ErrUnexpectedEOF))
	}
	var manifest pluginStateBackupManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestData)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return pluginStateBackupManifest{}, "", fmt.Errorf("decode backup manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return pluginStateBackupManifest{}, "", fmt.Errorf("backup manifest contains trailing JSON")
	}
	files, err := validatePluginStateBackupManifest(manifest)
	if err != nil {
		return pluginStateBackupManifest{}, "", err
	}
	seen := make(map[string]struct{}, len(files))
	for {
		header, err = tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return pluginStateBackupManifest{}, "", err
		}
		name, err := normalizePluginPackageEntryName(header.Name)
		if err != nil || name == "" || name != header.Name || header.Typeflag != tar.TypeReg {
			return pluginStateBackupManifest{}, "", fmt.Errorf("backup contains invalid entry %q", header.Name)
		}
		expected, ok := files[name]
		if !ok {
			return pluginStateBackupManifest{}, "", fmt.Errorf("backup contains unlisted entry %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return pluginStateBackupManifest{}, "", fmt.Errorf("backup contains duplicate entry %q", name)
		}
		if header.Size != expected.Bytes {
			return pluginStateBackupManifest{}, "", fmt.Errorf("backup entry %q has unexpected size", name)
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if !pathWithinRoot(destination, target) {
			return pluginStateBackupManifest{}, "", fmt.Errorf("backup entry escapes extraction root")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return pluginStateBackupManifest{}, "", err
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- target is constrained below the private extraction root.
		if err != nil {
			return pluginStateBackupManifest{}, "", err
		}
		hash := sha256.New()
		written, copyErr := io.CopyN(io.MultiWriter(file, hash), tarReader, header.Size)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || written != header.Size || syncErr != nil || closeErr != nil {
			return pluginStateBackupManifest{}, "", firstError(copyErr, syncErr, closeErr, io.ErrUnexpectedEOF)
		}
		if hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return pluginStateBackupManifest{}, "", fmt.Errorf("backup entry %q failed SHA256 validation", name)
		}
		seen[name] = struct{}{}
	}
	if len(seen) != len(files) {
		return pluginStateBackupManifest{}, "", fmt.Errorf("backup is missing %d manifest entries", len(files)-len(seen))
	}
	for _, dir := range []string{"plugins", "state"} {
		if err := os.MkdirAll(filepath.Join(destination, dir), 0o700); err != nil {
			return pluginStateBackupManifest{}, "", err
		}
	}
	return manifest, digest, nil
}

func validatePluginStateBackupManifest(manifest pluginStateBackupManifest) (map[string]pluginStateBackupFile, error) {
	if manifest.FormatVersion != pluginStateBackupFormatVersion || strings.TrimSpace(manifest.RuntimeVersion) == "" {
		return nil, fmt.Errorf("unsupported or invalid plugin state backup manifest")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return nil, fmt.Errorf("backup creation time is invalid")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > pluginStateBackupMaxEntries {
		return nil, fmt.Errorf("backup manifest file count is invalid")
	}
	files := make(map[string]pluginStateBackupFile, len(manifest.Files))
	var total int64
	for _, file := range manifest.Files {
		name, err := normalizePluginPackageEntryName(file.Path)
		if err != nil || name == "" || name != file.Path || !validPluginStateBackupPath(name) {
			return nil, fmt.Errorf("backup manifest path %q is invalid", file.Path)
		}
		if _, duplicate := files[name]; duplicate {
			return nil, fmt.Errorf("backup manifest path %q is duplicated", name)
		}
		if file.Bytes < 0 || file.Bytes > pluginStateBackupMaxFileBytes || !validSHA256Hex(file.SHA256) {
			return nil, fmt.Errorf("backup manifest metadata for %q is invalid", name)
		}
		if total > pluginStateBackupMaxTotalBytes-file.Bytes {
			return nil, fmt.Errorf("backup manifest exceeds %d bytes", pluginStateBackupMaxTotalBytes)
		}
		total += file.Bytes
		files[name] = file
	}
	if _, ok := files["database/forward.db"]; !ok {
		return nil, fmt.Errorf("backup manifest does not contain database/forward.db")
	}
	return files, nil
}

func validPluginStateBackupPath(name string) bool {
	if name == "database/forward.db" || name == "database/forward.db"+pluginSecretKeyFileSuffix {
		return true
	}
	return strings.HasPrefix(name, "plugins/") || strings.HasPrefix(name, "state/")
}

func validatePluginStateRestorePayload(payloadRoot string) error {
	databasePath := filepath.Join(payloadRoot, "database", "forward.db")
	if err := validatePluginStateSQLite(databasePath); err != nil {
		return err
	}
	keyPath := databasePath + pluginSecretKeyFileSuffix
	keyExists, err := boundedRegularFileExists(keyPath, pluginSecretKeyringMaxBytes)
	if err != nil {
		return err
	}
	if keyExists {
		if _, err := loadOrCreatePluginSecretKeyring(keyPath); err != nil {
			return err
		}
	}
	return validatePluginStateSecretEnvelopes(databasePath, keyExists)
}

func validatePluginStateSQLite(databasePath string) error {
	absPath, err := filepath.Abs(databasePath)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", absPath)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA query_only = ON`); err != nil {
		return fmt.Errorf("enable SQLite query-only validation: %w", err)
	}
	var result string
	if err := db.QueryRow(`PRAGMA quick_check(1)`).Scan(&result); err != nil {
		return fmt.Errorf("SQLite quick_check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("SQLite quick_check: %s", result)
	}
	for _, table := range []string{"rules", "plugin_records", "plugin_states"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("SQLite backup is missing required table %s", table)
		}
	}
	return nil
}

func validatePluginStateSecretEnvelopes(databasePath string, keyExists bool) error {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	var encryptedRecords int
	if err := db.QueryRow(`SELECT COUNT(*) FROM plugin_records WHERE instr(data_json, ?) > 0`, pluginSecretEnvelopeField).Scan(&encryptedRecords); err != nil {
		return err
	}
	operations, err := storepkg.GetAllPluginOperations(db)
	if err != nil {
		return err
	}
	if !keyExists && (encryptedRecords > 0 || len(operations) > 0) {
		return fmt.Errorf("plugin state contains encrypted secrets or operations but the keyring is missing")
	}
	if !keyExists {
		return nil
	}
	secretStore, err := newPluginSecretStore(db)
	if err != nil {
		return err
	}
	records, err := storepkg.GetAllPluginRecords(db)
	if err != nil {
		return err
	}
	for _, record := range records {
		if !strings.Contains(record.DataJSON, pluginSecretEnvelopeField) {
			continue
		}
		if _, _, err := secretStore.reencryptDiscoveredEnvelopes(record); err != nil {
			return fmt.Errorf("validate encrypted plugin record %s/%s/%s: %w", record.PluginID, record.ResourceID, record.RecordKey, err)
		}
	}
	for _, operation := range operations {
		for field, value := range map[string]string{
			"input": operation.InputJSON, "state": operation.StateJSON,
			"result": operation.ResultJSON, "error": operation.ErrorJSON,
		} {
			if _, err := decryptPluginOperationPayload(secretStore, operation, field, value); err != nil {
				return fmt.Errorf("validate encrypted plugin operation %s/%s field %s: %w", operation.PluginID, operation.OperationID, field, err)
			}
		}
	}
	return nil
}

func validatePluginStateRestoreTargetsInstalled(journal pluginStateRestoreJournal) error {
	payloadAvailable := false
	if err := validatePluginStateRestorePayload(filepath.Join(journal.StageRoot, "payload")); err == nil {
		// The staged payload remains the immutable reference until cleanup.
		payloadAvailable = true
	} else if journal.Phase != pluginStateRestorePhaseApplied {
		return err
	}
	if payloadAvailable {
		for _, item := range journal.Items {
			if err := validatePluginStateRestoreInstalledItem(item); err != nil {
				return fmt.Errorf("restored %s differs from staged backup: %w", item.Name, err)
			}
		}
	}
	if err := validatePluginStateSQLite(journal.DatabasePath); err != nil {
		return err
	}
	keyExists, err := boundedRegularFileExists(journal.DatabasePath+pluginSecretKeyFileSuffix, pluginSecretKeyringMaxBytes)
	if err != nil {
		return err
	}
	if keyExists {
		if _, err := loadOrCreatePluginSecretKeyring(journal.DatabasePath + pluginSecretKeyFileSuffix); err != nil {
			return err
		}
	}
	return validatePluginStateSecretEnvelopes(journal.DatabasePath, keyExists)
}

func validatePluginStateRestoreInstalledItem(item pluginStateRestoreItem) error {
	if !item.Desired {
		if exists, err := pluginStateRestorePathExists(item.Target, item.Kind); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("target should be absent")
		}
		return nil
	}
	if item.Kind == "file" {
		for _, path := range []string{item.Source, item.Target} {
			if exists, err := pluginStateRestorePathExists(path, "file"); err != nil {
				return err
			} else if !exists {
				return fmt.Errorf("file is missing")
			}
		}
		sourceDigest, err := sha256File(item.Source)
		if err != nil {
			return err
		}
		targetDigest, err := sha256File(item.Target)
		if err != nil {
			return err
		}
		if sourceDigest != targetDigest {
			return fmt.Errorf("file SHA256 mismatch")
		}
		return nil
	}
	sourceDigest, err := pluginStateRestoreDirectoryDigest(item.Source)
	if err != nil {
		return err
	}
	targetDigest, err := pluginStateRestoreDirectoryDigest(item.Target)
	if err != nil {
		return err
	}
	if sourceDigest != targetDigest {
		return fmt.Errorf("directory content digest mismatch")
	}
	return nil
}

func pluginStateRestoreDirectoryDigest(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("path must be a regular directory")
	}
	type entryDigest struct {
		path   string
		size   int64
		digest string
	}
	entries := make([]entryDigest, 0)
	var total int64
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("directory contains a symbolic link")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			entries = append(entries, entryDigest{path: rel + "/", size: -1})
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > pluginStateBackupMaxFileBytes || total > pluginStateBackupMaxTotalBytes-info.Size() {
			return fmt.Errorf("directory contains an invalid file")
		}
		total += info.Size()
		digest, err := sha256File(path)
		if err != nil {
			return err
		}
		entries = append(entries, entryDigest{path: rel, size: info.Size(), digest: digest})
		if len(entries) > pluginStateBackupMaxEntries*2 {
			return fmt.Errorf("directory contains too many entries")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	hash := sha256.New()
	for _, entry := range entries {
		fmt.Fprintf(hash, "%s\x00%d\x00%s\n", entry.path, entry.size, entry.digest)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyPluginStateRestoreFile(source, destination string, maxBytes int64) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	return copyPluginStateBackupFile(source, destination, maxBytes)
}

func copyPluginStateRestoreDirectory(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restore source must be a regular directory")
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	entries := 0
	var total int64
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		entries++
		if entries > pluginStateBackupMaxEntries {
			return fmt.Errorf("restore directory contains too many entries")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("restore directory contains a symbolic link")
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if !pathWithinRoot(destination, target) {
			return fmt.Errorf("restore path escapes destination")
		}
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		if !info.Mode().IsRegular() || info.Size() > pluginStateBackupMaxFileBytes || total > pluginStateBackupMaxTotalBytes-info.Size() {
			return fmt.Errorf("restore source contains an invalid file")
		}
		total += info.Size()
		return copyPluginStateRestoreFile(path, target, pluginStateBackupMaxFileBytes)
	})
}

func pluginStateRestorePathExists(path, kind string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || (kind == "file" && !info.Mode().IsRegular()) || (kind == "directory" && !info.IsDir()) {
		return false, fmt.Errorf("restore path %s has an unexpected type", path)
	}
	return true, nil
}

func removePluginStateRestoreCandidate(item pluginStateRestoreItem) error {
	exists, err := pluginStateRestorePathExists(item.Candidate, item.Kind)
	if err != nil || !exists {
		return err
	}
	return removePluginStateRestoreTypedPath(item.Candidate, item.Kind)
}

func removePluginStateRestoreTypedPath(path, kind string) error {
	exists, err := pluginStateRestorePathExists(path, kind)
	if err != nil || !exists {
		return err
	}
	if kind == "directory" {
		return os.RemoveAll(path)
	}
	return os.Remove(path)
}

func firstError(values ...error) error {
	for _, err := range values {
		if err != nil {
			return err
		}
	}
	return nil
}
