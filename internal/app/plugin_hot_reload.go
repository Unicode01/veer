package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const pluginHotReloadContentHashMaxBytes = pluginObjectMaxSize

const (
	pluginCatalogHotReloadResultSuccess   = "success"
	pluginCatalogHotReloadResultError     = "error"
	pluginCatalogHotReloadResultPartial   = "partial"
	pluginCatalogHotReloadResultUnchanged = "unchanged"
	pluginCatalogHotReloadResultPending   = "update_available"

	pluginCatalogHotReloadSourceManual = "manual"

	pluginCatalogSnapshotAttempts = 3
	pluginCatalogSnapshotPrefix   = "veer-plugin-catalog-"

	pluginCatalogUpdateAdded    = "added"
	pluginCatalogUpdateModified = "modified"
	pluginCatalogUpdateRemoved  = "removed"
)

func buildPluginCatalogFingerprint(cfg *Config) (string, error) {
	if cfg != nil && !cfg.PluginsEnabled() {
		return "plugins-disabled", nil
	}
	root := normalizePluginsDir("")
	if cfg != nil {
		root = normalizePluginsDir(cfg.PluginsDir)
	}
	return buildPluginDirectoryFingerprint(root)
}

func buildPluginDirectoryFingerprint(root string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "plugins-dir-error:" + root + ":" + err.Error(), err
	}

	h := sha256.New()
	fmt.Fprintln(h, "root=.")

	info, err := os.Lstat(absRoot)
	if os.IsNotExist(err) {
		fmt.Fprintln(h, "missing")
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	if err != nil {
		fmt.Fprintf(h, "root-error=%v\n", err)
		return hex.EncodeToString(h.Sum(nil)), err
	}
	if !info.IsDir() {
		err := fmt.Errorf("plugins_dir %q is not a directory", root)
		fmt.Fprintf(h, "not-dir mode=%s size=%d mtime=%d\n", info.Mode().String(), info.Size(), info.ModTime().UnixNano())
		return hex.EncodeToString(h.Sum(nil)), err
	}

	var firstErr error
	err = filepath.WalkDir(absRoot, func(path string, entry os.DirEntry, walkErr error) error {
		rel := "."
		if path != absRoot {
			if value, relErr := filepath.Rel(absRoot, path); relErr == nil {
				rel = filepath.ToSlash(value)
			} else {
				rel = filepath.ToSlash(path)
				if firstErr == nil {
					firstErr = relErr
				}
			}
		}
		if walkErr != nil {
			fmt.Fprintf(h, "walk-error path=%s err=%v\n", rel, walkErr)
			if firstErr == nil {
				firstErr = walkErr
			}
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry == nil {
			return nil
		}
		if rel == "." {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			fmt.Fprintf(h, "info-error path=%s err=%v\n", rel, infoErr)
			if firstErr == nil {
				firstErr = infoErr
			}
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		mode := info.Mode()
		switch {
		case entry.IsDir():
			fmt.Fprintf(h, "path=%s mode=%s type=dir\n", rel, mode.String())
		case mode&os.ModeSymlink != 0:
			fmt.Fprintf(h, "path=%s mode=%s type=symlink\n", rel, mode.String())
			target, linkErr := os.Readlink(path)
			if linkErr != nil {
				fmt.Fprintf(h, "symlink-error path=%s err=%v\n", rel, linkErr)
				if firstErr == nil {
					firstErr = linkErr
				}
			} else {
				fmt.Fprintf(h, "symlink-target path=%s target=%s\n", rel, target)
			}
		case mode.IsRegular():
			fmt.Fprintf(h, "path=%s mode=%s size=%d type=file\n", rel, mode.String(), info.Size())
			if info.Size() > pluginHotReloadContentHashMaxBytes {
				fmt.Fprintf(h, "content-skip path=%s reason=size>%d mtime=%d\n", rel, pluginHotReloadContentHashMaxBytes, info.ModTime().UnixNano())
			} else {
				sum, hashErr := sha256File(path)
				if hashErr != nil {
					fmt.Fprintf(h, "content-error path=%s err=%v\n", rel, hashErr)
					if firstErr == nil {
						firstErr = hashErr
					}
				} else {
					fmt.Fprintf(h, "content-sha256 path=%s sha256=%s\n", rel, sum)
				}
			}
		default:
			fmt.Fprintf(h, "path=%s mode=%s size=%d mtime=%d type=other\n", rel, mode.String(), info.Size(), info.ModTime().UnixNano())
		}
		return nil
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return hex.EncodeToString(h.Sum(nil)), firstErr
}

func snapshotPluginCatalogDirectory(cfg *Config) (string, string, error) {
	var lastErr error
	for attempt := 0; attempt < pluginCatalogSnapshotAttempts; attempt++ {
		before, err := buildPluginCatalogFingerprint(cfg)
		if err != nil {
			return "", before, err
		}
		dir, err := os.MkdirTemp("", pluginCatalogSnapshotPrefix)
		if err != nil {
			return "", before, fmt.Errorf("create plugin catalog snapshot: %w", err)
		}
		if cfg == nil || cfg.PluginsEnabled() {
			root := normalizePluginsDir("")
			if cfg != nil {
				root = normalizePluginsDir(cfg.PluginsDir)
			}
			if err := copyPluginCatalogDirectory(root, dir); err != nil {
				_ = removePluginCatalogSnapshot(dir)
				return "", before, err
			}
		}
		after, err := buildPluginCatalogFingerprint(cfg)
		if err != nil {
			_ = removePluginCatalogSnapshot(dir)
			return "", after, err
		}
		if before == after {
			return dir, after, nil
		}
		_ = removePluginCatalogSnapshot(dir)
		lastErr = fmt.Errorf("plugin directory changed while creating snapshot")
	}
	return "", "", lastErr
}

func copyPluginCatalogDirectory(root string, destination string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve plugin source directory: %w", err)
	}
	info, err := os.Lstat(absRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect plugin source directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("plugins_dir %q is not a directory", root)
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return fmt.Errorf("resolve plugin source directory: %w", err)
	}
	return filepath.WalkDir(realRoot, func(sourcePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(realRoot, sourcePath)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(destination, rel)
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		mode := entryInfo.Mode()
		switch {
		case entry.IsDir():
			if rel == "." {
				return nil
			}
			if err := os.MkdirAll(targetPath, 0o700); err != nil {
				return err
			}
			return os.Chmod(targetPath, mode.Perm())
		case mode&os.ModeSymlink != 0:
			realTarget, err := filepath.EvalSymlinks(sourcePath)
			if err != nil {
				return fmt.Errorf("resolve plugin symlink %s: %w", rel, err)
			}
			if !pathWithinRoot(realRoot, realTarget) {
				return fmt.Errorf("plugin symlink %s escapes plugin root", rel)
			}
			targetRel, err := filepath.Rel(realRoot, realTarget)
			if err != nil {
				return err
			}
			stagedTarget := filepath.Join(destination, targetRel)
			linkTarget, err := filepath.Rel(filepath.Dir(targetPath), stagedTarget)
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, targetPath)
		case mode.IsRegular():
			return copyPluginCatalogFile(sourcePath, targetPath, mode.Perm())
		default:
			return fmt.Errorf("plugin path %s has unsupported mode %s", rel, mode)
		}
	})
}

func copyPluginCatalogFile(sourcePath string, targetPath string, mode os.FileMode) error {
	source, err := os.Open(sourcePath) // #nosec G304 -- sourcePath comes from a bounded plugins_dir walk.
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- targetPath is inside a private snapshot directory.
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Chmod(targetPath, mode); err != nil {
		return err
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	return os.Chtimes(targetPath, info.ModTime(), info.ModTime())
}

func removePluginCatalogSnapshot(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" || !strings.HasPrefix(filepath.Base(dir), pluginCatalogSnapshotPrefix) {
		return nil
	}
	absTemp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if !pathWithinRoot(absTemp, absDir) || absDir == absTemp {
		return fmt.Errorf("refuse to remove plugin snapshot outside temporary directory")
	}
	return os.RemoveAll(absDir)
}

func pluginCatalogConfigForDir(cfg *Config, dir string) *Config {
	if cfg == nil {
		cfg = &Config{}
	}
	out := *cfg
	out.PluginsDir = dir
	return &out
}

func pluginCatalogUpdatesBetweenDirs(appliedDir, detectedDir string) []PluginCatalogUpdate {
	applied := externalPluginsBySourceInDir(appliedDir)
	detected := externalPluginsBySourceInDir(detectedDir)
	pairedApplied := make(map[string]struct{}, len(applied))
	pairedDetected := make(map[string]struct{}, len(detected))
	updates := make([]PluginCatalogUpdate, 0, len(applied)+len(detected))

	for source, current := range applied {
		candidate, ok := detected[source]
		if !ok {
			continue
		}
		pairedApplied[source] = struct{}{}
		pairedDetected[source] = struct{}{}
		if current.sourceFingerprint == candidate.sourceFingerprint {
			continue
		}
		updates = append(updates, newPluginCatalogUpdate(&current, &candidate))
	}

	detectedByID := make(map[string]LoadedPlugin, len(detected))
	for source, plugin := range detected {
		if _, paired := pairedDetected[source]; paired {
			continue
		}
		if _, duplicate := detectedByID[plugin.ID]; !duplicate {
			detectedByID[plugin.ID] = plugin
		}
	}
	for source, current := range applied {
		if _, paired := pairedApplied[source]; paired {
			continue
		}
		candidate, ok := detectedByID[current.ID]
		if !ok {
			continue
		}
		pairedApplied[source] = struct{}{}
		pairedDetected[candidate.Source] = struct{}{}
		updates = append(updates, newPluginCatalogUpdate(&current, &candidate))
	}

	for source, current := range applied {
		if _, paired := pairedApplied[source]; paired {
			continue
		}
		updates = append(updates, newPluginCatalogUpdate(&current, nil))
	}
	for source, candidate := range detected {
		if _, paired := pairedDetected[source]; paired {
			continue
		}
		updates = append(updates, newPluginCatalogUpdate(nil, &candidate))
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].PluginID < updates[j].PluginID })
	return updates
}

func newPluginCatalogUpdate(current, candidate *LoadedPlugin) PluginCatalogUpdate {
	update := PluginCatalogUpdate{}
	if current != nil {
		update.PluginID = current.ID
		update.Source = current.Source
		update.Name = current.Name
		update.Kind = current.Kind
		update.AppliedVersion = current.Version
		update.appliedSource = current.Source
	}
	if candidate != nil {
		if update.PluginID == "" {
			update.PluginID = candidate.ID
		}
		update.Source = candidate.Source
		update.Name = candidate.Name
		update.Kind = candidate.Kind
		update.DetectedVersion = candidate.Version
		update.detectedSource = candidate.Source
	}
	switch {
	case current == nil:
		update.Change = pluginCatalogUpdateAdded
	case candidate == nil:
		update.Change = pluginCatalogUpdateRemoved
	default:
		update.Change = pluginCatalogUpdateModified
	}
	return update
}

func externalPluginsBySourceInDir(dir string) map[string]LoadedPlugin {
	if strings.TrimSpace(dir) == "" {
		return map[string]LoadedPlugin{}
	}
	plugins := make(map[string]LoadedPlugin)
	for _, plugin := range loadPluginCatalog(&Config{PluginsDir: dir}).Plugins {
		if plugin.Builtin || strings.TrimSpace(plugin.Source) == "" {
			continue
		}
		plugins[plugin.Source] = plugin
	}
	return plugins
}

func clonePluginCatalogUpdates(updates []PluginCatalogUpdate) []PluginCatalogUpdate {
	if len(updates) == 0 {
		return nil
	}
	return append([]PluginCatalogUpdate(nil), updates...)
}

func normalizePluginCatalogUpdateSelection(pluginIDs []string, updates []PluginCatalogUpdate) ([]string, error) {
	available := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		available[update.PluginID] = struct{}{}
	}
	selected := make([]string, 0, len(pluginIDs))
	seen := make(map[string]struct{}, len(pluginIDs))
	for _, raw := range pluginIDs {
		id := strings.TrimSpace(strings.ToLower(raw))
		if !pluginIDPattern.MatchString(id) || reservedBuiltinPluginID(id) {
			return nil, fmt.Errorf("invalid plugin update id %q", raw)
		}
		if _, ok := available[id]; !ok {
			return nil, fmt.Errorf("plugin %q has no pending update", id)
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		selected = append(selected, id)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("select at least one pending plugin update")
	}
	sort.Strings(selected)
	return selected, nil
}

func pluginCatalogDirectChild(root, source string) (string, error) {
	source = strings.TrimSpace(source)
	if source == "" || source == "." || filepath.Base(source) != source {
		return "", fmt.Errorf("invalid plugin source %q", source)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(absRoot, source)
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if filepath.Dir(absPath) != absRoot || !pathWithinRoot(absRoot, absPath) {
		return "", fmt.Errorf("plugin source %q escapes catalog root", source)
	}
	return absPath, nil
}

func mergeSelectedPluginCatalogUpdates(appliedDir, detectedDir string, updates []PluginCatalogUpdate, selected []string) (string, string, error) {
	if strings.TrimSpace(appliedDir) == "" {
		return "", "", fmt.Errorf("applied plugin catalog snapshot is unavailable; select all pending updates")
	}
	mergedDir, _, err := snapshotPluginCatalogDirectory(&Config{PluginsDir: appliedDir})
	if err != nil {
		return "", "", fmt.Errorf("snapshot applied plugin catalog: %w", err)
	}
	fail := func(err error) (string, string, error) {
		_ = removePluginCatalogSnapshot(mergedDir)
		return "", "", err
	}

	updateByID := make(map[string]PluginCatalogUpdate, len(updates))
	for _, update := range updates {
		updateByID[update.PluginID] = update
	}
	for _, id := range selected {
		update, ok := updateByID[id]
		if !ok {
			return fail(fmt.Errorf("plugin %q has no pending update", id))
		}
		if update.appliedSource != "" {
			target, pathErr := pluginCatalogDirectChild(mergedDir, update.appliedSource)
			if pathErr != nil {
				return fail(pathErr)
			}
			if removeErr := os.RemoveAll(target); removeErr != nil {
				return fail(fmt.Errorf("remove applied plugin %s: %w", id, removeErr))
			}
		}
		if update.detectedSource == "" {
			continue
		}
		source, pathErr := pluginCatalogDirectChild(detectedDir, update.detectedSource)
		if pathErr != nil {
			return fail(pathErr)
		}
		target, pathErr := pluginCatalogDirectChild(mergedDir, update.detectedSource)
		if pathErr != nil {
			return fail(pathErr)
		}
		if removeErr := os.RemoveAll(target); removeErr != nil {
			return fail(fmt.Errorf("replace plugin %s: %w", id, removeErr))
		}
		if mkdirErr := os.MkdirAll(target, 0o700); mkdirErr != nil {
			return fail(fmt.Errorf("prepare plugin %s: %w", id, mkdirErr))
		}
		if copyErr := copyPluginCatalogDirectory(source, target); copyErr != nil {
			return fail(fmt.Errorf("copy plugin %s: %w", id, copyErr))
		}
	}
	fingerprint, err := buildPluginDirectoryFingerprint(mergedDir)
	if err != nil {
		return fail(fmt.Errorf("fingerprint merged plugin catalog: %w", err))
	}
	return mergedDir, fingerprint, nil
}

func (pm *ProcessManager) initializePluginCatalogSnapshot() {
	if pm == nil {
		return
	}
	sourceDir := normalizePluginsDir("")
	if pm.cfg != nil {
		sourceDir = normalizePluginsDir(pm.cfg.PluginsDir)
	}
	dir, fingerprint, err := snapshotPluginCatalogDirectory(pm.cfg)
	now := time.Now()
	pm.mu.Lock()
	pm.pluginCatalogSourceDir = sourceDir
	pm.pluginCatalogAppliedDir = dir
	pm.pluginCatalogAppliedFingerprint = fingerprint
	pm.pluginCatalogDetectedFingerprint = fingerprint
	pm.pluginCatalogPendingUpdates = nil
	pm.pluginCatalogCheckAt = now
	pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultSuccess
	pm.pluginCatalogLastCheckError = ""
	if err != nil {
		pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultError
		pm.pluginCatalogLastCheckError = err.Error()
	}
	pm.mu.Unlock()
	if err != nil {
		log.Printf("plugin update monitor: initialize applied snapshot failed; using source directory directly: %v", err)
	}
}

func (pm *ProcessManager) cleanupPluginCatalogSnapshot() {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	dir := pm.pluginCatalogAppliedDir
	pm.pluginCatalogAppliedDir = ""
	pm.mu.Unlock()
	if err := removePluginCatalogSnapshot(dir); err != nil {
		log.Printf("plugin update monitor: clean applied snapshot: %v", err)
	}
}

func (pm *ProcessManager) appliedPluginCatalogConfig(fallback *Config) (*Config, string) {
	base := fallback
	if pm != nil && pm.cfg != nil {
		base = pm.cfg
	}
	if base == nil {
		base = &Config{}
	}
	out := *base
	sourceDir := normalizePluginsDir(out.PluginsDir)
	if pm != nil {
		pm.mu.Lock()
		if pm.pluginCatalogSourceDir != "" {
			sourceDir = pm.pluginCatalogSourceDir
		}
		if pm.pluginCatalogAppliedDir != "" {
			out.PluginsDir = pm.pluginCatalogAppliedDir
		}
		pm.mu.Unlock()
	}
	return &out, sourceDir
}

func pluginCatalogConfigForProcess(pm *ProcessManager, fallback *Config) *Config {
	if pm == nil {
		return fallback
	}
	cfg, _ := pm.appliedPluginCatalogConfig(fallback)
	return cfg
}

func (pm *ProcessManager) shouldCheckPluginCatalogDriftLocked(now time.Time) bool {
	if pm == nil || pm.cfg == nil || !pm.cfg.PluginsEnabled() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return pm.pluginCatalogCheckAt.IsZero() || now.Sub(pm.pluginCatalogCheckAt) >= pluginCatalogDriftCheckEvery
}

func (pm *ProcessManager) detectPluginCatalogDrift() bool {
	if pm == nil {
		return false
	}
	pm.pluginCatalogUpdateMu.Lock()
	defer pm.pluginCatalogUpdateMu.Unlock()
	next, err := buildPluginCatalogFingerprint(pm.cfg)
	now := time.Now()
	checkResult := pluginCatalogHotReloadResultSuccess
	checkError := ""
	if err != nil {
		checkResult = pluginCatalogHotReloadResultError
		checkError = err.Error()
	}
	pm.mu.Lock()
	applied := strings.TrimSpace(pm.pluginCatalogAppliedFingerprint)
	appliedDir := pm.pluginCatalogAppliedDir
	sourceDir := pm.pluginCatalogSourceDir
	previousDetected := strings.TrimSpace(pm.pluginCatalogDetectedFingerprint)
	previousUpdates := clonePluginCatalogUpdates(pm.pluginCatalogPendingUpdates)
	pm.mu.Unlock()
	if applied == "" {
		pm.mu.Lock()
		pm.pluginCatalogAppliedFingerprint = next
		pm.pluginCatalogDetectedFingerprint = next
		pm.pluginCatalogPendingUpdates = nil
		pm.pluginCatalogCheckAt = now
		pm.pluginCatalogLastCheckResult = checkResult
		pm.pluginCatalogLastCheckError = checkError
		pm.mu.Unlock()
		if err != nil {
			log.Printf("plugin update monitor: catalog fingerprint scan issue: %v", err)
		}
		return false
	}
	updates := previousUpdates
	if err == nil {
		updates = nil
		if next != applied && appliedDir != "" && sourceDir != "" {
			updates = pluginCatalogUpdatesBetweenDirs(appliedDir, sourceDir)
		}
	}
	updateAvailable := len(updates) > 0
	if updateAvailable && err == nil {
		checkResult = pluginCatalogHotReloadResultPending
	} else if !updateAvailable && err == nil {
		checkResult = pluginCatalogHotReloadResultUnchanged
	}
	pm.mu.Lock()
	pm.pluginCatalogDetectedFingerprint = next
	pm.pluginCatalogPendingUpdates = clonePluginCatalogUpdates(updates)
	pm.pluginCatalogCheckAt = now
	pm.pluginCatalogLastCheckResult = checkResult
	pm.pluginCatalogLastCheckError = checkError
	shuttingDown := pm.shuttingDown
	pm.mu.Unlock()

	if err != nil {
		log.Printf("plugin update monitor: catalog fingerprint scan issue: %v", err)
	}
	if shuttingDown || !updateAvailable {
		return false
	}
	if next != previousDetected {
		log.Printf("plugin update monitor: plugin catalog update detected; waiting for manual apply")
	}
	return true
}

func (pm *ProcessManager) applyPluginCatalogUpdate() error {
	return pm.applyPluginCatalogUpdateSelection(nil)
}

func (pm *ProcessManager) applyPluginCatalogUpdateSelection(pluginIDs []string) error {
	if pm == nil {
		return fmt.Errorf("process manager is unavailable")
	}
	pm.pluginCatalogUpdateMu.Lock()
	defer pm.pluginCatalogUpdateMu.Unlock()

	detectedDir, detectedFingerprint, err := snapshotPluginCatalogDirectory(pm.cfg)
	pm.mu.Lock()
	previousDir := pm.pluginCatalogAppliedDir
	previousFingerprint := pm.pluginCatalogAppliedFingerprint
	pm.pluginCatalogDetectedFingerprint = detectedFingerprint
	pm.pluginCatalogCheckAt = time.Now()
	if err != nil {
		pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultError
		pm.pluginCatalogLastCheckError = err.Error()
	} else {
		pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultSuccess
		pm.pluginCatalogLastCheckError = ""
	}
	pm.mu.Unlock()
	if err != nil {
		pm.markPluginCatalogReloadCompleted(pluginCatalogHotReloadSourceManual, err)
		return err
	}

	updates := pluginCatalogUpdatesBetweenDirs(previousDir, detectedDir)
	pm.mu.Lock()
	pm.pluginCatalogPendingUpdates = clonePluginCatalogUpdates(updates)
	pm.mu.Unlock()

	selected := pluginIDs
	if pluginIDs != nil {
		selected, err = normalizePluginCatalogUpdateSelection(pluginIDs, updates)
		if err != nil {
			_ = removePluginCatalogSnapshot(detectedDir)
			pm.markPluginCatalogReloadCompleted(pluginCatalogHotReloadSourceManual, err)
			return err
		}
	}

	candidateDir := detectedDir
	candidateFingerprint := detectedFingerprint
	if pluginIDs != nil && len(selected) < len(updates) {
		candidateDir, candidateFingerprint, err = mergeSelectedPluginCatalogUpdates(previousDir, detectedDir, updates, selected)
		if err != nil {
			_ = removePluginCatalogSnapshot(detectedDir)
			pm.markPluginCatalogReloadCompleted(pluginCatalogHotReloadSourceManual, err)
			return err
		}
	}
	cleanupCandidates := func() {
		if candidateDir != detectedDir {
			_ = removePluginCatalogSnapshot(candidateDir)
		}
		_ = removePluginCatalogSnapshot(detectedDir)
	}

	candidateCfg := pluginCatalogConfigForDir(pm.cfg, candidateDir)
	validationCatalog := loadPluginCatalogWithControlRegistrationAndState(candidateCfg, pm.db)
	if err := pluginCatalogValidationError(validationCatalog); err != nil {
		cleanupCandidates()
		pm.markPluginCatalogReloadCompleted(pluginCatalogHotReloadSourceManual, err)
		return err
	}

	pm.mu.Lock()
	pm.pluginCatalogAppliedDir = candidateDir
	pm.pluginCatalogAppliedFingerprint = candidateFingerprint
	pm.mu.Unlock()

	_, applyErr := pm.reconcilePluginsForRuntimeWithError()
	if applyErr != nil {
		pm.mu.Lock()
		pm.pluginCatalogAppliedDir = previousDir
		pm.pluginCatalogAppliedFingerprint = previousFingerprint
		pm.mu.Unlock()
		_, rollbackErr := pm.reconcilePluginsForRuntimeWithError()
		if rollbackErr != nil {
			applyErr = fmt.Errorf("%v; rollback previous plugin catalog: %w", applyErr, rollbackErr)
		}
		cleanupCandidates()
		pm.markPluginCatalogReloadCompleted(pluginCatalogHotReloadSourceManual, applyErr)
		pm.requestRedistributeWorkers(0)
		return applyErr
	}

	if err := removePluginCatalogSnapshot(previousDir); err != nil {
		log.Printf("plugin update monitor: clean previous applied snapshot: %v", err)
	}
	remaining := pluginCatalogUpdatesBetweenDirs(candidateDir, detectedDir)
	pm.mu.Lock()
	pm.pluginCatalogDetectedFingerprint = detectedFingerprint
	pm.pluginCatalogPendingUpdates = clonePluginCatalogUpdates(remaining)
	if len(remaining) > 0 {
		pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultPending
	} else {
		pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultSuccess
	}
	pm.mu.Unlock()
	if candidateDir != detectedDir {
		_ = removePluginCatalogSnapshot(detectedDir)
	}
	pm.markPluginCatalogReloadCompleted(pluginCatalogHotReloadSourceManual, nil)
	pm.requestRedistributeWorkers(0)
	return nil
}

func pluginCatalogValidationError(catalog PluginCatalog) error {
	issues := make([]string, 0)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusError {
			continue
		}
		message := strings.TrimSpace(plugin.Error)
		if message == "" {
			message = "validation failed"
		}
		issues = append(issues, plugin.ID+": "+message)
	}
	if len(issues) == 0 {
		return nil
	}
	sort.Strings(issues)
	return fmt.Errorf("plugin catalog validation failed: %s", strings.Join(issues, "; "))
}

func (pm *ProcessManager) markPluginCatalogReloadCompleted(source string, err error) {
	if pm == nil {
		return
	}
	source = strings.TrimSpace(strings.ToLower(source))
	if source == "" {
		source = pluginCatalogHotReloadSourceManual
	}
	result := pluginCatalogHotReloadResultSuccess
	errText := ""
	if err != nil {
		result = pluginCatalogHotReloadResultPartial
		errText = err.Error()
	}
	pm.mu.Lock()
	pm.pluginCatalogLastReloadAt = time.Now()
	pm.pluginCatalogLastReloadSource = source
	pm.pluginCatalogLastReloadResult = result
	pm.pluginCatalogLastReloadError = errText
	pm.mu.Unlock()
}

func (pm *ProcessManager) snapshotPluginCatalogHotReloadStatus() *PluginCatalogHotReload {
	if pm == nil {
		return nil
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	enabled := true
	if pm.cfg != nil {
		enabled = pm.cfg.PluginsEnabled()
	}
	applied := strings.TrimSpace(pm.pluginCatalogAppliedFingerprint)
	detected := strings.TrimSpace(pm.pluginCatalogDetectedFingerprint)
	return &PluginCatalogHotReload{
		Enabled:                      enabled,
		CheckIntervalMS:              pluginCatalogDriftCheckEvery.Milliseconds(),
		UpdateAvailable:              len(pm.pluginCatalogPendingUpdates) > 0,
		LastCheckAt:                  pluginCatalogHotReloadTime(pm.pluginCatalogCheckAt),
		LastCheckResult:              pm.pluginCatalogLastCheckResult,
		LastCheckError:               pm.pluginCatalogLastCheckError,
		LastReloadAt:                 pluginCatalogHotReloadTime(pm.pluginCatalogLastReloadAt),
		LastReloadSource:             pm.pluginCatalogLastReloadSource,
		LastReloadResult:             pm.pluginCatalogLastReloadResult,
		LastReloadError:              pm.pluginCatalogLastReloadError,
		CatalogFingerprint:           applied,
		FingerprintShortHash:         pluginCatalogFingerprintShortHash(applied),
		AppliedFingerprint:           applied,
		AppliedFingerprintShortHash:  pluginCatalogFingerprintShortHash(applied),
		DetectedFingerprint:          detected,
		DetectedFingerprintShortHash: pluginCatalogFingerprintShortHash(detected),
		Updates:                      clonePluginCatalogUpdates(pm.pluginCatalogPendingUpdates),
	}
}

func pluginCatalogHotReloadTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func pluginCatalogFingerprintShortHash(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
