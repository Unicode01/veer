package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pluginHotReloadContentHashMaxBytes = pluginObjectMaxSize

const (
	pluginCatalogHotReloadResultSuccess   = "success"
	pluginCatalogHotReloadResultError     = "error"
	pluginCatalogHotReloadResultPartial   = "partial"
	pluginCatalogHotReloadResultUnchanged = "unchanged"

	pluginCatalogHotReloadSourceAuto   = "auto"
	pluginCatalogHotReloadSourceManual = "manual"
)

func buildPluginCatalogFingerprint(cfg *Config) (string, error) {
	if cfg != nil && !cfg.PluginsEnabled() {
		return "plugins-disabled", nil
	}
	root := normalizePluginsDir("")
	if cfg != nil {
		root = normalizePluginsDir(cfg.PluginsDir)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "plugins-dir-error:" + root + ":" + err.Error(), err
	}

	h := sha256.New()
	fmt.Fprintf(h, "root=%s\n", filepath.Clean(absRoot))

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
		fmt.Fprintf(h, "path=%s mode=%s size=%d mtime=%d\n", rel, mode.String(), info.Size(), info.ModTime().UnixNano())
		if mode&os.ModeSymlink != 0 {
			target, linkErr := os.Readlink(path)
			if linkErr != nil {
				fmt.Fprintf(h, "symlink-error path=%s err=%v\n", rel, linkErr)
				if firstErr == nil {
					firstErr = linkErr
				}
			} else {
				fmt.Fprintf(h, "symlink-target path=%s target=%s\n", rel, target)
			}
		} else if mode.IsRegular() {
			if info.Size() > pluginHotReloadContentHashMaxBytes {
				fmt.Fprintf(h, "content-skip path=%s reason=size>%d\n", rel, pluginHotReloadContentHashMaxBytes)
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
		}
		return nil
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return hex.EncodeToString(h.Sum(nil)), firstErr
}

func (pm *ProcessManager) refreshPluginCatalogFingerprint() error {
	if pm == nil {
		return nil
	}
	fingerprint, err := buildPluginCatalogFingerprint(pm.cfg)
	now := time.Now()
	pm.mu.Lock()
	pm.pluginCatalogFingerprint = fingerprint
	pm.pluginCatalogCheckAt = now
	pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultSuccess
	pm.pluginCatalogLastCheckError = ""
	if err != nil {
		pm.pluginCatalogLastCheckResult = pluginCatalogHotReloadResultError
		pm.pluginCatalogLastCheckError = err.Error()
	}
	pm.mu.Unlock()
	if err != nil {
		log.Printf("plugin hot reload: catalog fingerprint scan issue: %v", err)
	}
	return err
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
	next, err := buildPluginCatalogFingerprint(pm.cfg)
	now := time.Now()
	checkResult := pluginCatalogHotReloadResultSuccess
	checkError := ""
	if err != nil {
		checkResult = pluginCatalogHotReloadResultError
		checkError = err.Error()
	}
	pm.mu.Lock()
	previous := strings.TrimSpace(pm.pluginCatalogFingerprint)
	if previous == "" {
		pm.pluginCatalogFingerprint = next
		pm.pluginCatalogCheckAt = now
		pm.pluginCatalogLastCheckResult = checkResult
		pm.pluginCatalogLastCheckError = checkError
		pm.mu.Unlock()
		if err != nil {
			log.Printf("plugin hot reload: catalog fingerprint scan issue: %v", err)
		}
		return false
	}
	if next == previous {
		if err == nil {
			checkResult = pluginCatalogHotReloadResultUnchanged
		}
		pm.pluginCatalogCheckAt = now
		pm.pluginCatalogLastCheckResult = checkResult
		pm.pluginCatalogLastCheckError = checkError
		pm.mu.Unlock()
		return false
	}
	pm.pluginCatalogFingerprint = next
	pm.pluginCatalogCheckAt = now
	pm.pluginCatalogLastCheckResult = checkResult
	pm.pluginCatalogLastCheckError = checkError
	shuttingDown := pm.shuttingDown
	pm.mu.Unlock()

	if err != nil {
		log.Printf("plugin hot reload: catalog changed with scan issue: %v", err)
	}
	if shuttingDown {
		return false
	}
	log.Printf("plugin hot reload: plugin catalog changed; reconciling plugin runtime")
	pm.reconcilePluginsForRuntime()
	pm.requestRedistributeWorkers(0)
	pm.markPluginCatalogReloadCompleted(pluginCatalogHotReloadSourceAuto, err)
	return true
}

func (pm *ProcessManager) markPluginCatalogReloadCompleted(source string, err error) {
	if pm == nil {
		return
	}
	source = strings.TrimSpace(strings.ToLower(source))
	if source == "" {
		source = pluginCatalogHotReloadSourceAuto
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
	fingerprint := strings.TrimSpace(pm.pluginCatalogFingerprint)
	return &PluginCatalogHotReload{
		Enabled:              enabled,
		CheckIntervalMS:      pluginCatalogDriftCheckEvery.Milliseconds(),
		LastCheckAt:          pluginCatalogHotReloadTime(pm.pluginCatalogCheckAt),
		LastCheckResult:      pm.pluginCatalogLastCheckResult,
		LastCheckError:       pm.pluginCatalogLastCheckError,
		LastReloadAt:         pluginCatalogHotReloadTime(pm.pluginCatalogLastReloadAt),
		LastReloadSource:     pm.pluginCatalogLastReloadSource,
		LastReloadResult:     pm.pluginCatalogLastReloadResult,
		LastReloadError:      pm.pluginCatalogLastReloadError,
		CatalogFingerprint:   fingerprint,
		FingerprintShortHash: pluginCatalogFingerprintShortHash(fingerprint),
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
