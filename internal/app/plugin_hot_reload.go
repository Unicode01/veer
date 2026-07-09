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

func (pm *ProcessManager) refreshPluginCatalogFingerprint() {
	if pm == nil {
		return
	}
	fingerprint, err := buildPluginCatalogFingerprint(pm.cfg)
	pm.mu.Lock()
	pm.pluginCatalogFingerprint = fingerprint
	pm.pluginCatalogCheckAt = time.Now()
	pm.mu.Unlock()
	if err != nil {
		log.Printf("plugin hot reload: catalog fingerprint scan issue: %v", err)
	}
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
	pm.mu.Lock()
	previous := strings.TrimSpace(pm.pluginCatalogFingerprint)
	if previous == "" {
		pm.pluginCatalogFingerprint = next
		pm.pluginCatalogCheckAt = time.Now()
		pm.mu.Unlock()
		if err != nil {
			log.Printf("plugin hot reload: catalog fingerprint scan issue: %v", err)
		}
		return false
	}
	if next == previous {
		pm.pluginCatalogCheckAt = time.Now()
		pm.mu.Unlock()
		return false
	}
	pm.pluginCatalogFingerprint = next
	pm.pluginCatalogCheckAt = time.Now()
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
	return true
}
