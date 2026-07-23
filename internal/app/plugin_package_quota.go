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
	pluginPackageManagedMaxEntries = 262144
	pluginPackageDefaultInstalled  = 128
	pluginPackageDefaultStaged     = 32
	pluginPackageDefaultStorageMB  = 2048
)

type pluginPackageDiskUsage struct {
	Entries int
	Bytes   int64
}

func (m *pluginPackageManager) pluginPackageMaxInstalled() int {
	if m != nil && m.cfg != nil && m.cfg.PluginsMaxInstalled > 0 {
		return m.cfg.PluginsMaxInstalled
	}
	return pluginPackageDefaultInstalled
}

func (m *pluginPackageManager) pluginPackageMaxStaged() int {
	if m != nil && m.cfg != nil && m.cfg.PluginsMaxStaged > 0 {
		return m.cfg.PluginsMaxStaged
	}
	return pluginPackageDefaultStaged
}

func (m *pluginPackageManager) pluginPackageStorageLimit() int64 {
	megabytes := pluginPackageDefaultStorageMB
	if m != nil && m.cfg != nil && m.cfg.PluginsStorageLimitMB > 0 {
		megabytes = m.cfg.PluginsStorageLimitMB
	}
	return int64(megabytes) << 20
}

func (m *pluginPackageManager) enforcePluginPackageStageQuota() error {
	if m == nil {
		return fmt.Errorf("plugin package manager is unavailable")
	}
	m.cleanupExpiredStages(pluginPackageNow())
	staged, err := countPluginPackageDirectories(filepath.Join(m.stateRoot, "staging"))
	if err != nil {
		return err
	}
	if staged >= m.pluginPackageMaxStaged() {
		return fmt.Errorf("plugin staging limit reached: %d", m.pluginPackageMaxStaged())
	}
	reserve := int64(pluginPackageMaxArchiveBytes + pluginPackageMaxExtractedBytes)
	return m.enforcePluginPackageStorageQuota(reserve)
}

func (m *pluginPackageManager) enforcePluginPackageStorageQuota(reserve int64) error {
	if m == nil {
		return fmt.Errorf("plugin package manager is unavailable")
	}
	usage, err := measurePluginPackageManagedUsage(m.pluginsRoot, m.stateRoot)
	if err != nil {
		return err
	}
	limit := m.pluginPackageStorageLimit()
	if reserve < 0 {
		return fmt.Errorf("plugin storage reserve is invalid")
	}
	if usage.Bytes > limit || reserve > limit-usage.Bytes {
		if err := m.prunePluginPackageHistoryForQuota(reserve); err != nil {
			return err
		}
		usage, err = measurePluginPackageManagedUsage(m.pluginsRoot, m.stateRoot)
		if err != nil {
			return err
		}
	}
	if usage.Bytes > limit || reserve > limit-usage.Bytes {
		return fmt.Errorf("plugin storage quota exceeded: used=%d reserve=%d limit=%d bytes", usage.Bytes, reserve, limit)
	}
	return nil
}

func (m *pluginPackageManager) prunePluginPackageHistoryForQuota(reserve int64) error {
	protected, err := m.protectedPluginPackageHistories()
	if err != nil {
		return err
	}
	type candidate struct {
		pluginID string
		entry    PluginPackageHistoryEntry
	}
	candidates := make([]candidate, 0)
	historyRoot := filepath.Join(m.stateRoot, "history")
	plugins, err := os.ReadDir(historyRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, pluginDir := range plugins {
		if !pluginDir.IsDir() || !pluginIDPattern.MatchString(pluginDir.Name()) || reservedBuiltinPluginID(pluginDir.Name()) {
			continue
		}
		history, err := m.ListHistory(pluginDir.Name())
		if err != nil {
			return err
		}
		if len(history) > 0 {
			protected[pluginPackageHistoryQuotaKey(pluginDir.Name(), history[0].ID)] = struct{}{}
		}
		for _, entry := range history {
			key := pluginPackageHistoryQuotaKey(pluginDir.Name(), entry.ID)
			if _, keep := protected[key]; !keep {
				candidates = append(candidates, candidate{pluginID: pluginDir.Name(), entry: entry})
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].entry.CreatedAt == candidates[j].entry.CreatedAt {
			return pluginPackageHistoryQuotaKey(candidates[i].pluginID, candidates[i].entry.ID) < pluginPackageHistoryQuotaKey(candidates[j].pluginID, candidates[j].entry.ID)
		}
		return candidates[i].entry.CreatedAt < candidates[j].entry.CreatedAt
	})
	limit := m.pluginPackageStorageLimit()
	for _, item := range candidates {
		usage, err := measurePluginPackageManagedUsage(m.pluginsRoot, m.stateRoot)
		if err != nil {
			return err
		}
		if usage.Bytes <= limit && reserve <= limit-usage.Bytes {
			return nil
		}
		if err := removePluginPackageManagedPath(m.stateRoot, filepath.Dir(item.entry.pluginDir)); err != nil {
			return err
		}
	}
	return nil
}

func (m *pluginPackageManager) protectedPluginPackageHistories() (map[string]struct{}, error) {
	protected := make(map[string]struct{})
	probationRoot := filepath.Join(m.stateRoot, "probation")
	if entries, err := os.ReadDir(probationRoot); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), pluginPackageProbationFileSuffix) {
				continue
			}
			var probation PluginPackageProbation
			if err := readPluginPackageJSON(filepath.Join(probationRoot, entry.Name()), &probation); err != nil {
				return nil, err
			}
			if probation.PreviousHistoryID != "" {
				protected[pluginPackageHistoryQuotaKey(probation.PluginID, probation.PreviousHistoryID)] = struct{}{}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	groupRoot := filepath.Join(m.stateRoot, "probation-groups")
	if entries, err := os.ReadDir(groupRoot); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), pluginPackageProbationGroupFileSuffix) {
				continue
			}
			var group PluginPackageProbationGroup
			if err := readPluginPackageJSON(filepath.Join(groupRoot, entry.Name()), &group); err != nil {
				return nil, err
			}
			for _, member := range group.Members {
				if member.PreviousHistoryID != "" {
					protected[pluginPackageHistoryQuotaKey(member.PluginID, member.PreviousHistoryID)] = struct{}{}
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return protected, nil
}

func pluginPackageHistoryQuotaKey(pluginID, historyID string) string {
	return pluginID + "\x00" + historyID
}

func (m *pluginPackageManager) enforcePluginPackageInstalledQuota(additional int) error {
	if m == nil || additional <= 0 {
		return nil
	}
	installed, err := countPluginPackageDirectories(m.pluginsRoot)
	if err != nil {
		return err
	}
	limit := m.pluginPackageMaxInstalled()
	if installed > limit-additional {
		return fmt.Errorf("installed plugin limit exceeded: current=%d additional=%d limit=%d", installed, additional, limit)
	}
	return nil
}

func (m *pluginPackageManager) validatePluginPackageCatalogQuota(catalog PluginCatalog) error {
	installed := 0
	for _, plugin := range catalog.Plugins {
		if !plugin.Builtin {
			installed++
		}
	}
	if installed > m.pluginPackageMaxInstalled() {
		return fmt.Errorf("installed plugin limit exceeded: final=%d limit=%d", installed, m.pluginPackageMaxInstalled())
	}
	return nil
}

func measurePluginPackageManagedUsage(roots ...string) (pluginPackageDiskUsage, error) {
	usage := pluginPackageDiskUsage{}
	for _, root := range roots {
		info, err := os.Lstat(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return pluginPackageDiskUsage{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return pluginPackageDiskUsage{}, fmt.Errorf("plugin managed root %s must be a regular directory", root)
		}
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == root {
				return nil
			}
			usage.Entries++
			if usage.Entries > pluginPackageManagedMaxEntries {
				return fmt.Errorf("plugin managed state contains more than %d entries", pluginPackageManagedMaxEntries)
			}
			entryInfo, err := entry.Info()
			if err != nil {
				return err
			}
			if entryInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("plugin managed state contains symbolic link %s", path)
			}
			if entry.IsDir() {
				return nil
			}
			if !entryInfo.Mode().IsRegular() || entryInfo.Size() < 0 {
				return fmt.Errorf("plugin managed state contains unsupported file %s", path)
			}
			if usage.Bytes > int64(^uint64(0)>>1)-entryInfo.Size() {
				return fmt.Errorf("plugin managed state size overflow")
			}
			usage.Bytes += entryInfo.Size()
			return nil
		})
		if err != nil {
			return pluginPackageDiskUsage{}, err
		}
	}
	return usage, nil
}

func countPluginPackageDirectories(root string) (int, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return 0, fmt.Errorf("plugin managed root contains symbolic link %s", filepath.Join(root, entry.Name()))
		}
		if entry.IsDir() {
			count++
		}
	}
	return count, nil
}

var pluginPackageNow = func() time.Time { return time.Now() }
