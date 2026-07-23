package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const pluginRepositoryPolicyFormatVersion = 1

type PluginRepositoryPolicyRequest struct {
	PluginID      string `json:"plugin_id"`
	RepositoryID  string `json:"repository_id"`
	Channel       string `json:"channel"`
	PinnedVersion string `json:"pinned_version,omitempty"`
	Hold          bool   `json:"hold"`
}

type PluginRepositoryPolicy struct {
	FormatVersion int    `json:"format_version"`
	PluginID      string `json:"plugin_id"`
	RepositoryID  string `json:"repository_id"`
	Channel       string `json:"channel"`
	PinnedVersion string `json:"pinned_version,omitempty"`
	Hold          bool   `json:"hold"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

func (m *pluginPackageManager) SetRepositoryPolicy(request PluginRepositoryPolicyRequest) (PluginRepositoryPolicy, error) {
	if m == nil {
		return PluginRepositoryPolicy{}, fmt.Errorf("plugin package manager is unavailable")
	}
	pluginID := strings.TrimSpace(strings.ToLower(request.PluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return PluginRepositoryPolicy{}, fmt.Errorf("plugin id is invalid")
	}
	repositoryID := strings.TrimSpace(strings.ToLower(request.RepositoryID))
	repository, err := m.loadPluginRepository(repositoryID)
	if err != nil {
		return PluginRepositoryPolicy{}, err
	}
	channel := strings.TrimSpace(strings.ToLower(request.Channel))
	if channel == "" {
		channel = repository.Channel
	}
	channel, err = normalizePluginRepositoryChannel(channel)
	if err != nil {
		return PluginRepositoryPolicy{}, err
	}
	pinnedVersion := strings.TrimSpace(request.PinnedVersion)
	if pinnedVersion != "" {
		normalized, normalizeErr := normalizePluginSemanticVersion(pinnedVersion)
		if normalizeErr != nil || normalized != pinnedVersion {
			return PluginRepositoryPolicy{}, fmt.Errorf("pinned_version must be strict SemVer")
		}
		catalog, catalogErr := m.LoadRepositoryCatalog(repository.ID)
		if catalogErr == nil {
			if _, selectErr := selectPluginRepositoryTarget(catalog, channel, pluginID, pinnedVersion); selectErr != nil {
				return PluginRepositoryPolicy{}, fmt.Errorf("pinned version is unavailable: %w", selectErr)
			}
		}
	}
	if installed := pluginRepositoryInstalledPlugins(m)[pluginID]; installed.ID != "" {
		if pinnedVersion != "" {
			installedVersion, installedErr := semver.StrictNewVersion(installed.Version)
			pinned, pinnedErr := semver.StrictNewVersion(pinnedVersion)
			if installedErr != nil || pinnedErr != nil {
				return PluginRepositoryPolicy{}, fmt.Errorf("installed or pinned version is not strict SemVer")
			}
			if pinned.LessThan(installedVersion) {
				return PluginRepositoryPolicy{}, fmt.Errorf("pinned_version %s is older than installed version %s", pinnedVersion, installed.Version)
			}
			if request.Hold && pinnedVersion != installed.Version {
				return PluginRepositoryPolicy{}, fmt.Errorf("hold requires pinned_version to match installed version %s", installed.Version)
			}
		}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	policy := PluginRepositoryPolicy{
		FormatVersion: pluginRepositoryPolicyFormatVersion,
		PluginID:      pluginID, RepositoryID: repository.ID, Channel: channel,
		PinnedVersion: pinnedVersion, Hold: request.Hold, CreatedAt: now, UpdatedAt: now,
	}
	if previous, loadErr := m.loadRepositoryPolicy(pluginID); loadErr != nil {
		return PluginRepositoryPolicy{}, loadErr
	} else if previous != nil {
		policy.CreatedAt = previous.CreatedAt
	}
	if err := writePluginPackageJSONAtomic(m.repositoryPolicyPath(pluginID), policy, true); err != nil {
		return PluginRepositoryPolicy{}, err
	}
	recordPluginAudit(m.db, pluginID, "repository.policy.set", "system", "success", map[string]any{
		"repository_id": policy.RepositoryID, "channel": policy.Channel, "pinned_version": policy.PinnedVersion, "hold": policy.Hold,
	})
	return policy, nil
}

func (m *pluginPackageManager) DeleteRepositoryPolicy(pluginID string) error {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return fmt.Errorf("plugin id is invalid")
	}
	if _, err := m.loadRepositoryPolicy(pluginID); err != nil {
		return err
	}
	if err := os.Remove(m.repositoryPolicyPath(pluginID)); err != nil {
		return err
	}
	recordPluginAudit(m.db, pluginID, "repository.policy.delete", "system", "success", nil)
	return nil
}

func (m *pluginPackageManager) ListRepositoryPolicies() ([]PluginRepositoryPolicy, error) {
	entries, err := os.ReadDir(filepath.Join(m.stateRoot, "repository-policies"))
	if err != nil {
		return nil, err
	}
	policies := make([]PluginRepositoryPolicy, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("repository policy directory contains unexpected entry %s", entry.Name())
		}
		pluginID := strings.TrimSuffix(entry.Name(), ".json")
		policy, err := m.loadRepositoryPolicy(pluginID)
		if err != nil {
			return nil, err
		}
		if policy != nil {
			policies = append(policies, *policy)
		}
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].PluginID < policies[j].PluginID })
	return policies, nil
}

func (m *pluginPackageManager) repositoryPoliciesByPlugin() (map[string]PluginRepositoryPolicy, error) {
	items, err := m.ListRepositoryPolicies()
	if err != nil {
		return nil, err
	}
	out := make(map[string]PluginRepositoryPolicy, len(items))
	for _, item := range items {
		out[item.PluginID] = item
	}
	return out, nil
}

func (m *pluginPackageManager) loadRepositoryPolicy(pluginID string) (*PluginRepositoryPolicy, error) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return nil, fmt.Errorf("plugin id is invalid")
	}
	var policy PluginRepositoryPolicy
	err := readPluginPackageJSON(m.repositoryPolicyPath(pluginID), &policy)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validatePluginRepositoryPolicy(policy); err != nil {
		return nil, err
	}
	if policy.PluginID != pluginID {
		return nil, fmt.Errorf("repository policy identity mismatch")
	}
	return &policy, nil
}

func validatePluginRepositoryPolicy(policy PluginRepositoryPolicy) error {
	if policy.FormatVersion != pluginRepositoryPolicyFormatVersion || !pluginIDPattern.MatchString(policy.PluginID) || reservedBuiltinPluginID(policy.PluginID) ||
		!pluginIDPattern.MatchString(policy.RepositoryID) || reservedBuiltinPluginID(policy.RepositoryID) {
		return fmt.Errorf("repository policy identity is invalid")
	}
	if _, err := normalizePluginRepositoryChannel(policy.Channel); err != nil {
		return fmt.Errorf("repository policy channel is invalid")
	}
	if policy.PinnedVersion != "" {
		normalized, err := normalizePluginSemanticVersion(policy.PinnedVersion)
		if err != nil || normalized != policy.PinnedVersion {
			return fmt.Errorf("repository policy pinned version is invalid")
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, policy.CreatedAt); err != nil {
		return fmt.Errorf("repository policy created_at is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, policy.UpdatedAt); err != nil {
		return fmt.Errorf("repository policy updated_at is invalid")
	}
	return nil
}

func (m *pluginPackageManager) repositoryPolicyPath(pluginID string) string {
	return filepath.Join(m.stateRoot, "repository-policies", pluginID+".json")
}

func (m *pluginPackageManager) effectiveRepositorySelection(repository PluginRepository, pluginID, requestedVersion string) (string, string, *PluginRepositoryPolicy, error) {
	policy, err := m.loadRepositoryPolicy(pluginID)
	if err != nil {
		return "", "", nil, err
	}
	channel := repository.Channel
	if policy == nil || policy.RepositoryID != repository.ID {
		return channel, requestedVersion, policy, nil
	}
	channel = policy.Channel
	if policy.PinnedVersion != "" {
		if requestedVersion != "" && requestedVersion != policy.PinnedVersion {
			return "", "", nil, fmt.Errorf("plugin %s is pinned to version %s", pluginID, policy.PinnedVersion)
		}
		requestedVersion = policy.PinnedVersion
	}
	return channel, requestedVersion, policy, nil
}

func (m *pluginPackageManager) enforceRepositoryHold(policy *PluginRepositoryPolicy, pluginID, candidateVersion string) error {
	if policy == nil || !policy.Hold {
		return nil
	}
	installed := pluginRepositoryInstalledPlugins(m)[pluginID]
	if installed.ID != "" && installed.Version != candidateVersion {
		return fmt.Errorf("plugin %s is on hold at version %s", pluginID, installed.Version)
	}
	return nil
}
