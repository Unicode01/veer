package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	pluginRepositoryUpdateCurrent       = "current"
	pluginRepositoryUpdateAvailable     = "update_available"
	pluginRepositoryUpdateHeld          = "held"
	pluginRepositoryUpdatePinned        = "pinned"
	pluginRepositoryUpdateRevoked       = "revoked"
	pluginRepositoryUpdateUnavailable   = "unavailable"
	pluginRepositoryUpdateMetadataError = "metadata_unavailable"
)

type PluginRepositoryUpdateStatus struct {
	PluginID                 string                  `json:"plugin_id"`
	CurrentVersion           string                  `json:"current_version"`
	AvailableVersion         string                  `json:"available_version,omitempty"`
	RepositoryID             string                  `json:"repository_id,omitempty"`
	Channel                  string                  `json:"channel,omitempty"`
	PinnedVersion            string                  `json:"pinned_version,omitempty"`
	Hold                     bool                    `json:"hold"`
	Status                   string                  `json:"status"`
	Reason                   string                  `json:"reason,omitempty"`
	ExecutionTier            string                  `json:"execution_tier"`
	RequiresTrustedPublisher bool                    `json:"requires_trusted_publisher"`
	ProvenanceStatus         string                  `json:"provenance_status,omitempty"`
	Target                   *PluginRepositoryTarget `json:"target,omitempty"`
}

type PluginRepositoryRefreshResult struct {
	RepositoryID string `json:"repository_id"`
	Refreshed    bool   `json:"refreshed"`
	TargetCount  int    `json:"target_count,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (m *pluginPackageManager) ListRepositoryUpdates() ([]PluginRepositoryUpdateStatus, error) {
	installed := pluginRepositoryInstalledPlugins(m)
	policies, err := m.repositoryPoliciesByPlugin()
	if err != nil {
		return nil, err
	}
	provenanceItems, err := m.ListPluginPackageProvenance()
	if err != nil {
		return nil, err
	}
	provenance := make(map[string]PluginPackageProvenanceStatus, len(provenanceItems))
	for _, item := range provenanceItems {
		provenance[item.PluginID] = item
	}
	pluginIDs := make([]string, 0, len(installed))
	for pluginID := range installed {
		pluginIDs = append(pluginIDs, pluginID)
	}
	sort.Strings(pluginIDs)

	statuses := make([]PluginRepositoryUpdateStatus, 0, len(pluginIDs))
	for _, pluginID := range pluginIDs {
		plugin := installed[pluginID]
		policy, hasPolicy := policies[pluginID]
		origin, hasOrigin := provenance[pluginID]
		status := PluginRepositoryUpdateStatus{
			PluginID: pluginID, CurrentVersion: plugin.Version,
			Status:                   pluginRepositoryUpdateUnavailable,
			ExecutionTier:            pluginPackageExecutionTier(plugin),
			RequiresTrustedPublisher: pluginPackageRequiresTrustedPublisher(plugin),
		}
		if hasOrigin {
			status.RepositoryID = origin.RepositoryID
			status.Channel = origin.RepositoryChannel
			status.ProvenanceStatus = origin.Status
		}
		if hasPolicy {
			status.RepositoryID = policy.RepositoryID
			status.Channel = policy.Channel
			status.PinnedVersion = policy.PinnedVersion
			status.Hold = policy.Hold
		}
		if status.RepositoryID == "" {
			status.Reason = "plugin has no repository provenance or policy"
			statuses = append(statuses, status)
			continue
		}
		repository, loadErr := m.loadPluginRepository(status.RepositoryID)
		if loadErr != nil {
			status.Reason = loadErr.Error()
			statuses = append(statuses, status)
			continue
		}
		if status.Channel == "" {
			status.Channel = repository.Channel
		}
		catalog, catalogErr := m.LoadRepositoryCatalog(repository.ID)
		if catalogErr != nil {
			status.Status = pluginRepositoryUpdateMetadataError
			status.Reason = catalogErr.Error()
			statuses = append(statuses, status)
			continue
		}
		if hasOrigin && origin.Status == "revoked" {
			status.Status = pluginRepositoryUpdateRevoked
			status.Reason = origin.RevocationReason
			statuses = append(statuses, status)
			continue
		}
		requestedVersion := status.PinnedVersion
		target, selectErr := selectPluginRepositoryTarget(catalog, status.Channel, pluginID, requestedVersion)
		if selectErr != nil {
			status.Reason = selectErr.Error()
			statuses = append(statuses, status)
			continue
		}
		status.AvailableVersion = target.Version
		copyTarget := target
		status.Target = &copyTarget
		currentVersion, currentErr := semver.StrictNewVersion(plugin.Version)
		availableVersion, availableErr := semver.StrictNewVersion(target.Version)
		if currentErr != nil || availableErr != nil {
			status.Reason = "installed or available version is not strict SemVer"
			statuses = append(statuses, status)
			continue
		}
		switch {
		case availableVersion.GreaterThan(currentVersion) && status.Hold:
			status.Status = pluginRepositoryUpdateHeld
		case availableVersion.GreaterThan(currentVersion):
			status.Status = pluginRepositoryUpdateAvailable
		case status.PinnedVersion != "":
			status.Status = pluginRepositoryUpdatePinned
		default:
			status.Status = pluginRepositoryUpdateCurrent
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (m *pluginPackageManager) RefreshAllRepositories() []PluginRepositoryRefreshResult {
	repositories, err := m.ListRepositories()
	if err != nil {
		return []PluginRepositoryRefreshResult{{Error: err.Error()}}
	}
	results := make([]PluginRepositoryRefreshResult, 0, len(repositories))
	for _, repository := range repositories {
		result := PluginRepositoryRefreshResult{RepositoryID: repository.ID}
		catalog, refreshErr := m.RefreshRepository(repository.ID)
		if refreshErr != nil {
			result.Error = refreshErr.Error()
		} else {
			result.Refreshed = true
			result.TargetCount = len(catalog.Targets)
		}
		results = append(results, result)
	}
	return results
}

func pluginRepositoryRefreshResultsError(results []PluginRepositoryRefreshResult) error {
	errors := make([]string, 0)
	for _, result := range results {
		if result.Error != "" {
			name := result.RepositoryID
			if name == "" {
				name = "repository"
			}
			errors = append(errors, name+": "+result.Error)
		}
	}
	if len(errors) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errors, "; "))
}
