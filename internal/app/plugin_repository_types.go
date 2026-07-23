package app

import "encoding/json"

const (
	pluginRepositoryFormatVersion       = 1
	pluginRepositoryTargetFormatVersion = 1
	pluginRepositoryChannelStable       = "stable"
	pluginRepositoryChannelPreview      = "preview"
	pluginRepositoryMaxRootBytes        = 512 << 10
	pluginRepositoryMaxTargets          = 4096
	pluginRepositoryMaxCatalogBytes     = 4 << 20
	pluginRepositoryHTTPTimeoutSeconds  = 30
	pluginRepositoryTargetKind          = "veer-plugin"
)

type PluginRepositoryRequest struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	MetadataURL string          `json:"metadata_url"`
	TargetsURL  string          `json:"targets_url"`
	Channel     string          `json:"channel"`
	Root        json.RawMessage `json:"root"`
}

type PluginRepository struct {
	FormatVersion    int    `json:"format_version"`
	ID               string `json:"id"`
	Name             string `json:"name"`
	MetadataURL      string `json:"metadata_url"`
	TargetsURL       string `json:"targets_url"`
	Channel          string `json:"channel"`
	RootSHA256       string `json:"root_sha256"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	LastRefreshAt    string `json:"last_refresh_at,omitempty"`
	LastRefreshError string `json:"last_refresh_error,omitempty"`
	RootVersion      int64  `json:"root_version,omitempty"`
	TimestampVersion int64  `json:"timestamp_version,omitempty"`
	SnapshotVersion  int64  `json:"snapshot_version,omitempty"`
	TargetsVersion   int64  `json:"targets_version,omitempty"`
	TargetCount      int    `json:"target_count,omitempty"`
}

type PluginRepositoryTarget struct {
	Target           string               `json:"target"`
	PluginID         string               `json:"plugin_id"`
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	Version          string               `json:"version"`
	Channel          string               `json:"channel"`
	Stability        string               `json:"stability,omitempty"`
	Compatibility    *PluginCompatibility `json:"compatibility,omitempty"`
	Dependencies     []PluginDependency   `json:"dependencies,omitempty"`
	Conflicts        []PluginConflict     `json:"conflicts,omitempty"`
	Length           int64                `json:"length"`
	SHA256           string               `json:"sha256"`
	Revoked          bool                 `json:"revoked,omitempty"`
	RevocationReason string               `json:"revocation_reason,omitempty"`
}

type PluginRepositoryCatalog struct {
	RepositoryID     string                   `json:"repository_id"`
	RefreshedAt      string                   `json:"refreshed_at"`
	RootVersion      int64                    `json:"root_version"`
	TimestampVersion int64                    `json:"timestamp_version"`
	SnapshotVersion  int64                    `json:"snapshot_version"`
	TargetsVersion   int64                    `json:"targets_version"`
	Targets          []PluginRepositoryTarget `json:"targets"`
}

type PluginRepositoryStageRequest struct {
	RepositoryID       string `json:"repository_id"`
	PluginID           string `json:"plugin_id"`
	Version            string `json:"version,omitempty"`
	DeferRelationships bool   `json:"defer_relationships,omitempty"`
}

type PluginRepositoryInstallPlanRequest struct {
	RepositoryID string `json:"repository_id"`
	PluginID     string `json:"plugin_id"`
	Version      string `json:"version,omitempty"`
}

type PluginRepositoryInstallPlanReuse struct {
	PluginID string `json:"plugin_id"`
	Version  string `json:"version"`
}

type PluginRepositoryInstallPlan struct {
	RepositoryID     string                             `json:"repository_id"`
	Channel          string                             `json:"channel"`
	RequestedPlugin  string                             `json:"requested_plugin_id"`
	RequestedVersion string                             `json:"requested_version,omitempty"`
	CreatedAt        string                             `json:"created_at"`
	Stages           []PluginPackageStage               `json:"stages"`
	Reused           []PluginRepositoryInstallPlanReuse `json:"reused,omitempty"`
}

type pluginRepositoryTargetMetadata struct {
	FormatVersion    int                  `json:"format_version"`
	Kind             string               `json:"kind"`
	PluginID         string               `json:"plugin_id"`
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	Version          string               `json:"version"`
	Channel          string               `json:"channel"`
	Stability        string               `json:"stability,omitempty"`
	Compatibility    *PluginCompatibility `json:"compatibility,omitempty"`
	Dependencies     []PluginDependency   `json:"dependencies,omitempty"`
	Conflicts        []PluginConflict     `json:"conflicts,omitempty"`
	Revoked          bool                 `json:"revoked,omitempty"`
	RevocationReason string               `json:"revocation_reason,omitempty"`
}

type pluginRepositoryVersionLedger struct {
	FormatVersion int                                      `json:"format_version"`
	Entries       map[string]pluginRepositoryVersionRecord `json:"entries"`
}

type pluginRepositoryVersionRecord struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Target  string `json:"target"`
	SeenAt  string `json:"seen_at"`
}

type PluginPackageProvenance struct {
	FormatVersion     int    `json:"format_version"`
	PluginID          string `json:"plugin_id"`
	Version           string `json:"version"`
	Source            string `json:"source"`
	RepositoryID      string `json:"repository_id"`
	RepositoryTarget  string `json:"repository_target"`
	RepositoryChannel string `json:"repository_channel"`
	RepositoryVersion int64  `json:"repository_metadata_version"`
	ArchiveSHA256     string `json:"archive_sha256"`
	AppliedAt         string `json:"applied_at"`
}

type PluginPackageProvenanceStatus struct {
	PluginPackageProvenance
	Status           string `json:"status"`
	RevocationReason string `json:"revocation_reason,omitempty"`
}
