package app

import "time"

const (
	pluginPackageFormatVersion            = 1
	pluginPackageMaxArchiveBytes          = 32 << 20
	pluginPackageMaxExtractedBytes        = 128 << 20
	pluginPackageMaxEntryBytes            = 16 << 20
	pluginPackageMaxEntries               = 2048
	pluginPackageStageLifetime            = 24 * time.Hour
	pluginPackageHistoryLimit             = 10
	pluginPackageSignatureDomain          = "veer-plugin-package-v2\x00"
	pluginPackageStateSuffix              = ".veer-state"
	pluginPackageStageMetadataFile        = "stage.json"
	pluginPackageHistoryMetadataFile      = "history.json"
	pluginPackageTransactionFile          = "transaction.json"
	pluginPackageBatchMetadataFile        = "batch.json"
	pluginPackageProbationFileSuffix      = ".json"
	pluginPackageProbationGroupFileSuffix = ".json"
	pluginPackageProbationDuration        = 10 * time.Minute
	pluginPackageProbationRestarts        = 3
	pluginPackageProbationBoots           = 3
	pluginPackageBatchMaxStages           = 16
	pluginPackageExecutionTierControl     = "control"
	pluginPackageExecutionTierDataplane   = "dataplane"
	pluginPackagePublisherNone            = "none"
	pluginPackagePublisherUnknown         = "unknown"
	pluginPackagePublisherTrusted         = "trusted"
	pluginPackagePublisherRevoked         = "revoked"
	pluginPackagePublisherScopeMismatch   = "scope_mismatch"
)

type pluginPackageSignature struct {
	SignerID  string
	PublicKey string
	Signature string
}

type PluginPackageStage struct {
	ID                    string                   `json:"id"`
	PluginID              string                   `json:"plugin_id"`
	Name                  string                   `json:"name"`
	Version               string                   `json:"version"`
	ExistingVersion       string                   `json:"existing_version,omitempty"`
	ExistingFingerprint   string                   `json:"existing_fingerprint,omitempty"`
	ArchiveSHA256         string                   `json:"archive_sha256"`
	CandidateFingerprint  string                   `json:"candidate_fingerprint"`
	Signed                bool                     `json:"signed"`
	Trusted               bool                     `json:"trusted"`
	SignerID              string                   `json:"signer_id,omitempty"`
	SignerName            string                   `json:"signer_name,omitempty"`
	SignerPublicKey       string                   `json:"signer_public_key,omitempty"`
	PublisherStatus       string                   `json:"publisher_status"`
	SignerScope           *PluginTrustScope        `json:"signer_scope,omitempty"`
	ExecutionTier         string                   `json:"execution_tier"`
	Stability             string                   `json:"stability"`
	PrivilegeDigest       string                   `json:"privilege_digest"`
	PrivilegeAdditions    []string                 `json:"privilege_additions,omitempty"`
	AffectedPlugins       []string                 `json:"affected_plugins,omitempty"`
	HistoryID             string                   `json:"history_id,omitempty"`
	CreatedAt             string                   `json:"created_at"`
	ExpiresAt             string                   `json:"expires_at"`
	Compatibility         *PluginCompatibility     `json:"compatibility,omitempty"`
	Dependencies          []PluginDependency       `json:"dependencies,omitempty"`
	Conflicts             []PluginConflict         `json:"conflicts,omitempty"`
	Permissions           []string                 `json:"permissions,omitempty"`
	RuntimeSurface        PluginRuntimeSurface     `json:"runtime_surface"`
	RuntimeSurfaceDigest  string                   `json:"runtime_surface_digest"`
	DeferredRelationships bool                     `json:"deferred_relationships,omitempty"`
	TrustSource           string                   `json:"trust_source,omitempty"`
	RepositoryID          string                   `json:"repository_id,omitempty"`
	RepositoryTarget      string                   `json:"repository_target,omitempty"`
	RepositoryChannel     string                   `json:"repository_channel,omitempty"`
	RepositoryVersion     int64                    `json:"repository_metadata_version,omitempty"`
	Provenance            *PluginPackageProvenance `json:"provenance,omitempty"`
	archivePath           string
	candidateDir          string
	stageDir              string
	signature             string
}

type PluginPackageApplyRequest struct {
	StageID                 string `json:"stage_id"`
	ApprovedPrivilegeDigest string `json:"approved_privilege_digest,omitempty"`
	ApproveUnsigned         bool   `json:"approve_unsigned,omitempty"`
	ApprovePublisher        bool   `json:"approve_publisher,omitempty"`
	RememberPublisher       bool   `json:"remember_publisher,omitempty"`
}

type PluginPackageBatchApplyRequest struct {
	Stages []PluginPackageApplyRequest `json:"stages"`
}

type PluginPackageBatchOperationResult struct {
	ID             string                         `json:"id"`
	Operation      string                         `json:"operation"`
	Plugins        []PluginPackageOperationResult `json:"plugins"`
	RuntimeApplied bool                           `json:"runtime_applied"`
	Catalog        *PluginCatalog                 `json:"catalog,omitempty"`
}

type pluginPackageBatchTransaction struct {
	ID                  string                              `json:"id"`
	Operation           string                              `json:"operation"`
	ResourceMigrationID string                              `json:"resource_migration_id"`
	ProbationGroupID    string                              `json:"probation_group_id,omitempty"`
	Phase               string                              `json:"phase"`
	CreatedAt           string                              `json:"created_at"`
	Items               []pluginPackageBatchTransactionItem `json:"items"`
}

type pluginPackageBatchTransactionItem struct {
	TransactionID           string                   `json:"transaction_id"`
	HistoryID               string                   `json:"history_id"`
	StageID                 string                   `json:"stage_id"`
	Operation               string                   `json:"operation"`
	PluginID                string                   `json:"plugin_id"`
	Version                 string                   `json:"version"`
	PreviousVersion         string                   `json:"previous_version,omitempty"`
	PreviousPrivilegeDigest string                   `json:"previous_privilege_digest,omitempty"`
	PreviousFingerprint     string                   `json:"previous_fingerprint,omitempty"`
	ArchiveSHA256           string                   `json:"archive_sha256,omitempty"`
	CandidateFingerprint    string                   `json:"candidate_fingerprint"`
	TargetDir               string                   `json:"target_dir"`
	CandidateDir            string                   `json:"candidate_dir"`
	BackupDir               string                   `json:"backup_dir"`
	StageDir                string                   `json:"stage_dir"`
	PreviousProvenance      *PluginPackageProvenance `json:"previous_provenance,omitempty"`
	CandidateProvenance     *PluginPackageProvenance `json:"candidate_provenance,omitempty"`
}

type PluginPackageOperationResult struct {
	PluginID       string                  `json:"plugin_id"`
	Version        string                  `json:"version,omitempty"`
	Operation      string                  `json:"operation"`
	HistoryID      string                  `json:"history_id,omitempty"`
	RuntimeApplied bool                    `json:"runtime_applied"`
	Probation      *PluginPackageProbation `json:"probation,omitempty"`
	Warnings       []string                `json:"warnings,omitempty"`
	Catalog        *PluginCatalog          `json:"catalog,omitempty"`
}

type PluginPackageProbation struct {
	PluginID          string `json:"plugin_id"`
	Version           string `json:"version"`
	PreviousHistoryID string `json:"previous_history_id,omitempty"`
	GroupID           string `json:"group_id,omitempty"`
	CreatedAt         string `json:"created_at"`
	StartedAt         string `json:"started_at"`
	ExpiresAt         string `json:"expires_at"`
	Pending           bool   `json:"pending,omitempty"`
	BaselineRestarts  uint64 `json:"baseline_restarts"`
	UncleanStarts     int    `json:"unclean_starts"`
	CleanShutdown     bool   `json:"clean_shutdown"`
	RecoveryAttempts  int    `json:"recovery_attempts,omitempty"`
	NextRecoveryAt    string `json:"next_recovery_at,omitempty"`
	LastFailure       string `json:"last_failure,omitempty"`
	LastFailureAt     string `json:"last_failure_at,omitempty"`
}

type PluginPackageProbationGroup struct {
	ID               string                              `json:"id"`
	CreatedAt        string                              `json:"created_at"`
	Members          []PluginPackageProbationGroupMember `json:"members"`
	RecoveryAttempts int                                 `json:"recovery_attempts,omitempty"`
	NextRecoveryAt   string                              `json:"next_recovery_at,omitempty"`
	LastFailure      string                              `json:"last_failure,omitempty"`
	LastFailureAt    string                              `json:"last_failure_at,omitempty"`
}

type PluginPackageProbationGroupMember struct {
	PluginID          string `json:"plugin_id"`
	Version           string `json:"version"`
	Operation         string `json:"operation"`
	PreviousHistoryID string `json:"previous_history_id,omitempty"`
}

type PluginPackageHistoryEntry struct {
	ID                string                   `json:"id"`
	PluginID          string                   `json:"plugin_id"`
	Version           string                   `json:"version"`
	ArchiveSHA256     string                   `json:"archive_sha256,omitempty"`
	SourceFingerprint string                   `json:"source_fingerprint,omitempty"`
	PrivilegeDigest   string                   `json:"privilege_digest,omitempty"`
	CreatedAt         string                   `json:"created_at"`
	Reason            string                   `json:"reason"`
	Provenance        *PluginPackageProvenance `json:"provenance,omitempty"`
	pluginDir         string
}

type PluginPackageUninstallRequest struct {
	PluginID  string `json:"plugin_id"`
	Force     bool   `json:"force,omitempty"`
	PurgeData bool   `json:"purge_data,omitempty"`
}

type PluginPackageRollbackRequest struct {
	PluginID  string `json:"plugin_id"`
	HistoryID string `json:"history_id"`
}

type PluginTrustKey struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	PublicKey  string            `json:"public_key"`
	Status     string            `json:"status"`
	CreatedAt  string            `json:"created_at"`
	RevokedAt  string            `json:"revoked_at,omitempty"`
	ReplacedBy string            `json:"replaced_by,omitempty"`
	Scope      *PluginTrustScope `json:"scope,omitempty"`
}

type PluginTrustKeyRequest struct {
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	Replaces  string            `json:"replaces,omitempty"`
	Scope     *PluginTrustScope `json:"scope,omitempty"`
}

type PluginTrustScope struct {
	PluginIDs             []string `json:"plugin_ids,omitempty"`
	Permissions           []string `json:"permissions,omitempty"`
	PermissionsRestricted bool     `json:"permissions_restricted,omitempty"`
	ExecutionTiers        []string `json:"execution_tiers,omitempty"`
	Stabilities           []string `json:"stabilities,omitempty"`
}

type pluginPackageTransaction struct {
	ID                      string                   `json:"id"`
	HistoryID               string                   `json:"history_id"`
	Operation               string                   `json:"operation"`
	PluginID                string                   `json:"plugin_id"`
	Version                 string                   `json:"version,omitempty"`
	PreviousVersion         string                   `json:"previous_version,omitempty"`
	PreviousPrivilegeDigest string                   `json:"previous_privilege_digest,omitempty"`
	PreviousFingerprint     string                   `json:"previous_fingerprint,omitempty"`
	ArchiveSHA256           string                   `json:"archive_sha256,omitempty"`
	ResourceMigrationID     string                   `json:"resource_migration_id,omitempty"`
	Phase                   string                   `json:"phase"`
	TargetDir               string                   `json:"target_dir"`
	CandidateDir            string                   `json:"candidate_dir,omitempty"`
	BackupDir               string                   `json:"backup_dir,omitempty"`
	StageDir                string                   `json:"stage_dir,omitempty"`
	PurgeData               bool                     `json:"purge_data,omitempty"`
	CreatedAt               string                   `json:"created_at"`
	PreviousProvenance      *PluginPackageProvenance `json:"previous_provenance,omitempty"`
	CandidateProvenance     *PluginPackageProvenance `json:"candidate_provenance,omitempty"`
}
