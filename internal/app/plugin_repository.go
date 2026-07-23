package app

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func (m *pluginPackageManager) AddRepository(request PluginRepositoryRequest) (PluginRepository, error) {
	if m == nil {
		return PluginRepository{}, fmt.Errorf("plugin package manager is unavailable")
	}
	id := strings.TrimSpace(strings.ToLower(request.ID))
	if !pluginIDPattern.MatchString(id) || reservedBuiltinPluginID(id) {
		return PluginRepository{}, fmt.Errorf("repository id is invalid")
	}
	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return PluginRepository{}, fmt.Errorf("repository name must contain 1 to 128 printable characters")
	}
	metadataURL, err := normalizePluginRepositoryURL(request.MetadataURL)
	if err != nil {
		return PluginRepository{}, fmt.Errorf("metadata_url: %w", err)
	}
	targetsURL, err := normalizePluginRepositoryURL(request.TargetsURL)
	if err != nil {
		return PluginRepository{}, fmt.Errorf("targets_url: %w", err)
	}
	channel, err := normalizePluginRepositoryChannel(request.Channel)
	if err != nil {
		return PluginRepository{}, err
	}
	root := bytes.TrimSpace(request.Root)
	if len(root) == 0 || len(root) > pluginRepositoryMaxRootBytes || !json.Valid(root) {
		return PluginRepository{}, fmt.Errorf("root must be valid TUF JSON of at most %d bytes", pluginRepositoryMaxRootBytes)
	}
	trusted, err := trustedmetadata.New(root)
	if err != nil {
		return PluginRepository{}, fmt.Errorf("root is not valid TUF metadata: %w", err)
	}
	if trusted.Root == nil || trusted.Root.Signed.Version < 1 {
		return PluginRepository{}, fmt.Errorf("root TUF metadata version is invalid")
	}
	if !trusted.Root.Signed.Expires.After(time.Now()) {
		return PluginRepository{}, fmt.Errorf("root TUF metadata is expired")
	}

	repositoryDir := m.pluginRepositoryDir(id)
	if _, err := os.Lstat(repositoryDir); err == nil {
		return PluginRepository{}, fmt.Errorf("repository %s already exists", id)
	} else if !os.IsNotExist(err) {
		return PluginRepository{}, err
	}
	for _, dir := range []string{repositoryDir, filepath.Join(repositoryDir, "metadata"), filepath.Join(repositoryDir, "targets")} {
		if err := ensurePluginPackageDirectory(dir, 0o700); err != nil {
			_ = removePluginPackageManagedPath(m.stateRoot, repositoryDir)
			return PluginRepository{}, err
		}
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removePluginPackageManagedPath(m.stateRoot, repositoryDir)
		}
	}()
	rootHash := sha256.Sum256(root)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	repository := PluginRepository{
		FormatVersion: pluginRepositoryFormatVersion, ID: id, Name: name,
		MetadataURL: metadataURL, TargetsURL: targetsURL, Channel: channel,
		RootSHA256: hex.EncodeToString(rootHash[:]), CreatedAt: now, UpdatedAt: now,
		RootVersion: trusted.Root.Signed.Version,
	}
	if err := writePluginPackageFileAtomic(filepath.Join(repositoryDir, "root.json"), root, false, 0o600); err != nil {
		return PluginRepository{}, err
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(repositoryDir, "repository.json"), repository, false); err != nil {
		return PluginRepository{}, err
	}
	cleanup = false
	recordPluginAudit(m.db, "", "repository.add", "system", "success", map[string]any{
		"repository_id": repository.ID, "channel": repository.Channel, "root_sha256": repository.RootSHA256,
	})
	return repository, nil
}

func (m *pluginPackageManager) ListRepositories() ([]PluginRepository, error) {
	root := filepath.Join(m.stateRoot, "repositories")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	repositories := make([]PluginRepository, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !pluginIDPattern.MatchString(entry.Name()) || reservedBuiltinPluginID(entry.Name()) {
			return nil, fmt.Errorf("repository state contains unexpected entry %s", entry.Name())
		}
		repository, err := m.loadPluginRepository(entry.Name())
		if err != nil {
			return nil, err
		}
		repositories = append(repositories, repository)
	}
	sort.Slice(repositories, func(i, j int) bool { return repositories[i].ID < repositories[j].ID })
	return repositories, nil
}

func (m *pluginPackageManager) DeleteRepository(id string) error {
	id = strings.TrimSpace(strings.ToLower(id))
	if !pluginIDPattern.MatchString(id) || reservedBuiltinPluginID(id) {
		return fmt.Errorf("repository id is invalid")
	}
	if _, err := m.loadPluginRepository(id); err != nil {
		return err
	}
	policies, err := m.ListRepositoryPolicies()
	if err != nil {
		return err
	}
	for _, policy := range policies {
		if policy.RepositoryID == id {
			return fmt.Errorf("repository %s is referenced by policy for plugin %s", id, policy.PluginID)
		}
	}
	stages, err := os.ReadDir(filepath.Join(m.stateRoot, "staging"))
	if err != nil {
		return err
	}
	for _, entry := range stages {
		if !entry.IsDir() || !validPluginPackageID(entry.Name()) {
			continue
		}
		var record pluginPackageStageRecord
		if err := readPluginPackageJSON(filepath.Join(m.stateRoot, "staging", entry.Name(), pluginPackageStageMetadataFile), &record); err != nil {
			return err
		}
		if record.Stage.RepositoryID == id {
			return fmt.Errorf("repository %s has pending stage %s", id, record.Stage.ID)
		}
	}
	if err := removePluginPackageManagedPath(m.stateRoot, m.pluginRepositoryDir(id)); err != nil {
		return err
	}
	recordPluginAudit(m.db, "", "repository.delete", "system", "success", map[string]any{"repository_id": id})
	return nil
}

func (m *pluginPackageManager) RefreshRepository(id string) (PluginRepositoryCatalog, error) {
	repository, err := m.loadPluginRepository(id)
	if err != nil {
		return PluginRepositoryCatalog{}, err
	}
	catalog, _, err := m.refreshPluginRepository(repository)
	return catalog, err
}

func (m *pluginPackageManager) LoadRepositoryCatalog(id string) (PluginRepositoryCatalog, error) {
	repository, err := m.loadPluginRepository(id)
	if err != nil {
		return PluginRepositoryCatalog{}, err
	}
	var catalog PluginRepositoryCatalog
	if err := readPluginRepositoryJSON(filepath.Join(m.pluginRepositoryDir(repository.ID), "catalog.json"), pluginRepositoryMaxCatalogBytes, &catalog); err != nil {
		if os.IsNotExist(err) {
			return PluginRepositoryCatalog{}, fmt.Errorf("repository %s has not been refreshed", repository.ID)
		}
		return PluginRepositoryCatalog{}, err
	}
	if err := validatePluginRepositoryCatalog(repository, catalog); err != nil {
		return PluginRepositoryCatalog{}, err
	}
	return catalog, nil
}

func (m *pluginPackageManager) StageFromRepository(request PluginRepositoryStageRequest) (PluginPackageStage, error) {
	repository, err := m.loadPluginRepository(request.RepositoryID)
	if err != nil {
		return PluginPackageStage{}, err
	}
	pluginID := strings.TrimSpace(strings.ToLower(request.PluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return PluginPackageStage{}, fmt.Errorf("plugin id is invalid")
	}
	requestedVersion := strings.TrimSpace(request.Version)
	if requestedVersion != "" {
		if normalized, err := normalizePluginSemanticVersion(requestedVersion); err != nil || normalized != requestedVersion {
			return PluginPackageStage{}, fmt.Errorf("plugin version must be strict SemVer")
		}
	}
	channel, requestedVersion, policy, err := m.effectiveRepositorySelection(repository, pluginID, requestedVersion)
	if err != nil {
		return PluginPackageStage{}, err
	}
	catalog, client, err := m.refreshPluginRepository(repository)
	if err != nil {
		return PluginPackageStage{}, err
	}
	target, err := selectPluginRepositoryTarget(catalog, channel, pluginID, requestedVersion)
	if err != nil {
		return PluginPackageStage{}, err
	}
	if err := m.enforceRepositoryHold(policy, pluginID, target.Version); err != nil {
		return PluginPackageStage{}, err
	}
	return m.stagePluginRepositoryTarget(repository, catalog, client, target, request.DeferRelationships)
}

func (m *pluginPackageManager) stagePluginRepositoryTarget(
	repository PluginRepository,
	catalog PluginRepositoryCatalog,
	client *updater.Updater,
	target PluginRepositoryTarget,
	deferredRelationships bool,
) (PluginPackageStage, error) {
	if err := m.validateRepositoryTargetPolicy(repository, target); err != nil {
		return PluginPackageStage{}, err
	}
	if err := m.checkPluginRepositoryAntiDowngrade(repository, target); err != nil {
		return PluginPackageStage{}, err
	}
	targetInfo, err := client.GetTargetInfo(target.Target)
	if err != nil {
		return PluginPackageStage{}, fmt.Errorf("resolve repository target: %w", err)
	}
	if err := verifyPluginRepositoryTargetInfo(target, targetInfo); err != nil {
		return PluginPackageStage{}, err
	}
	_, archive, err := client.DownloadTarget(targetInfo, "", repository.TargetsURL)
	if err != nil {
		return PluginPackageStage{}, fmt.Errorf("download repository target: %w", err)
	}
	stage, err := m.StageWithDeferredRelationships(bytes.NewReader(archive), "", "", deferredRelationships)
	if err != nil {
		return PluginPackageStage{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removePluginPackageManagedPath(m.stateRoot, stage.stageDir)
		}
	}()
	if stage.PluginID != target.PluginID || stage.Version != target.Version {
		return PluginPackageStage{}, fmt.Errorf("repository target metadata does not match plugin manifest")
	}
	if repository.Channel == pluginRepositoryChannelStable && stage.RuntimeSurfaceDigest == "" {
		return PluginPackageStage{}, fmt.Errorf("repository candidate has no runtime surface digest")
	}
	candidate, _, _, err := m.validateCandidateDirectoryWithOptions(stage.candidateDir, deferredRelationships)
	if err != nil {
		return PluginPackageStage{}, err
	}
	if err := validatePluginRepositoryCandidateStability(repository.Channel, candidate.Stability); err != nil {
		return PluginPackageStage{}, err
	}
	if target.Stability != "" && target.Stability != candidate.Stability {
		return PluginPackageStage{}, fmt.Errorf("repository target stability does not match plugin manifest")
	}
	if target.Name != candidate.Name || target.Description != candidate.Description ||
		!reflect.DeepEqual(target.Compatibility, candidate.Compatibility) ||
		!reflect.DeepEqual(target.Dependencies, candidate.Dependencies) ||
		!reflect.DeepEqual(target.Conflicts, candidate.Conflicts) {
		return PluginPackageStage{}, fmt.Errorf("repository target manifest metadata does not match plugin manifest")
	}
	stage.Trusted = true
	stage.TrustSource = "tuf"
	stage.RepositoryID = repository.ID
	stage.RepositoryTarget = target.Target
	stage.RepositoryChannel = target.Channel
	stage.RepositoryVersion = catalog.TargetsVersion
	stage.Provenance = pluginRepositoryProvenance(stage)
	if err := writePluginPackageJSONAtomic(filepath.Join(stage.stageDir, pluginPackageStageMetadataFile), pluginPackageStageRecord{Stage: stage}, true); err != nil {
		return PluginPackageStage{}, err
	}
	if err := m.recordPluginRepositoryVersion(repository, target); err != nil {
		return PluginPackageStage{}, err
	}
	cleanup = false
	recordPluginAudit(m.db, stage.PluginID, "repository.stage", "system", "success", map[string]any{
		"repository_id": repository.ID, "target": target.Target, "version": target.Version, "channel": target.Channel,
	})
	return stage, nil
}

func (m *pluginPackageManager) validateRepositoryTargetPolicy(repository PluginRepository, target PluginRepositoryTarget) error {
	policy, err := m.loadRepositoryPolicy(target.PluginID)
	if err != nil {
		return err
	}
	if policy == nil || policy.RepositoryID != repository.ID {
		return nil
	}
	if target.Channel != policy.Channel {
		return fmt.Errorf("plugin %s repository policy requires channel %s", target.PluginID, policy.Channel)
	}
	if policy.PinnedVersion != "" && target.Version != policy.PinnedVersion {
		return fmt.Errorf("plugin %s is pinned to version %s", target.PluginID, policy.PinnedVersion)
	}
	return m.enforceRepositoryHold(policy, target.PluginID, target.Version)
}

func (m *pluginPackageManager) validateRepositoryStage(stage PluginPackageStage) error {
	if stage.RepositoryID == "" || stage.HistoryID != "" {
		return fmt.Errorf("repository stage trust metadata is invalid")
	}
	wantProvenance := pluginRepositoryProvenance(stage)
	if stage.Provenance == nil || wantProvenance == nil || *stage.Provenance != *wantProvenance {
		return fmt.Errorf("repository stage provenance does not match its trust metadata")
	}
	if err := validatePluginPackageProvenance(*stage.Provenance); err != nil {
		return err
	}
	repository, err := m.loadPluginRepository(stage.RepositoryID)
	if err != nil {
		return err
	}
	if repository.Channel != stage.RepositoryChannel {
		return fmt.Errorf("repository channel changed after staging")
	}
	catalog, client, err := m.refreshPluginRepository(repository)
	if err != nil {
		return err
	}
	if catalog.TargetsVersion < stage.RepositoryVersion {
		return fmt.Errorf("repository targets metadata rolled back from %d to %d", stage.RepositoryVersion, catalog.TargetsVersion)
	}
	var target *PluginRepositoryTarget
	for i := range catalog.Targets {
		candidate := &catalog.Targets[i]
		if candidate.Target == stage.RepositoryTarget && candidate.PluginID == stage.PluginID && candidate.Version == stage.Version {
			target = candidate
			break
		}
	}
	if target == nil {
		return fmt.Errorf("repository target %s is no longer available", stage.RepositoryTarget)
	}
	if target.Revoked {
		return fmt.Errorf("repository target %s is revoked: %s", target.Target, target.RevocationReason)
	}
	if target.SHA256 != stage.ArchiveSHA256 {
		return fmt.Errorf("repository target digest changed after staging")
	}
	info, err := client.GetTargetInfo(target.Target)
	if err != nil {
		return err
	}
	if err := verifyPluginRepositoryTargetInfo(*target, info); err != nil {
		return err
	}
	return m.checkPluginRepositoryLedger(repository, *target)
}

func (m *pluginPackageManager) refreshPluginRepository(repository PluginRepository) (catalog PluginRepositoryCatalog, client *updater.Updater, resultErr error) {
	client, err := m.newPluginRepositoryUpdater(repository)
	if err != nil {
		return PluginRepositoryCatalog{}, nil, err
	}
	if err := client.Refresh(); err != nil {
		m.notePluginRepositoryRefresh(repository, PluginRepositoryCatalog{}, err)
		return PluginRepositoryCatalog{}, nil, fmt.Errorf("refresh TUF repository %s: %w", repository.ID, err)
	}
	catalog, err = buildPluginRepositoryCatalog(repository, client)
	if err != nil {
		m.notePluginRepositoryRefresh(repository, PluginRepositoryCatalog{}, err)
		return PluginRepositoryCatalog{}, nil, err
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(m.pluginRepositoryDir(repository.ID), "catalog.json"), catalog, true); err != nil {
		return PluginRepositoryCatalog{}, nil, err
	}
	if err := m.notePluginRepositoryRefresh(repository, catalog, nil); err != nil {
		return PluginRepositoryCatalog{}, nil, err
	}
	recordPluginAudit(m.db, "", "repository.refresh", "system", "success", map[string]any{
		"repository_id": repository.ID, "targets_version": catalog.TargetsVersion, "target_count": len(catalog.Targets),
	})
	return catalog, client, nil
}

func (m *pluginPackageManager) newPluginRepositoryUpdater(repository PluginRepository) (*updater.Updater, error) {
	root, err := readPluginRepositoryFile(filepath.Join(m.pluginRepositoryDir(repository.ID), "root.json"), pluginRepositoryMaxRootBytes)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(root)
	if hex.EncodeToString(hash[:]) != repository.RootSHA256 {
		return nil, fmt.Errorf("repository %s root digest does not match configuration", repository.ID)
	}
	cfg, err := tufconfig.New(repository.MetadataURL, root)
	if err != nil {
		return nil, err
	}
	cfg.LocalMetadataDir = filepath.Join(m.pluginRepositoryDir(repository.ID), "metadata")
	cfg.LocalTargetsDir = filepath.Join(m.pluginRepositoryDir(repository.ID), "targets")
	cfg.RemoteTargetsURL = repository.TargetsURL
	cfg.RootMaxLength = pluginRepositoryMaxRootBytes
	cfg.TimestampMaxLength = 64 << 10
	cfg.SnapshotMaxLength = 2 << 20
	cfg.TargetsMaxLength = pluginRepositoryMaxCatalogBytes
	cfg.MaxRootRotations = 1024
	cfg.MaxDelegations = 0
	client := m.repositoryHTTPClient
	if client == nil {
		client = newPluginRepositoryHTTPClient()
	}
	if err := cfg.SetDefaultFetcherHTTPClient(client); err != nil {
		return nil, err
	}
	return updater.New(cfg)
}

func buildPluginRepositoryCatalog(repository PluginRepository, client *updater.Updater) (PluginRepositoryCatalog, error) {
	trusted := client.GetTrustedMetadataSet()
	if trusted.Root == nil || trusted.Timestamp == nil || trusted.Snapshot == nil || trusted.Targets[tufmetadata.TARGETS] == nil {
		return PluginRepositoryCatalog{}, fmt.Errorf("repository trusted metadata set is incomplete")
	}
	targets := client.GetTopLevelTargets()
	if len(targets) > pluginRepositoryMaxTargets {
		return PluginRepositoryCatalog{}, fmt.Errorf("repository target count %d exceeds %d", len(targets), pluginRepositoryMaxTargets)
	}
	catalog := PluginRepositoryCatalog{
		RepositoryID: repository.ID, RefreshedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RootVersion: trusted.Root.Signed.Version, TimestampVersion: trusted.Timestamp.Signed.Version,
		SnapshotVersion: trusted.Snapshot.Signed.Version, TargetsVersion: trusted.Targets[tufmetadata.TARGETS].Signed.Version,
		Targets: make([]PluginRepositoryTarget, 0, len(targets)),
	}
	seen := make(map[string]string)
	for targetPath, info := range targets {
		target, ok, err := parsePluginRepositoryTarget(targetPath, info)
		if err != nil {
			return PluginRepositoryCatalog{}, err
		}
		if !ok {
			continue
		}
		key := target.PluginID + "\x00" + target.Version + "\x00" + target.Channel
		if previous, exists := seen[key]; exists {
			return PluginRepositoryCatalog{}, fmt.Errorf("repository contains duplicate plugin target %s and %s", previous, target.Target)
		}
		seen[key] = target.Target
		catalog.Targets = append(catalog.Targets, target)
	}
	sort.Slice(catalog.Targets, func(i, j int) bool {
		left, right := catalog.Targets[i], catalog.Targets[j]
		if left.PluginID != right.PluginID {
			return left.PluginID < right.PluginID
		}
		leftVersion, _ := semver.StrictNewVersion(left.Version)
		rightVersion, _ := semver.StrictNewVersion(right.Version)
		if !leftVersion.Equal(rightVersion) {
			return leftVersion.LessThan(rightVersion)
		}
		return left.Target < right.Target
	})
	if encoded, err := json.Marshal(catalog); err != nil || len(encoded) > pluginRepositoryMaxCatalogBytes {
		return PluginRepositoryCatalog{}, fmt.Errorf("repository catalog exceeds %d bytes", pluginRepositoryMaxCatalogBytes)
	}
	return catalog, nil
}

func parsePluginRepositoryTarget(targetPath string, info *tufmetadata.TargetFiles) (PluginRepositoryTarget, bool, error) {
	if info == nil || info.Custom == nil {
		return PluginRepositoryTarget{}, false, nil
	}
	var header struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(*info.Custom, &header); err != nil {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s custom metadata is invalid: %w", targetPath, err)
	}
	if header.Kind != pluginRepositoryTargetKind {
		return PluginRepositoryTarget{}, false, nil
	}
	var custom pluginRepositoryTargetMetadata
	if err := decodePluginRepositoryJSON(*info.Custom, &custom); err != nil {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s custom metadata: %w", targetPath, err)
	}
	if custom.FormatVersion != pluginRepositoryTargetFormatVersion || custom.Kind != pluginRepositoryTargetKind {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s has unsupported Veer metadata version", targetPath)
	}
	if !validPluginRepositoryTargetPath(targetPath) {
		return PluginRepositoryTarget{}, false, fmt.Errorf("repository target path %q is invalid", targetPath)
	}
	custom.PluginID = strings.TrimSpace(strings.ToLower(custom.PluginID))
	if !pluginIDPattern.MatchString(custom.PluginID) || reservedBuiltinPluginID(custom.PluginID) {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s plugin id is invalid", targetPath)
	}
	custom.Name = strings.TrimSpace(custom.Name)
	custom.Description = strings.TrimSpace(custom.Description)
	if custom.Name == "" || len(custom.Name) > 128 || strings.ContainsAny(custom.Name, "\x00\r\n") {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s plugin name is invalid", targetPath)
	}
	if len(custom.Description) > 2048 || strings.ContainsAny(custom.Description, "\x00\r") {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s plugin description is invalid", targetPath)
	}
	if err := normalizePluginCompatibility(custom.Compatibility); err != nil {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s compatibility: %w", targetPath, err)
	}
	if err := normalizePluginDependencies(custom.PluginID, custom.Dependencies); err != nil {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s dependencies: %w", targetPath, err)
	}
	if err := normalizePluginConflicts(custom.PluginID, custom.Conflicts); err != nil {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s conflicts: %w", targetPath, err)
	}
	if err := validatePluginRelationshipOverlap(custom.Dependencies, custom.Conflicts); err != nil {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s relationships: %w", targetPath, err)
	}
	version, err := semver.StrictNewVersion(strings.TrimSpace(custom.Version))
	if err != nil || version.String() != custom.Version {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s version must be strict SemVer", targetPath)
	}
	channel, err := normalizePluginRepositoryChannel(custom.Channel)
	if err != nil {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s: %w", targetPath, err)
	}
	if channel == pluginRepositoryChannelStable && version.Prerelease() != "" {
		return PluginRepositoryTarget{}, false, fmt.Errorf("stable target %s cannot use a prerelease version", targetPath)
	}
	if info.Length <= 0 || info.Length > pluginPackageMaxArchiveBytes {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s length %d is outside package limits", targetPath, info.Length)
	}
	digest, ok := info.Hashes["sha256"]
	if !ok || len(digest) != sha256.Size {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s is missing a SHA256 digest", targetPath)
	}
	custom.Stability = strings.TrimSpace(strings.ToLower(custom.Stability))
	if custom.Stability != "" && !validPluginStability(custom.Stability) {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s stability is invalid", targetPath)
	}
	custom.RevocationReason = strings.TrimSpace(custom.RevocationReason)
	if len(custom.RevocationReason) > 1024 || strings.ContainsAny(custom.RevocationReason, "\x00\r\n") {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s revocation reason is invalid", targetPath)
	}
	if custom.Revoked && custom.RevocationReason == "" {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s revocation requires a reason", targetPath)
	}
	if !custom.Revoked && custom.RevocationReason != "" {
		return PluginRepositoryTarget{}, false, fmt.Errorf("target %s has a revocation reason but is not revoked", targetPath)
	}
	return PluginRepositoryTarget{
		Target: targetPath, PluginID: custom.PluginID, Name: custom.Name, Description: custom.Description,
		Version: custom.Version, Channel: channel, Stability: custom.Stability,
		Compatibility: clonePluginCompatibility(custom.Compatibility),
		Dependencies:  append([]PluginDependency(nil), custom.Dependencies...),
		Conflicts:     append([]PluginConflict(nil), custom.Conflicts...),
		Length:        info.Length, SHA256: hex.EncodeToString(digest),
		Revoked: custom.Revoked, RevocationReason: custom.RevocationReason,
	}, true, nil
}

func selectPluginRepositoryTarget(catalog PluginRepositoryCatalog, channel, pluginID, requestedVersion string) (PluginRepositoryTarget, error) {
	var selected *PluginRepositoryTarget
	for i := range catalog.Targets {
		target := &catalog.Targets[i]
		if target.PluginID != pluginID || target.Channel != channel || target.Revoked {
			continue
		}
		if requestedVersion != "" && target.Version != requestedVersion {
			continue
		}
		if selected == nil {
			copyTarget := *target
			selected = &copyTarget
			continue
		}
		current, _ := semver.StrictNewVersion(selected.Version)
		candidate, _ := semver.StrictNewVersion(target.Version)
		if candidate.GreaterThan(current) {
			copyTarget := *target
			selected = &copyTarget
		}
	}
	if selected == nil {
		if requestedVersion == "" {
			return PluginRepositoryTarget{}, fmt.Errorf("repository has no non-revoked %s target for plugin %s", channel, pluginID)
		}
		return PluginRepositoryTarget{}, fmt.Errorf("repository has no non-revoked %s target for plugin %s version %s", channel, pluginID, requestedVersion)
	}
	return *selected, nil
}

func verifyPluginRepositoryTargetInfo(target PluginRepositoryTarget, info *tufmetadata.TargetFiles) error {
	if info == nil || info.Length != target.Length {
		return fmt.Errorf("repository target length does not match trusted catalog")
	}
	digest, ok := info.Hashes["sha256"]
	if !ok || hex.EncodeToString(digest) != target.SHA256 {
		return fmt.Errorf("repository target digest does not match trusted catalog")
	}
	return nil
}

func (m *pluginPackageManager) checkPluginRepositoryAntiDowngrade(repository PluginRepository, target PluginRepositoryTarget) error {
	if err := m.checkPluginRepositoryLedger(repository, target); err != nil {
		return err
	}
	current, err := m.loadCurrentPlugin(target.PluginID)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	currentVersion, err := semver.StrictNewVersion(current.Version)
	if err != nil {
		return fmt.Errorf("installed plugin version is invalid: %w", err)
	}
	candidateVersion, _ := semver.StrictNewVersion(target.Version)
	if !candidateVersion.GreaterThan(currentVersion) {
		return fmt.Errorf("repository target version %s is not newer than installed version %s; use verified local history for rollback", target.Version, current.Version)
	}
	return nil
}

func (m *pluginPackageManager) checkPluginRepositoryLedger(repository PluginRepository, target PluginRepositoryTarget) error {
	ledger, err := m.loadPluginRepositoryLedger(repository.ID)
	if err != nil {
		return err
	}
	previous, ok := ledger.Entries[target.PluginID]
	if !ok {
		return nil
	}
	previousVersion, err := semver.StrictNewVersion(previous.Version)
	if err != nil {
		return fmt.Errorf("repository version ledger is invalid")
	}
	candidateVersion, _ := semver.StrictNewVersion(target.Version)
	if candidateVersion.LessThan(previousVersion) {
		return fmt.Errorf("repository target version %s is below highest trusted version %s", target.Version, previous.Version)
	}
	if candidateVersion.Equal(previousVersion) && previous.SHA256 != target.SHA256 {
		return fmt.Errorf("repository target version %s changed digest after it was trusted", target.Version)
	}
	return nil
}

func (m *pluginPackageManager) recordPluginRepositoryVersion(repository PluginRepository, target PluginRepositoryTarget) error {
	ledger, err := m.loadPluginRepositoryLedger(repository.ID)
	if err != nil {
		return err
	}
	if ledger.Entries == nil {
		ledger.Entries = make(map[string]pluginRepositoryVersionRecord)
	}
	previous, exists := ledger.Entries[target.PluginID]
	if exists {
		previousVersion, _ := semver.StrictNewVersion(previous.Version)
		candidateVersion, _ := semver.StrictNewVersion(target.Version)
		if candidateVersion.LessThan(previousVersion) || (candidateVersion.Equal(previousVersion) && previous.SHA256 != target.SHA256) {
			return fmt.Errorf("repository version ledger refused a downgrade")
		}
		if candidateVersion.Equal(previousVersion) {
			return nil
		}
	}
	ledger.Entries[target.PluginID] = pluginRepositoryVersionRecord{
		Version: target.Version, SHA256: target.SHA256, Target: target.Target, SeenAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	return writePluginPackageJSONAtomic(filepath.Join(m.pluginRepositoryDir(repository.ID), "versions.json"), ledger, true)
}

func (m *pluginPackageManager) loadPluginRepositoryLedger(id string) (pluginRepositoryVersionLedger, error) {
	path := filepath.Join(m.pluginRepositoryDir(id), "versions.json")
	var ledger pluginRepositoryVersionLedger
	if err := readPluginPackageJSON(path, &ledger); err != nil {
		if os.IsNotExist(err) {
			return pluginRepositoryVersionLedger{FormatVersion: pluginRepositoryFormatVersion, Entries: make(map[string]pluginRepositoryVersionRecord)}, nil
		}
		return pluginRepositoryVersionLedger{}, err
	}
	if ledger.FormatVersion != pluginRepositoryFormatVersion || ledger.Entries == nil || len(ledger.Entries) > pluginRepositoryMaxTargets {
		return pluginRepositoryVersionLedger{}, fmt.Errorf("repository version ledger is invalid")
	}
	for pluginID, record := range ledger.Entries {
		if !pluginIDPattern.MatchString(pluginID) || record.Version == "" || len(record.SHA256) != sha256.Size*2 || !validPluginRepositoryTargetPath(record.Target) {
			return pluginRepositoryVersionLedger{}, fmt.Errorf("repository version ledger entry %s is invalid", pluginID)
		}
		if _, err := semver.StrictNewVersion(record.Version); err != nil {
			return pluginRepositoryVersionLedger{}, fmt.Errorf("repository version ledger entry %s is invalid", pluginID)
		}
		if _, err := hex.DecodeString(record.SHA256); err != nil {
			return pluginRepositoryVersionLedger{}, fmt.Errorf("repository version ledger entry %s is invalid", pluginID)
		}
		if _, err := time.Parse(time.RFC3339Nano, record.SeenAt); err != nil {
			return pluginRepositoryVersionLedger{}, fmt.Errorf("repository version ledger entry %s is invalid", pluginID)
		}
	}
	return ledger, nil
}

func (m *pluginPackageManager) loadPluginRepository(id string) (PluginRepository, error) {
	id = strings.TrimSpace(strings.ToLower(id))
	if !pluginIDPattern.MatchString(id) || reservedBuiltinPluginID(id) {
		return PluginRepository{}, fmt.Errorf("repository id is invalid")
	}
	var repository PluginRepository
	if err := readPluginPackageJSON(filepath.Join(m.pluginRepositoryDir(id), "repository.json"), &repository); err != nil {
		if os.IsNotExist(err) {
			return PluginRepository{}, fmt.Errorf("repository %s not found", id)
		}
		return PluginRepository{}, err
	}
	if repository.ID != id || repository.FormatVersion != pluginRepositoryFormatVersion {
		return PluginRepository{}, fmt.Errorf("repository %s metadata failed identity validation", id)
	}
	if _, err := normalizePluginRepositoryURL(repository.MetadataURL); err != nil {
		return PluginRepository{}, fmt.Errorf("repository %s metadata URL is invalid", id)
	}
	if _, err := normalizePluginRepositoryURL(repository.TargetsURL); err != nil {
		return PluginRepository{}, fmt.Errorf("repository %s targets URL is invalid", id)
	}
	if _, err := normalizePluginRepositoryChannel(repository.Channel); err != nil {
		return PluginRepository{}, fmt.Errorf("repository %s channel is invalid", id)
	}
	if len(repository.RootSHA256) != sha256.Size*2 {
		return PluginRepository{}, fmt.Errorf("repository %s root digest is invalid", id)
	}
	if _, err := time.Parse(time.RFC3339Nano, repository.CreatedAt); err != nil {
		return PluginRepository{}, fmt.Errorf("repository %s creation time is invalid", id)
	}
	if _, err := time.Parse(time.RFC3339Nano, repository.UpdatedAt); err != nil {
		return PluginRepository{}, fmt.Errorf("repository %s update time is invalid", id)
	}
	return repository, nil
}

func (m *pluginPackageManager) notePluginRepositoryRefresh(repository PluginRepository, catalog PluginRepositoryCatalog, refreshErr error) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	repository.UpdatedAt = now
	repository.LastRefreshAt = now
	if refreshErr != nil {
		repository.LastRefreshError = compactPluginSchemaError(refreshErr)
	} else {
		repository.LastRefreshError = ""
		repository.RootVersion = catalog.RootVersion
		repository.TimestampVersion = catalog.TimestampVersion
		repository.SnapshotVersion = catalog.SnapshotVersion
		repository.TargetsVersion = catalog.TargetsVersion
		repository.TargetCount = len(catalog.Targets)
	}
	return writePluginPackageJSONAtomic(filepath.Join(m.pluginRepositoryDir(repository.ID), "repository.json"), repository, true)
}

func validatePluginRepositoryCatalog(repository PluginRepository, catalog PluginRepositoryCatalog) error {
	if catalog.RepositoryID != repository.ID || catalog.RootVersion < 1 || catalog.TimestampVersion < 1 || catalog.SnapshotVersion < 1 || catalog.TargetsVersion < 1 {
		return fmt.Errorf("repository catalog metadata is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, catalog.RefreshedAt); err != nil || len(catalog.Targets) > pluginRepositoryMaxTargets {
		return fmt.Errorf("repository catalog metadata is invalid")
	}
	seenTargets := make(map[string]struct{}, len(catalog.Targets))
	seenVersions := make(map[string]struct{}, len(catalog.Targets))
	for _, target := range catalog.Targets {
		if err := validatePluginRepositoryCatalogTarget(target); err != nil {
			return fmt.Errorf("repository catalog target %s is invalid: %w", target.Target, err)
		}
		if _, exists := seenTargets[target.Target]; exists {
			return fmt.Errorf("repository catalog contains duplicate target %s", target.Target)
		}
		seenTargets[target.Target] = struct{}{}
		versionKey := target.PluginID + "\x00" + target.Version + "\x00" + target.Channel
		if _, exists := seenVersions[versionKey]; exists {
			return fmt.Errorf("repository catalog contains duplicate plugin version")
		}
		seenVersions[versionKey] = struct{}{}
	}
	return nil
}

func validatePluginRepositoryCatalogTarget(target PluginRepositoryTarget) error {
	if !validPluginRepositoryTargetPath(target.Target) || !pluginIDPattern.MatchString(target.PluginID) || reservedBuiltinPluginID(target.PluginID) {
		return fmt.Errorf("target identity is invalid")
	}
	if strings.TrimSpace(target.Name) != target.Name || target.Name == "" || len(target.Name) > 128 || strings.ContainsAny(target.Name, "\x00\r\n") {
		return fmt.Errorf("target name is invalid")
	}
	if strings.TrimSpace(target.Description) != target.Description || len(target.Description) > 2048 || strings.ContainsAny(target.Description, "\x00\r") {
		return fmt.Errorf("target description is invalid")
	}
	version, err := normalizePluginSemanticVersion(target.Version)
	if err != nil || version != target.Version {
		return fmt.Errorf("target version is invalid")
	}
	channel, err := normalizePluginRepositoryChannel(target.Channel)
	if err != nil || channel != target.Channel || validatePluginRepositoryCandidateStability(channel, target.Stability) != nil {
		return fmt.Errorf("target channel or stability is invalid")
	}
	if target.Length <= 0 || target.Length > pluginPackageMaxArchiveBytes || len(target.SHA256) != sha256.Size*2 {
		return fmt.Errorf("target archive metadata is invalid")
	}
	if _, err := hex.DecodeString(target.SHA256); err != nil {
		return fmt.Errorf("target archive digest is invalid")
	}
	normalizedCompatibility := clonePluginCompatibility(target.Compatibility)
	if err := normalizePluginCompatibility(normalizedCompatibility); err != nil || !reflect.DeepEqual(normalizedCompatibility, target.Compatibility) {
		return fmt.Errorf("target compatibility is invalid")
	}
	normalizedDependencies := append([]PluginDependency(nil), target.Dependencies...)
	if err := normalizePluginDependencies(target.PluginID, normalizedDependencies); err != nil || !reflect.DeepEqual(normalizedDependencies, target.Dependencies) {
		return fmt.Errorf("target dependencies are invalid")
	}
	normalizedConflicts := append([]PluginConflict(nil), target.Conflicts...)
	if err := normalizePluginConflicts(target.PluginID, normalizedConflicts); err != nil || !reflect.DeepEqual(normalizedConflicts, target.Conflicts) {
		return fmt.Errorf("target conflicts are invalid")
	}
	if err := validatePluginRelationshipOverlap(normalizedDependencies, normalizedConflicts); err != nil {
		return fmt.Errorf("target relationships are invalid")
	}
	if strings.TrimSpace(target.RevocationReason) != target.RevocationReason || len(target.RevocationReason) > 1024 || strings.ContainsAny(target.RevocationReason, "\x00\r\n") ||
		(target.Revoked && target.RevocationReason == "") || (!target.Revoked && target.RevocationReason != "") {
		return fmt.Errorf("target revocation metadata is invalid")
	}
	return nil
}

func validatePluginRepositoryCandidateStability(channel, stability string) error {
	stability = strings.TrimSpace(strings.ToLower(stability))
	switch channel {
	case pluginRepositoryChannelStable:
		if stability != pluginStabilityStable {
			return fmt.Errorf("stable repository target requires plugin stability stable, found %s", stability)
		}
	case pluginRepositoryChannelPreview:
		if stability != pluginStabilityStable && stability != pluginStabilityPreview {
			return fmt.Errorf("preview repository target requires plugin stability preview or stable, found %s", stability)
		}
	default:
		return fmt.Errorf("repository channel is invalid")
	}
	return nil
}

func normalizePluginRepositoryChannel(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		value = pluginRepositoryChannelStable
	}
	if value != pluginRepositoryChannelStable && value != pluginRepositoryChannelPreview {
		return "", fmt.Errorf("channel must be stable or preview")
	}
	return value, nil
}

func normalizePluginRepositoryURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || strings.ToLower(parsed.Scheme) != "https" || parsed.Host == "" {
		return "", fmt.Errorf("URL must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", fmt.Errorf("URL must not contain credentials, query, fragment, or opaque data")
	}
	for _, part := range strings.Split(strings.ReplaceAll(parsed.EscapedPath(), "\\", "/"), "/") {
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == ".." || strings.Contains(decoded, "\\") {
			return "", fmt.Errorf("URL path is invalid")
		}
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func validPluginRepositoryTargetPath(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || strings.Contains(value, "\x00") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (m *pluginPackageManager) pluginRepositoryDir(id string) string {
	return filepath.Join(m.stateRoot, "repositories", id)
}

func newPluginRepositoryHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	return &http.Client{
		Transport: transport,
		Timeout:   pluginRepositoryHTTPTimeoutSeconds * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("repository redirect limit exceeded")
			}
			if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || !strings.EqualFold(req.URL.Host, via[0].URL.Host)) {
				return fmt.Errorf("repository redirect changed origin")
			}
			return nil
		},
	}
}

func decodePluginRepositoryJSON(data []byte, target any) error {
	if err := rejectPluginDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("JSON contains trailing values")
		}
		return err
	}
	return nil
}

func readPluginRepositoryFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("repository file is not a bounded regular file")
	}
	return os.ReadFile(path) // #nosec G304 -- path is manager-owned and checked above.
}

func readPluginRepositoryJSON(path string, maxBytes int64, target any) error {
	data, err := readPluginRepositoryFile(path, maxBytes)
	if err != nil {
		return err
	}
	return decodePluginRepositoryJSON(data, target)
}

func writePluginPackageFileAtomic(path string, data []byte, replace bool, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	id, err := newPluginPackageID()
	if err != nil {
		return err
	}
	temporary := path + ".tmp-" + id
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304 -- path is manager-owned and temporary name is random.
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		return errors.Join(writeErr, syncErr, closeErr)
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			_ = os.Remove(temporary)
			return fmt.Errorf("path already exists")
		} else if !os.IsNotExist(err) {
			_ = os.Remove(temporary)
			return err
		}
	}
	if err := os.Rename(temporary, path); err != nil {
		if replace {
			if removeErr := os.Remove(path); removeErr == nil || os.IsNotExist(removeErr) {
				err = os.Rename(temporary, path)
			}
		}
		if err != nil {
			_ = os.Remove(temporary)
			return err
		}
	}
	return os.Chmod(path, mode)
}
