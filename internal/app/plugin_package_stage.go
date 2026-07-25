package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type pluginPackageStageRecord struct {
	Stage     PluginPackageStage `json:"stage"`
	Signature string             `json:"signature,omitempty"`
}

func (m *pluginPackageManager) Stage(reader io.Reader) (PluginPackageStage, error) {
	return m.StageWithDeferredRelationships(reader, false)
}

func (m *pluginPackageManager) StageWithDeferredRelationships(reader io.Reader, deferredRelationships bool) (PluginPackageStage, error) {
	if err := m.enforcePluginPackageStageQuota(); err != nil {
		return PluginPackageStage{}, err
	}
	stageID, err := newPluginPackageID()
	if err != nil {
		return PluginPackageStage{}, err
	}
	stageDir := filepath.Join(m.stateRoot, "staging", stageID)
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return PluginPackageStage{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removePluginPackageManagedPath(m.stateRoot, stageDir)
		}
	}()

	uploadPath := filepath.Join(stageDir, "upload")
	uploadDigest, uploadBytes, err := writeBoundedPluginPackageFile(reader, uploadPath, pluginPackageMaxContainerBytes, "plugin package upload")
	if err != nil {
		return PluginPackageStage{}, err
	}
	archivePath := filepath.Join(stageDir, pluginPackageContainerArchiveName)
	container, err := isPluginPackageContainer(uploadPath)
	if err != nil {
		return PluginPackageStage{}, err
	}
	archiveDigest := uploadDigest
	signature := pluginPackageSignature{}
	if container {
		archiveDigest, signature, err = extractPluginPackageContainer(uploadPath, archivePath)
		if err != nil {
			return PluginPackageStage{}, err
		}
		if err := os.Remove(uploadPath); err != nil {
			return PluginPackageStage{}, err
		}
	} else {
		if uploadBytes > pluginPackageMaxArchiveBytes {
			return PluginPackageStage{}, fmt.Errorf("plugin package archive exceeds %d bytes", pluginPackageMaxArchiveBytes)
		}
		if err := os.Rename(uploadPath, archivePath); err != nil {
			return PluginPackageStage{}, err
		}
	}
	verifiedSignature, err := m.verifyArchiveSignature(archiveDigest, signature)
	if err != nil {
		return PluginPackageStage{}, err
	}
	extractDir := filepath.Join(stageDir, "extracted")
	candidateDir, err := extractPluginPackageArchive(archivePath, extractDir)
	if err != nil {
		return PluginPackageStage{}, err
	}
	candidate, previous, affected, err := m.validateCandidateDirectoryWithOptions(candidateDir, deferredRelationships)
	if err != nil {
		return PluginPackageStage{}, err
	}
	if filepath.Base(candidateDir) != candidate.ID {
		return PluginPackageStage{}, fmt.Errorf("plugin package directory %q does not match manifest id %q", filepath.Base(candidateDir), candidate.ID)
	}
	trusted, publisherStatus := pluginPackagePublisherState(verifiedSignature, candidate)
	if previous == nil {
		if err := m.enforcePluginPackageInstalledQuota(1); err != nil {
			return PluginPackageStage{}, err
		}
	}
	fingerprint, err := buildPluginDirectoryFingerprint(candidateDir)
	if err != nil {
		return PluginPackageStage{}, fmt.Errorf("fingerprint plugin candidate: %w", err)
	}
	privileges, privilegeDigest := pluginPrivilegeSummary(candidate)
	runtimeSurface := pluginRuntimeSurfaceFromLoaded(candidate)
	runtimeSurfaceDigest := pluginRuntimeSurfaceDigest(runtimeSurface)
	var previousPrivileges []string
	existingVersion := ""
	existingFingerprint := ""
	if previous != nil {
		existingVersion = previous.Version
		previousPrivileges, _ = pluginPrivilegeSummary(*previous)
		existingFingerprint, _ = buildPluginDirectoryFingerprint(filepath.Join(m.pluginsRoot, previous.ID))
	}
	additions := pluginPrivilegeAdditions(previousPrivileges, privileges)
	now := time.Now().UTC()
	trustSource := "unsigned"
	if verifiedSignature.Signed {
		trustSource = "signature"
	}
	stage := PluginPackageStage{
		ID:                    stageID,
		PluginID:              candidate.ID,
		Name:                  candidate.Name,
		Version:               candidate.Version,
		ExistingVersion:       existingVersion,
		ExistingFingerprint:   existingFingerprint,
		ArchiveSHA256:         archiveDigest,
		CandidateFingerprint:  fingerprint,
		Signed:                verifiedSignature.Signed,
		Trusted:               trusted,
		SignerID:              verifiedSignature.SignerID,
		SignerPublicKey:       verifiedSignature.PublicKey,
		PublisherStatus:       publisherStatus,
		ExecutionTier:         pluginPackageExecutionTier(candidate),
		Stability:             candidate.Stability,
		PrivilegeDigest:       privilegeDigest,
		PrivilegeAdditions:    additions,
		AffectedPlugins:       affected,
		CreatedAt:             now.Format(time.RFC3339Nano),
		ExpiresAt:             now.Add(pluginPackageStageLifetime).Format(time.RFC3339Nano),
		Compatibility:         clonePluginCompatibility(candidate.Compatibility),
		Dependencies:          append([]PluginDependency(nil), candidate.Dependencies...),
		Conflicts:             append([]PluginConflict(nil), candidate.Conflicts...),
		RuntimeSurface:        runtimeSurface,
		RuntimeSurfaceDigest:  runtimeSurfaceDigest,
		DeferredRelationships: deferredRelationships,
		TrustSource:           trustSource,
		archivePath:           archivePath,
		candidateDir:          candidateDir,
		stageDir:              stageDir,
		signature:             strings.TrimSpace(signature.Signature),
	}
	if candidate.Control != nil {
		stage.Permissions = append([]string(nil), candidate.Control.Permissions...)
	}
	if verifiedSignature.TrustKey != nil {
		stage.SignerName = verifiedSignature.TrustKey.Name
		stage.SignerScope = clonePluginTrustScope(verifiedSignature.TrustKey.Scope)
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(stageDir, pluginPackageStageMetadataFile), pluginPackageStageRecord{Stage: stage, Signature: stage.signature}, false); err != nil {
		return PluginPackageStage{}, err
	}
	cleanup = false
	recordPluginAudit(m.db, stage.PluginID, "package.stage", "system", "success", map[string]any{
		"stage_id": stage.ID, "version": stage.Version, "signed": stage.Signed, "trusted": stage.Trusted,
		"signer_id": stage.SignerID, "publisher_status": stage.PublisherStatus, "privilege_additions": stage.PrivilegeAdditions,
	})
	return stage, nil
}

func (m *pluginPackageManager) LoadStage(stageID string) (PluginPackageStage, error) {
	if err := validatePluginPackageID(stageID); err != nil {
		return PluginPackageStage{}, err
	}
	stageDir := filepath.Join(m.stateRoot, "staging", stageID)
	var record pluginPackageStageRecord
	if err := readPluginPackageJSON(filepath.Join(stageDir, pluginPackageStageMetadataFile), &record); err != nil {
		if os.IsNotExist(err) {
			return PluginPackageStage{}, fmt.Errorf("plugin package stage %s not found", stageID)
		}
		return PluginPackageStage{}, err
	}
	stage := record.Stage
	if stage.ID != stageID || !pluginIDPattern.MatchString(stage.PluginID) {
		return PluginPackageStage{}, fmt.Errorf("plugin package stage metadata failed identity validation")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, stage.ExpiresAt)
	if err != nil || time.Now().After(expiresAt) {
		_ = removePluginPackageManagedPath(m.stateRoot, stageDir)
		return PluginPackageStage{}, fmt.Errorf("plugin package stage %s has expired", stageID)
	}
	stage.stageDir = stageDir
	stage.archivePath = filepath.Join(stageDir, pluginPackageContainerArchiveName)
	stage.candidateDir = filepath.Join(stageDir, "extracted", stage.PluginID)
	stage.signature = record.Signature
	if stage.HistoryID == "" {
		archiveDigest, err := sha256File(stage.archivePath)
		if err != nil || archiveDigest != stage.ArchiveSHA256 {
			return PluginPackageStage{}, fmt.Errorf("plugin package stage archive failed integrity validation")
		}
	} else {
		if !validPluginPackageHistoryID(stage.HistoryID) || !stage.Trusted || stage.TrustSource != "history" || stage.RepositoryID != "" {
			return PluginPackageStage{}, fmt.Errorf("plugin rollback stage metadata failed validation")
		}
		if err := validatePluginPackageProvenanceForPackage(stage.Provenance, stage.PluginID, stage.Version); err != nil {
			return PluginPackageStage{}, fmt.Errorf("plugin rollback stage provenance failed validation: %w", err)
		}
	}
	if stage.RepositoryID != "" {
		stage.Trusted = false
		if stage.TrustSource != "tuf" || stage.Signed || stage.HistoryID != "" {
			return PluginPackageStage{}, fmt.Errorf("plugin repository stage trust metadata failed validation")
		}
		if err := m.validateRepositoryStage(stage); err != nil {
			return PluginPackageStage{}, err
		}
		stage.Trusted = true
		stage.PublisherStatus = pluginPackagePublisherNone
	} else if stage.Trusted && !stage.Signed && stage.HistoryID == "" {
		return PluginPackageStage{}, fmt.Errorf("plugin package stage has an unverified trust source")
	} else if stage.HistoryID == "" && stage.Provenance != nil {
		return PluginPackageStage{}, fmt.Errorf("local plugin stage cannot carry repository provenance")
	}
	if stage.RepositoryID == "" && stage.HistoryID == "" {
		if stage.Signed && stage.TrustSource != "signature" {
			return PluginPackageStage{}, fmt.Errorf("signed plugin package stage has an invalid trust source")
		}
		if !stage.Signed && stage.TrustSource != "unsigned" {
			return PluginPackageStage{}, fmt.Errorf("unsigned plugin package stage has an invalid trust source")
		}
	} else if stage.HistoryID != "" {
		stage.PublisherStatus = pluginPackagePublisherNone
	}
	var verifiedSignature pluginPackageVerifiedSignature
	if stage.Signed {
		verifiedSignature, err = m.verifyArchiveSignature(stage.ArchiveSHA256, pluginPackageSignature{
			SignerID: stage.SignerID, PublicKey: stage.SignerPublicKey, Signature: stage.signature,
		})
		if err != nil {
			return PluginPackageStage{}, err
		}
		if !verifiedSignature.Signed || verifiedSignature.SignerID != stage.SignerID || verifiedSignature.PublicKey != stage.SignerPublicKey {
			return PluginPackageStage{}, fmt.Errorf("plugin package stage signer identity changed")
		}
	} else if stage.SignerID != "" || stage.SignerPublicKey != "" || stage.signature != "" {
		return PluginPackageStage{}, fmt.Errorf("unsigned plugin package stage contains signer metadata")
	}
	fingerprint, err := buildPluginDirectoryFingerprint(stage.candidateDir)
	if err != nil || fingerprint != stage.CandidateFingerprint {
		return PluginPackageStage{}, fmt.Errorf("plugin package stage candidate failed integrity validation")
	}
	candidate, _, _, err := m.validateCandidateDirectoryWithOptions(stage.candidateDir, stage.DeferredRelationships)
	if err != nil {
		return PluginPackageStage{}, err
	}
	if stage.Signed {
		stage.Trusted, stage.PublisherStatus = pluginPackagePublisherState(verifiedSignature, candidate)
		stage.SignerName = ""
		stage.SignerScope = nil
		if verifiedSignature.TrustKey != nil {
			stage.SignerName = verifiedSignature.TrustKey.Name
			stage.SignerScope = clonePluginTrustScope(verifiedSignature.TrustKey.Scope)
		}
	} else if stage.RepositoryID == "" && stage.HistoryID == "" {
		stage.Trusted = false
		stage.PublisherStatus = pluginPackagePublisherNone
	}
	if stage.ExecutionTier != pluginPackageExecutionTier(candidate) || stage.Stability != candidate.Stability {
		return PluginPackageStage{}, fmt.Errorf("plugin package stage execution trust metadata changed")
	}
	_, privilegeDigest := pluginPrivilegeSummary(candidate)
	runtimeSurface := pluginRuntimeSurfaceFromLoaded(candidate)
	if candidate.ID != stage.PluginID || candidate.Version != stage.Version || privilegeDigest != stage.PrivilegeDigest ||
		pluginRuntimeSurfaceDigest(runtimeSurface) != stage.RuntimeSurfaceDigest {
		return PluginPackageStage{}, fmt.Errorf("plugin package stage candidate no longer matches approved metadata")
	}
	return stage, nil
}

func (m *pluginPackageManager) validateCandidateDirectory(candidateDir string) (LoadedPlugin, *LoadedPlugin, []string, error) {
	return m.validateCandidateDirectoryWithOptions(candidateDir, false)
}

func (m *pluginPackageManager) validateCandidateDirectoryWithOptions(candidateDir string, deferredRelationships bool) (LoadedPlugin, *LoadedPlugin, []string, error) {
	candidate, err := loadPluginFromDir(candidateDir, filepath.Base(candidateDir))
	if err != nil {
		return LoadedPlugin{}, nil, nil, err
	}
	if candidate.Status != pluginStatusActive {
		return LoadedPlugin{}, nil, nil, fmt.Errorf("plugin candidate is invalid: %s", candidate.Error)
	}
	validationCfg := pluginPackageValidationConfig(m.cfg, m.pluginsRoot)
	candidate, err = registerPluginPackageCandidate(candidate, validationCfg)
	if err != nil {
		return LoadedPlugin{}, nil, nil, err
	}
	if err := checkPluginHostPrerequisites(candidate); err != nil {
		return LoadedPlugin{}, nil, nil, fmt.Errorf("plugin candidate host preflight failed: %w", err)
	}
	baseline := loadPluginCatalogWithControlRegistrationAndState(validationCfg, m.db)
	baselineStatus := make(map[string]string, len(baseline.Plugins))
	var previous *LoadedPlugin
	for i := range baseline.Plugins {
		plugin := baseline.Plugins[i]
		baselineStatus[plugin.ID] = plugin.Status
		if plugin.ID == candidate.ID {
			copyPlugin := plugin
			previous = &copyPlugin
		}
	}
	if previous != nil {
		if err := validatePluginActionContractUpgrade(*previous, candidate); err != nil {
			return LoadedPlugin{}, previous, nil, fmt.Errorf("plugin action contract is incompatible: %w", err)
		}
		if err := validatePluginEventContractUpgrade(*previous, candidate); err != nil {
			return LoadedPlugin{}, previous, nil, fmt.Errorf("plugin event contract is incompatible: %w", err)
		}
		if err := validatePluginServiceContractUpgrade(*previous, candidate); err != nil {
			return LoadedPlugin{}, previous, nil, fmt.Errorf("plugin service contract is incompatible: %w", err)
		}
	}
	if deferredRelationships {
		candidate.Enabled = true
		candidate.Status = pluginStatusActive
		candidate.Runtime = externalPluginRuntimeState()
		candidate.Error = ""
		candidate.resolutionError = false
		if err := checkPluginCompatibility(candidate, currentPluginHostEnvironment()); err != nil {
			return LoadedPlugin{}, previous, nil, fmt.Errorf("plugin candidate is incompatible: %w", err)
		}
		return candidate, previous, nil, nil
	}

	candidate.Enabled = true
	candidate.Status = pluginStatusActive
	candidate.Runtime = externalPluginRuntimeState()
	candidate.Error = ""
	candidate.resolutionError = false
	replaced := false
	for i := range baseline.Plugins {
		if baseline.Plugins[i].ID == candidate.ID {
			baseline.Plugins[i] = candidate
			replaced = true
			break
		}
	}
	if !replaced {
		baseline.Plugins = append(baseline.Plugins, candidate)
	}
	resolved := resolvePluginCatalogRelationships(baseline, currentPluginHostEnvironment())
	resolvedCandidate := relationshipPluginByIDValue(resolved, candidate.ID)
	if resolvedCandidate == nil || resolvedCandidate.Status != pluginStatusActive {
		if resolvedCandidate == nil {
			return LoadedPlugin{}, previous, nil, fmt.Errorf("plugin candidate disappeared during catalog validation")
		}
		return LoadedPlugin{}, previous, nil, fmt.Errorf("plugin candidate is incompatible: %s", resolvedCandidate.Error)
	}
	affected := make([]string, 0)
	for _, plugin := range resolved.Plugins {
		if plugin.Builtin || plugin.ID == candidate.ID {
			continue
		}
		before := baselineStatus[plugin.ID]
		if before != pluginStatusError && plugin.Status == pluginStatusError {
			return LoadedPlugin{}, previous, nil, fmt.Errorf("plugin candidate would make %s unavailable: %s", plugin.ID, plugin.Error)
		}
		if before == pluginStatusError && plugin.Status == pluginStatusActive {
			affected = append(affected, plugin.ID)
		}
	}
	sort.Strings(affected)
	return *resolvedCandidate, previous, affected, nil
}

func registerPluginPackageCandidate(plugin LoadedPlugin, cfg *Config) (LoadedPlugin, error) {
	if plugin.Control == nil || plugin.controlMainPath == "" {
		return plugin, nil
	}
	if ok, reason := pluginControlRegistrationAllowed(plugin); !ok {
		return LoadedPlugin{}, fmt.Errorf("plugin control registration is unavailable: %s", reason)
	}
	validationConfig := Config{}
	if cfg != nil {
		validationConfig = *cfg
	}
	enabled := true
	validationConfig.PluginsEnabledSetting = &enabled
	runtime, ok := newPluginControlRuntime(nil, &validationConfig, nil).(*gojaPluginControlRuntime)
	if !ok || runtime == nil {
		return LoadedPlugin{}, fmt.Errorf("plugin control runtime is unavailable")
	}
	defer runtime.Close()
	surface, err := runtime.runPluginControlWithSurface(plugin, pluginControlEvent{Kind: "register"}, true)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("register plugin candidate: %w", err)
	}
	applyPluginRuntimeSurface(&plugin, surface)
	if plugin.Status != pluginStatusActive {
		return LoadedPlugin{}, fmt.Errorf("validate plugin candidate surface: %s", plugin.Error)
	}
	return plugin, nil
}

func pluginPackageValidationConfig(cfg *Config, pluginsRoot string) *Config {
	copyConfig := Config{}
	if cfg != nil {
		copyConfig = *cfg
		copyConfig.KernelEngineOrder = append([]string(nil), cfg.KernelEngineOrder...)
		copyConfig.Tags = append([]string(nil), cfg.Tags...)
		if cfg.Experimental != nil {
			copyConfig.Experimental = make(map[string]bool, len(cfg.Experimental))
			for key, value := range cfg.Experimental {
				copyConfig.Experimental[key] = value
			}
		}
	}
	enabled := true
	copyConfig.PluginsEnabledSetting = &enabled
	copyConfig.PluginsDir = pluginsRoot
	return &copyConfig
}

func pluginRuntimeSurfaceFromLoaded(plugin LoadedPlugin) PluginRuntimeSurface {
	return PluginRuntimeSurface{
		Capabilities:       append([]string(nil), plugin.Capabilities...),
		VirtualInterfaces:  append([]PluginVirtualInterface(nil), plugin.VirtualInterfaces...),
		Objects:            append([]PluginObject(nil), plugin.Objects...),
		Hooks:              clonePluginHooks(plugin.Hooks),
		Resources:          append([]PluginResource(nil), plugin.Resources...),
		Actions:            append([]PluginAction(nil), plugin.Actions...),
		Services:           clonePluginServices(plugin.Services),
		EventSubscriptions: append([]PluginEventSubscription(nil), plugin.EventSubscriptions...),
		RingSubscriptions:  append([]PluginRingSubscription(nil), plugin.RingSubscriptions...),
		UI:                 clonePluginUI(plugin.UI),
	}
}

func pluginRuntimeSurfaceDigest(surface PluginRuntimeSurface) string {
	data, err := json.Marshal(surface)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func clonePluginCompatibility(value *PluginCompatibility) *PluginCompatibility {
	if value == nil {
		return nil
	}
	clone := *value
	clone.OS = append([]string(nil), value.OS...)
	clone.Architectures = append([]string(nil), value.Architectures...)
	clone.Features = append([]string(nil), value.Features...)
	return &clone
}

func pluginPrivilegeSummary(plugin LoadedPlugin) ([]string, string) {
	entries := make([]string, 0)
	if plugin.Control != nil {
		for _, permission := range plugin.Control.Permissions {
			entries = append(entries, "permission:"+permission)
		}
		for _, access := range plugin.Control.ResourceAccess {
			entries = append(entries, "resource:"+access.Plugin+"/"+access.Resource+":"+strings.Join(access.Methods, ","))
		}
		for _, access := range plugin.Control.ActionAccess {
			entries = append(entries, "action:"+access.Plugin+":"+strings.Join(access.Actions, ","))
		}
		for _, access := range plugin.Control.EventAccess {
			entries = append(entries, "event:"+access.Plugin+":"+strings.Join(access.TopicPrefixes, ","))
		}
		for _, access := range plugin.Control.NetAccess {
			data, _ := json.Marshal(access)
			entries = append(entries, "network:"+string(data))
		}
		for _, pattern := range plugin.Control.NamespaceAccess {
			entries = append(entries, "namespace:"+pattern)
		}
	}
	if plugin.UI != nil {
		for _, access := range plugin.UI.Resources {
			entries = append(entries, "ui-resource:"+access.Resource+":"+strings.Join(access.Methods, ","))
		}
		for _, action := range plugin.UI.Actions {
			entries = append(entries, "ui-action:"+action)
		}
		for _, access := range plugin.UI.ResourceAccess {
			entries = append(entries, "ui-cross-resource:"+access.Plugin+"/"+access.Resource+":"+strings.Join(access.Methods, ","))
		}
	}
	for _, object := range plugin.Objects {
		hash := object.ResolvedSHA256
		if hash == "" {
			hash = object.SHA256
		}
		surface, _ := json.Marshal(struct {
			Path      string                 `json:"path"`
			SHA256    string                 `json:"sha256"`
			Variants  []PluginObjectVariant  `json:"variants,omitempty"`
			Programs  []PluginObjectProgram  `json:"programs,omitempty"`
			StateMaps []PluginObjectStateMap `json:"state_maps,omitempty"`
		}{
			Path: object.Path, SHA256: hash, Variants: object.Variants,
			Programs: object.Programs, StateMaps: object.StateMaps,
		})
		entries = append(entries, "object:"+object.ID+":"+string(surface))
	}
	for _, hook := range plugin.Hooks {
		data, _ := json.Marshal(hook)
		entries = append(entries, "hook:"+string(data))
	}
	sort.Strings(entries)
	hash := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return entries, hex.EncodeToString(hash[:])
}

func pluginPackageExecutionTier(plugin LoadedPlugin) string {
	if len(plugin.Objects) > 0 || len(plugin.Hooks) > 0 {
		return pluginPackageExecutionTierDataplane
	}
	if plugin.Control != nil && (pluginControlHasPermission(plugin, "ebpf.load") || pluginControlHasPermission(plugin, "hook.attach")) {
		return pluginPackageExecutionTierDataplane
	}
	return pluginPackageExecutionTierControl
}

func pluginPackagePublisherState(signature pluginPackageVerifiedSignature, plugin LoadedPlugin) (bool, string) {
	if !signature.Signed {
		return false, pluginPackagePublisherNone
	}
	if signature.TrustKey == nil {
		return false, pluginPackagePublisherUnknown
	}
	if signature.TrustKey.Status == pluginTrustStatusRevoked {
		return false, pluginPackagePublisherRevoked
	}
	if err := validatePluginTrustKeyScope(*signature.TrustKey, plugin); err != nil {
		return false, pluginPackagePublisherScopeMismatch
	}
	return true, pluginPackagePublisherTrusted
}

func pluginPrivilegeAdditions(previous, candidate []string) []string {
	seen := make(map[string]struct{}, len(previous))
	for _, value := range previous {
		seen[value] = struct{}{}
	}
	additions := make([]string, 0)
	for _, value := range candidate {
		if _, exists := seen[value]; !exists {
			additions = append(additions, value)
		}
	}
	return additions
}

func relationshipPluginByIDValue(catalog PluginCatalog, id string) *LoadedPlugin {
	for i := range catalog.Plugins {
		if catalog.Plugins[i].ID == id {
			return &catalog.Plugins[i]
		}
	}
	return nil
}

func validatePluginPackageID(value string) error {
	if len(value) != 32 {
		return fmt.Errorf("invalid plugin package identifier")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("invalid plugin package identifier")
	}
	return nil
}

func (m *pluginPackageManager) cleanupExpiredStages(now time.Time) {
	root := filepath.Join(m.stateRoot, "staging")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || validatePluginPackageID(entry.Name()) != nil {
			continue
		}
		path := filepath.Join(root, entry.Name())
		var record pluginPackageStageRecord
		if err := readPluginPackageJSON(filepath.Join(path, pluginPackageStageMetadataFile), &record); err == nil {
			expiresAt, parseErr := time.Parse(time.RFC3339Nano, record.Stage.ExpiresAt)
			if parseErr == nil && now.Before(expiresAt) {
				continue
			}
		}
		_ = removePluginPackageManagedPath(m.stateRoot, path)
	}
}
