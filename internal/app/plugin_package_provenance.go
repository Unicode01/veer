package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func pluginRepositoryProvenance(stage PluginPackageStage) *PluginPackageProvenance {
	if stage.RepositoryID == "" {
		return clonePluginPackageProvenance(stage.Provenance)
	}
	return &PluginPackageProvenance{
		FormatVersion: pluginRepositoryFormatVersion,
		PluginID:      stage.PluginID, Version: stage.Version, Source: "tuf",
		RepositoryID: stage.RepositoryID, RepositoryTarget: stage.RepositoryTarget,
		RepositoryChannel: stage.RepositoryChannel, RepositoryVersion: stage.RepositoryVersion,
		ArchiveSHA256: stage.ArchiveSHA256,
	}
}

func clonePluginPackageProvenance(value *PluginPackageProvenance) *PluginPackageProvenance {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func equalPluginPackageProvenance(left, right *PluginPackageProvenance) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validatePluginPackageProvenanceForPackage(value *PluginPackageProvenance, pluginID, version string) error {
	if value == nil {
		return nil
	}
	if err := validatePluginPackageProvenance(*value); err != nil {
		return err
	}
	if value.PluginID != pluginID || value.Version != version {
		return fmt.Errorf("plugin provenance package identity mismatch")
	}
	return nil
}

func validatePluginPackageProvenance(value PluginPackageProvenance) error {
	if value.FormatVersion != pluginRepositoryFormatVersion || value.Source != "tuf" {
		return fmt.Errorf("plugin provenance format is invalid")
	}
	if !pluginIDPattern.MatchString(value.PluginID) || reservedBuiltinPluginID(value.PluginID) {
		return fmt.Errorf("plugin provenance plugin id is invalid")
	}
	version, err := normalizePluginSemanticVersion(value.Version)
	if err != nil || version != value.Version {
		return fmt.Errorf("plugin provenance version is invalid")
	}
	if !pluginIDPattern.MatchString(value.RepositoryID) || !validPluginRepositoryTargetPath(value.RepositoryTarget) {
		return fmt.Errorf("plugin provenance repository identity is invalid")
	}
	if _, err := normalizePluginRepositoryChannel(value.RepositoryChannel); err != nil {
		return fmt.Errorf("plugin provenance repository channel is invalid")
	}
	if value.RepositoryVersion < 1 || len(value.ArchiveSHA256) != sha256.Size*2 {
		return fmt.Errorf("plugin provenance repository version or archive digest is invalid")
	}
	if _, err := hex.DecodeString(value.ArchiveSHA256); err != nil {
		return fmt.Errorf("plugin provenance archive digest is invalid")
	}
	if value.AppliedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, value.AppliedAt); err != nil {
			return fmt.Errorf("plugin provenance apply time is invalid")
		}
	}
	return nil
}

func (m *pluginPackageManager) loadPluginPackageProvenance(pluginID string) (*PluginPackageProvenance, error) {
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return nil, fmt.Errorf("plugin provenance id is invalid")
	}
	var value PluginPackageProvenance
	err := readPluginPackageJSON(filepath.Join(m.stateRoot, "provenance", pluginID+".json"), &value)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if value.PluginID != pluginID {
		return nil, fmt.Errorf("plugin provenance identity mismatch")
	}
	if err := validatePluginPackageProvenance(value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (m *pluginPackageManager) applyPluginPackageProvenance(pluginID string, value *PluginPackageProvenance, appliedAt string) error {
	path := filepath.Join(m.stateRoot, "provenance", pluginID+".json")
	if value == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	copyValue := *value
	copyValue.PluginID = pluginID
	if strings.TrimSpace(copyValue.AppliedAt) == "" {
		copyValue.AppliedAt = appliedAt
	}
	if err := validatePluginPackageProvenance(copyValue); err != nil {
		return err
	}
	return writePluginPackageJSONAtomic(path, copyValue, true)
}

func (m *pluginPackageManager) applyPluginPackageTransactionProvenance(tx pluginPackageTransaction) error {
	return m.applyPluginPackageProvenance(tx.PluginID, tx.CandidateProvenance, tx.CreatedAt)
}

func (m *pluginPackageManager) restorePluginPackageTransactionProvenance(tx pluginPackageTransaction) error {
	return m.applyPluginPackageProvenance(tx.PluginID, tx.PreviousProvenance, tx.CreatedAt)
}

func (m *pluginPackageManager) applyPluginPackageBatchProvenance(tx pluginPackageBatchTransaction, candidate bool) error {
	for _, item := range tx.Items {
		value := item.PreviousProvenance
		if candidate {
			value = item.CandidateProvenance
		}
		if err := m.applyPluginPackageProvenance(item.PluginID, value, tx.CreatedAt); err != nil {
			return fmt.Errorf("apply plugin %s provenance: %w", item.PluginID, err)
		}
	}
	return nil
}

func (m *pluginPackageManager) ListPluginPackageProvenance() ([]PluginPackageProvenanceStatus, error) {
	entries, err := os.ReadDir(filepath.Join(m.stateRoot, "provenance"))
	if err != nil {
		return nil, err
	}
	out := make([]PluginPackageProvenanceStatus, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("plugin provenance directory contains unexpected entry %s", entry.Name())
		}
		pluginID := strings.TrimSuffix(entry.Name(), ".json")
		value, err := m.loadPluginPackageProvenance(pluginID)
		if err != nil {
			return nil, err
		}
		if value == nil {
			continue
		}
		status := PluginPackageProvenanceStatus{PluginPackageProvenance: *value, Status: "trusted"}
		repository, err := m.loadPluginRepository(value.RepositoryID)
		if err != nil {
			status.Status = "repository_unavailable"
			out = append(out, status)
			continue
		}
		catalog, err := m.LoadRepositoryCatalog(repository.ID)
		if err != nil {
			status.Status = "metadata_unavailable"
			out = append(out, status)
			continue
		}
		status.Status = "target_unavailable"
		for _, target := range catalog.Targets {
			if target.Target != value.RepositoryTarget || target.PluginID != value.PluginID || target.Version != value.Version || target.SHA256 != value.ArchiveSHA256 {
				continue
			}
			if target.Revoked {
				status.Status = "revoked"
				status.RevocationReason = target.RevocationReason
			} else {
				status.Status = "trusted"
			}
			break
		}
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out, nil
}
