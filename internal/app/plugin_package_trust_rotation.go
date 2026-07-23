package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const pluginTrustRotationFormatVersion = 1

type pluginTrustRotationJournal struct {
	FormatVersion int            `json:"format_version"`
	ID            string         `json:"id"`
	OldKeyID      string         `json:"old_key_id"`
	NewKey        PluginTrustKey `json:"new_key"`
	CreatedAt     string         `json:"created_at"`
	RevokedAt     string         `json:"revoked_at"`
}

func (m *pluginPackageManager) rotatePluginTrustKey(oldKeyID string, newKey PluginTrustKey) error {
	oldKeyID = strings.TrimSpace(strings.ToLower(oldKeyID))
	oldKey, err := m.loadPluginTrustKey(oldKeyID)
	if err != nil {
		return err
	}
	if oldKey.Status != pluginTrustStatusActive {
		return fmt.Errorf("trust key %s is not active", oldKeyID)
	}
	if newKey.Status != pluginTrustStatusActive || newKey.ID == oldKeyID {
		return fmt.Errorf("replacement trust key is invalid")
	}
	id, err := newPluginPackageID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	journal := pluginTrustRotationJournal{
		FormatVersion: pluginTrustRotationFormatVersion,
		ID:            id, OldKeyID: oldKeyID, NewKey: newKey,
		CreatedAt: now.Format(time.RFC3339Nano), RevokedAt: now.Format(time.RFC3339Nano),
	}
	journalPath := filepath.Join(m.stateRoot, "trust-rotations", id+".json")
	if err := writePluginPackageJSONAtomic(journalPath, journal, false); err != nil {
		return err
	}
	return m.completePluginTrustRotation(journalPath, journal)
}

func (m *pluginPackageManager) recoverPluginTrustRotations() error {
	root := filepath.Join(m.stateRoot, "trust-rotations")
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return fmt.Errorf("plugin trust rotation directory contains unexpected entry %s", entry.Name())
		}
		path := filepath.Join(root, entry.Name())
		var journal pluginTrustRotationJournal
		if err := readPluginPackageJSON(path, &journal); err != nil {
			return err
		}
		if entry.Name() != journal.ID+".json" {
			return fmt.Errorf("plugin trust rotation journal identity mismatch")
		}
		if err := m.completePluginTrustRotation(path, journal); err != nil {
			return err
		}
		recordPluginAudit(m.db, "", "trust.rotate_recovered", "system", "success", map[string]any{
			"old_key_id": journal.OldKeyID, "new_key_id": journal.NewKey.ID,
		})
	}
	return nil
}

func (m *pluginPackageManager) completePluginTrustRotation(journalPath string, journal pluginTrustRotationJournal) error {
	if err := validatePluginTrustRotationJournal(journal); err != nil {
		return err
	}
	newPath := filepath.Join(m.stateRoot, "trust", journal.NewKey.ID+".json")
	if existing, err := m.loadPluginTrustKey(journal.NewKey.ID); err == nil {
		if !equalPluginTrustKeys(existing, journal.NewKey) {
			return fmt.Errorf("replacement trust key %s does not match its rotation journal", journal.NewKey.ID)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := writePluginPackageJSONAtomic(newPath, journal.NewKey, false); err != nil {
		return err
	}

	oldKey, err := m.loadPluginTrustKey(journal.OldKeyID)
	if err != nil {
		return err
	}
	switch oldKey.Status {
	case pluginTrustStatusActive:
		oldKey.Status = pluginTrustStatusRevoked
		oldKey.RevokedAt = journal.RevokedAt
		oldKey.ReplacedBy = journal.NewKey.ID
		if err := writePluginPackageJSONAtomic(filepath.Join(m.stateRoot, "trust", oldKey.ID+".json"), oldKey, true); err != nil {
			return err
		}
	case pluginTrustStatusRevoked:
		if oldKey.ReplacedBy != journal.NewKey.ID || oldKey.RevokedAt != journal.RevokedAt {
			return fmt.Errorf("revoked trust key %s does not match its rotation journal", oldKey.ID)
		}
	default:
		return fmt.Errorf("trust key %s has invalid status", oldKey.ID)
	}
	return os.Remove(journalPath)
}

func validatePluginTrustRotationJournal(journal pluginTrustRotationJournal) error {
	if journal.FormatVersion != pluginTrustRotationFormatVersion || !validPluginPackageID(journal.ID) {
		return fmt.Errorf("plugin trust rotation journal is invalid")
	}
	if !validPluginPackageID(journal.OldKeyID) || journal.OldKeyID == journal.NewKey.ID {
		return fmt.Errorf("plugin trust rotation key identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, journal.CreatedAt); err != nil {
		return fmt.Errorf("plugin trust rotation creation time is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, journal.RevokedAt); err != nil {
		return fmt.Errorf("plugin trust rotation revocation time is invalid")
	}
	if err := validatePluginTrustKeyState(journal.NewKey); err != nil || journal.NewKey.Status != pluginTrustStatusActive {
		return fmt.Errorf("plugin trust rotation replacement key is invalid")
	}
	publicKey, err := decodePluginTrustPublicKey(journal.NewKey.PublicKey)
	if err != nil || pluginTrustKeyID(publicKey) != journal.NewKey.ID {
		return fmt.Errorf("plugin trust rotation replacement key failed integrity validation")
	}
	return nil
}

func (m *pluginPackageManager) loadPluginTrustKey(id string) (PluginTrustKey, error) {
	id = strings.TrimSpace(strings.ToLower(id))
	if len(id) != 32 {
		return PluginTrustKey{}, fmt.Errorf("invalid trust key id")
	}
	path := filepath.Join(m.stateRoot, "trust", id+".json")
	var key PluginTrustKey
	if err := readPluginPackageJSON(path, &key); err != nil {
		return PluginTrustKey{}, err
	}
	if key.Status == "" {
		key.Status = pluginTrustStatusActive
	}
	publicKey, err := decodePluginTrustPublicKey(key.PublicKey)
	if err != nil || pluginTrustKeyID(publicKey) != id || key.ID != id {
		return PluginTrustKey{}, fmt.Errorf("trust key %s failed integrity validation", id)
	}
	if err := validatePluginTrustKeyState(key); err != nil {
		return PluginTrustKey{}, err
	}
	return key, nil
}

func equalPluginTrustKeys(left, right PluginTrustKey) bool {
	return left.ID == right.ID && left.Name == right.Name && left.PublicKey == right.PublicKey &&
		left.Status == right.Status && left.CreatedAt == right.CreatedAt &&
		left.RevokedAt == right.RevokedAt && left.ReplacedBy == right.ReplacedBy &&
		equalPluginTrustScopes(left.Scope, right.Scope)
}
