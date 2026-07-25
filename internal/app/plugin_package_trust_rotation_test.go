package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"
)

func TestPluginTrustRotationRevokesOldSigner(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := manager.AddTrustKey(PluginTrustKeyRequest{Name: "Old Publisher", PublicKey: base64.StdEncoding.EncodeToString(oldPublic)})
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := manager.AddTrustKey(PluginTrustKeyRequest{
		Name: "New Publisher", PublicKey: base64.StdEncoding.EncodeToString(newPublic), Replaces: oldKey.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := manager.ListTrustKeys()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]PluginTrustKey, len(keys))
	for _, key := range keys {
		byID[key.ID] = key
	}
	if byID[oldKey.ID].Status != pluginTrustStatusRevoked || byID[oldKey.ID].ReplacedBy != newKey.ID || byID[oldKey.ID].RevokedAt == "" {
		t.Fatalf("old trust key = %+v", byID[oldKey.ID])
	}
	if byID[newKey.ID].Status != pluginTrustStatusActive {
		t.Fatalf("new trust key = %+v", byID[newKey.ID])
	}

	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "rotated_signer", Version: "1.0.0"})
	digest := sha256.Sum256(archive)
	message := append([]byte(pluginPackageSignatureDomain), digest[:]...)
	oldSignature := base64.StdEncoding.EncodeToString(ed25519.Sign(oldPrivate, message))
	oldStage, err := manager.Stage(bytes.NewReader(buildSignedPluginPackageForTest(t, archive, pluginPackageSignature{
		SignerID: oldKey.ID, PublicKey: oldKey.PublicKey, Signature: oldSignature,
	})))
	if err != nil || oldStage.PublisherStatus != pluginPackagePublisherRevoked || oldStage.Trusted {
		t.Fatalf("revoked publisher stage = %+v, err=%v", oldStage, err)
	}
	newSignature := base64.StdEncoding.EncodeToString(ed25519.Sign(newPrivate, message))
	if _, err := manager.Stage(bytes.NewReader(buildSignedPluginPackageForTest(t, archive, pluginPackageSignature{
		SignerID: newKey.ID, PublicKey: newKey.PublicKey, Signature: newSignature,
	}))); err != nil {
		t.Fatalf("replacement signer stage: %v", err)
	}
	if _, err := manager.AddTrustKey(PluginTrustKeyRequest{Name: "Revive Old", PublicKey: oldKey.PublicKey}); err == nil {
		t.Fatal("revoked public key was re-added")
	}
}

func TestPluginTrustRotationJournalRecoversOnManagerStartup(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	oldPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := manager.AddTrustKey(PluginTrustKeyRequest{Name: "Old", PublicKey: base64.StdEncoding.EncodeToString(oldPublic)})
	if err != nil {
		t.Fatal(err)
	}
	newPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	newKey := PluginTrustKey{
		ID: pluginTrustKeyID(newPublic), Name: "New", PublicKey: base64.StdEncoding.EncodeToString(newPublic),
		Status: pluginTrustStatusActive, CreatedAt: now.Format(time.RFC3339Nano),
	}
	journal := pluginTrustRotationJournal{
		FormatVersion: pluginTrustRotationFormatVersion,
		ID:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OldKeyID: oldKey.ID, NewKey: newKey,
		CreatedAt: now.Format(time.RFC3339Nano), RevokedAt: now.Format(time.RFC3339Nano),
	}
	journalPath := filepath.Join(manager.stateRoot, "trust-rotations", journal.ID+".json")
	if err := writePluginPackageJSONAtomic(journalPath, journal, false); err != nil {
		t.Fatal(err)
	}

	recovered, err := newPluginPackageManager(manager.cfg, manager.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldRecovered, err := recovered.loadPluginTrustKey(oldKey.ID)
	if err != nil {
		t.Fatal(err)
	}
	newRecovered, err := recovered.loadPluginTrustKey(newKey.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldRecovered.Status != pluginTrustStatusRevoked || oldRecovered.ReplacedBy != newKey.ID || newRecovered.Status != pluginTrustStatusActive {
		t.Fatalf("recovered trust keys old=%+v new=%+v", oldRecovered, newRecovered)
	}
	if entries, err := filepath.Glob(filepath.Join(manager.stateRoot, "trust-rotations", "*.json")); err != nil || len(entries) != 0 {
		t.Fatalf("rotation journals = %+v, err=%v", entries, err)
	}
}
