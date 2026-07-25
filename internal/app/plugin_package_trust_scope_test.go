package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginTrustScopeAllowsOnlyDeclaredPluginAndPermissions(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := manager.AddTrustKey(PluginTrustKeyRequest{
		Name: "Scoped Publisher", PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Scope: &PluginTrustScope{
			PluginIDs:      []string{"vendor_*"},
			Permissions:    []string{"plugin.register"},
			ExecutionTiers: []string{pluginPackageExecutionTierControl},
			Stabilities:    []string{pluginStabilityStable},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.Scope == nil || len(key.Scope.PluginIDs) != 1 || key.Scope.PluginIDs[0] != "vendor_*" {
		t.Fatalf("normalized trust scope = %+v", key.Scope)
	}

	allowed := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "vendor_router", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	stage, err := stageSignedPluginPackageForTrustScopeTest(t, manager, key, privateKey, allowed)
	if err != nil {
		t.Fatalf("stage allowed package: %v", err)
	}
	if !equalPluginTrustScopes(stage.SignerScope, key.Scope) {
		t.Fatalf("stage signer scope = %+v, want %+v", stage.SignerScope, key.Scope)
	}

	wrongID := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "other_router", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	assertPluginPackagePublisherScopeMismatch(t, manager, key, privateKey, wrongID)

	wrongPermission := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "vendor_router", Version: "1.1.0", Stability: pluginStabilityStable,
		Permissions: []string{"kv", "plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	assertPluginPackagePublisherScopeMismatch(t, manager, key, privateKey, wrongPermission)

	wrongStability := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "vendor_router", Version: "1.1.0", Stability: pluginStabilityPreview,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	assertPluginPackagePublisherScopeMismatch(t, manager, key, privateKey, wrongStability)
}

func TestPluginTrustScopeRejectsDataplaneTier(t *testing.T) {
	key := PluginTrustKey{ID: strings.Repeat("a", 32), Scope: &PluginTrustScope{
		ExecutionTiers: []string{pluginPackageExecutionTierControl},
	}}
	plugin := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "vendor_filter", Stability: pluginStabilityStable,
		Control: &PluginControl{Permissions: []string{"ebpf.load"}},
	}}
	if err := validatePluginTrustKeyScope(key, plugin); err == nil || !strings.Contains(err.Error(), "not authorized for dataplane execution tier") {
		t.Fatalf("dataplane scope error = %v", err)
	}
}

func TestPluginTrustKeyRotationInheritsAndCannotBroadenScope(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	oldPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := manager.AddTrustKey(PluginTrustKeyRequest{
		Name: "Old Scoped Publisher", PublicKey: base64.StdEncoding.EncodeToString(oldPublic),
		Scope: &PluginTrustScope{PluginIDs: []string{"vendor_*"}, Permissions: []string{"plugin.register"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	inheritedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inherited, err := manager.AddTrustKey(PluginTrustKeyRequest{
		Name: "Inherited Scope", PublicKey: base64.StdEncoding.EncodeToString(inheritedPublic), Replaces: oldKey.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !equalPluginTrustScopes(inherited.Scope, oldKey.Scope) {
		t.Fatalf("inherited scope = %+v, want %+v", inherited.Scope, oldKey.Scope)
	}

	broaderPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.AddTrustKey(PluginTrustKeyRequest{
		Name: "Broader Scope", PublicKey: base64.StdEncoding.EncodeToString(broaderPublic), Replaces: inherited.ID,
		Scope: &PluginTrustScope{Permissions: []string{"plugin.register"}},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be broader") {
		t.Fatalf("broader replacement scope error = %v", err)
	}

	narrowerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	narrower, err := manager.AddTrustKey(PluginTrustKeyRequest{
		Name: "Narrower Scope", PublicKey: base64.StdEncoding.EncodeToString(narrowerPublic), Replaces: inherited.ID,
		Scope: &PluginTrustScope{PluginIDs: []string{"vendor_router"}, Permissions: []string{"plugin.register"}},
	})
	if err != nil {
		t.Fatalf("narrow replacement scope: %v", err)
	}
	if narrower.Scope == nil || len(narrower.Scope.PluginIDs) != 1 || narrower.Scope.PluginIDs[0] != "vendor_router" {
		t.Fatalf("narrower scope = %+v", narrower.Scope)
	}
}

func TestPluginPackageStageUsesCurrentSignerScope(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := manager.AddTrustKey(PluginTrustKeyRequest{
		Name: "Mutable Publisher", PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Scope: &PluginTrustScope{PluginIDs: []string{"vendor_*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "vendor_router", Version: "1.0.0"})
	stage, err := stageSignedPluginPackageForTrustScopeTest(t, manager, key, privateKey, archive)
	if err != nil {
		t.Fatal(err)
	}
	key.Scope = &PluginTrustScope{PluginIDs: []string{"vendor_router"}}
	if err := writePluginPackageJSONAtomic(filepath.Join(manager.stateRoot, "trust", key.ID+".json"), key, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := manager.LoadStage(stage.ID)
	if err != nil {
		t.Fatalf("LoadStage() after scope update: %v", err)
	}
	if !loaded.Trusted || !equalPluginTrustScopes(loaded.SignerScope, key.Scope) {
		t.Fatalf("stage signer scope = %+v, want current %+v", loaded.SignerScope, key.Scope)
	}
}

func TestNormalizePluginTrustScopeRejectsEmptyAndInvalidValues(t *testing.T) {
	for _, scope := range []*PluginTrustScope{
		{},
		{PluginIDs: []string{"../escape"}},
		{PluginIDs: []string{"vendor_*_bad"}},
		{ExecutionTiers: []string{"native"}},
		{Stabilities: []string{"unstable"}},
	} {
		if _, err := normalizePluginTrustScope(scope); err == nil {
			t.Fatalf("normalizePluginTrustScope(%+v) succeeded", scope)
		}
	}
}

func stageSignedPluginPackageForTrustScopeTest(t testing.TB, manager *pluginPackageManager, key PluginTrustKey, privateKey ed25519.PrivateKey, archive []byte) (PluginPackageStage, error) {
	t.Helper()
	digest := sha256.Sum256(archive)
	signature := ed25519.Sign(privateKey, append([]byte(pluginPackageSignatureDomain), digest[:]...))
	return manager.Stage(bytes.NewReader(buildSignedPluginPackageForTest(t, archive, pluginPackageSignature{
		SignerID: key.ID, PublicKey: key.PublicKey, Signature: base64.StdEncoding.EncodeToString(signature),
	})))
}

func assertPluginPackagePublisherScopeMismatch(t *testing.T, manager *pluginPackageManager, key PluginTrustKey, privateKey ed25519.PrivateKey, archive []byte) {
	t.Helper()
	stage, err := stageSignedPluginPackageForTrustScopeTest(t, manager, key, privateKey, archive)
	if err != nil {
		t.Fatalf("stage scope-mismatched package: %v", err)
	}
	if !stage.Signed || stage.Trusted || stage.PublisherStatus != pluginPackagePublisherScopeMismatch {
		t.Fatalf("scope-mismatched stage = %+v", stage)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{
		StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest,
	}); err == nil || !strings.Contains(err.Error(), "approve_publisher") {
		t.Fatalf("scope-mismatched apply error = %v", err)
	}
}
