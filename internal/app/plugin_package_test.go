package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/kernelcap"
	"github.com/Unicode01/veer/internal/store"
)

func TestPluginPackageStageRejectsUnavailableRequiredHostFeature(t *testing.T) {
	original := detectPluginHostKernelCapabilities
	t.Cleanup(func() { detectPluginHostKernelCapabilities = original })
	detectPluginHostKernelCapabilities = func() kernelcap.KernelCapabilities {
		return kernelcap.KernelCapabilities{
			OS: "linux",
			TC: kernelcap.CapabilityCheck{Reason: "test TC attach unavailable"},
		}
	}
	manager := newPluginPackageManagerForTest(t)
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID:      "needs_tc",
		Version: "1.0.0",
		Compatibility: &PluginCompatibility{
			Features: []string{"dataplane.tc_pipeline.v2"},
		},
	})
	if _, err := manager.Stage(bytes.NewReader(archive), "", ""); err == nil ||
		!strings.Contains(err.Error(), "plugin candidate host preflight failed") ||
		!strings.Contains(err.Error(), "test TC attach unavailable") {
		t.Fatalf("Stage() host preflight error = %v", err)
	}
}

func TestPluginPackageUnsignedInstallAndPrivilegeApproval(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID:          "managed_plugin",
		Version:     "1.0.0",
		Permissions: []string{"kv", "plugin.register"},
		Control:     `exports.onReconcile = function () {};`,
	})
	stage, err := manager.Stage(bytes.NewReader(archive), "", "")
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if stage.Trusted || stage.Signed || len(stage.PrivilegeAdditions) == 0 {
		t.Fatalf("stage trust/privileges = %+v", stage)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest}); err == nil || !strings.Contains(err.Error(), "allow_unsigned") {
		t.Fatalf("ApplyStage(unsigned) error = %v", err)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true}); err == nil || !strings.Contains(err.Error(), "approval digest") {
		t.Fatalf("ApplyStage(unapproved) error = %v", err)
	}
	result, err := manager.ApplyStage(PluginPackageApplyRequest{
		StageID:                 stage.ID,
		ApprovedPrivilegeDigest: stage.PrivilegeDigest,
		AllowUnsigned:           true,
	})
	if err != nil {
		t.Fatalf("ApplyStage() error = %v", err)
	}
	if result.PluginID != "managed_plugin" || result.Version != "1.0.0" || result.Operation != "install" {
		t.Fatalf("install result = %+v", result)
	}
	plugin, err := manager.loadCurrentPlugin("managed_plugin")
	if err != nil || plugin == nil || plugin.Version != "1.0.0" {
		t.Fatalf("installed plugin = %+v, err=%v", plugin, err)
	}
}

func TestPluginPackageDataplaneAlwaysRequiresTrustedPublisher(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "unsigned_dataplane", Version: "1.0.0",
		Permissions: []string{"ebpf.load", "plugin.register"},
		Control:     `exports.onReconcile = function () {};`,
	})
	stage, err := manager.Stage(bytes.NewReader(archive), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if stage.ExecutionTier != pluginPackageExecutionTierDataplane || !stage.RequiresTrustedPublisher {
		t.Fatalf("dataplane stage trust classification = %+v", stage)
	}
	_, err = manager.ApplyStage(PluginPackageApplyRequest{
		StageID: stage.ID, AllowUnsigned: true, ApprovedPrivilegeDigest: stage.PrivilegeDigest,
	})
	if err == nil || !strings.Contains(err.Error(), "trusted publisher or TUF repository") {
		t.Fatalf("unsigned dataplane apply error = %v", err)
	}
}

func TestPluginPackageTrustedDataplaneCanBeInstalled(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustKey, err := manager.AddTrustKey(PluginTrustKeyRequest{Name: "Dataplane Publisher", PublicKey: base64.StdEncoding.EncodeToString(publicKey)})
	if err != nil {
		t.Fatal(err)
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "trusted_dataplane", Version: "1.0.0",
		Permissions: []string{"ebpf.load", "plugin.register"},
		Control:     `exports.onReconcile = function () {};`,
	})
	digest := sha256.Sum256(archive)
	signature := ed25519.Sign(privateKey, append([]byte(pluginPackageSignatureDomain), digest[:]...))
	stage, err := manager.Stage(bytes.NewReader(archive), trustKey.ID, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		t.Fatal(err)
	}
	if !stage.Trusted || stage.ExecutionTier != pluginPackageExecutionTierDataplane || !stage.RequiresTrustedPublisher {
		t.Fatalf("trusted dataplane stage = %+v", stage)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{
		StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest,
	}); err != nil {
		t.Fatalf("apply trusted dataplane package: %v", err)
	}
}

func TestPluginPackageStageRequiresSchemaVersionForActionContractChanges(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	control := func(version int, valueType string) string {
		return fmt.Sprintf(`
plugin.action({
  id: 'lookup',
  runtime_update: 'runtime_query',
  request_schema_version: %d,
  request_schema: {
    type: 'object',
    properties: {value: {type: %q}}
  }
});
exports.onAction = function (ctx) { return ctx.payload; };
`, version, valueType)
	}
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "schema_upgrade", Version: "1.0.0", Permissions: []string{"plugin.register"}, Control: control(1, "integer"),
	}))

	_, err := manager.Stage(bytes.NewReader(buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "schema_upgrade", Version: "1.1.0", Permissions: []string{"plugin.register"}, Control: control(1, "string"),
	})), "", "")
	if err == nil || !strings.Contains(err.Error(), "schema changed without increasing schema_version 1") {
		t.Fatalf("same-version action contract stage error = %v", err)
	}

	stage, err := manager.Stage(bytes.NewReader(buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "schema_upgrade", Version: "1.1.0", Permissions: []string{"plugin.register"}, Control: control(2, "string"),
	})), "", "")
	if err != nil {
		t.Fatalf("versioned action contract stage: %v", err)
	}
	if got := stage.RuntimeSurface.Actions[0].RequestSchemaVersion; got != 2 {
		t.Fatalf("staged request schema_version = %d, want 2", got)
	}
}

func TestPluginPackageStageRequiresServiceVersionForEndpointContractChanges(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	control := func(serviceVersion string, maxPayload int) string {
		return fmt.Sprintf(`
plugin.action({id:'apply', runtime_update:'runtime_apply', max_payload_bytes:%d});
plugin.service({id:'wan.adapter', version:%q, actions:['apply']});
exports.onAction = function () {};
`, maxPayload, serviceVersion)
	}
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "service_upgrade", Version: "1.0.0", Permissions: []string{"plugin.register"}, Control: control("1.0.0", 1024),
	}))

	_, err := manager.Stage(bytes.NewReader(buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "service_upgrade", Version: "1.1.0", Permissions: []string{"plugin.register"}, Control: control("1.0.0", 2048),
	})), "", "")
	if err == nil || !strings.Contains(err.Error(), "contract changed without increasing service version 1.0.0") {
		t.Fatalf("same-version service contract stage error = %v", err)
	}

	stage, err := manager.Stage(bytes.NewReader(buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "service_upgrade", Version: "1.1.0", Permissions: []string{"plugin.register"}, Control: control("1.1.0", 2048),
	})), "", "")
	if err != nil {
		t.Fatalf("versioned service contract stage: %v", err)
	}
	if got := stage.RuntimeSurface.Services; len(got) != 1 || got[0].Version != "1.1.0" {
		t.Fatalf("staged services = %+v", got)
	}
}

func TestPluginPackageManagerRejectsUnsignedPackageByPolicy(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	requireSigned := true
	manager.cfg.PluginsRequireSigned = &requireSigned
	stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "unsigned_policy", Version: "1.0.0",
	}))
	_, err := manager.ApplyStage(PluginPackageApplyRequest{
		StageID:       stage.ID,
		AllowUnsigned: true,
	})
	if err == nil || !strings.Contains(err.Error(), "plugins_require_signed_packages") {
		t.Fatalf("unsigned policy error = %v", err)
	}
}

func TestPluginPackageSignedInstallUsesTrustStore(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustKey, err := manager.AddTrustKey(PluginTrustKeyRequest{Name: "Test Publisher", PublicKey: base64.StdEncoding.EncodeToString(publicKey)})
	if err != nil {
		t.Fatalf("AddTrustKey() error = %v", err)
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "signed_plugin", Version: "1.0.0"})
	digest := sha256.Sum256(archive)
	message := append([]byte(pluginPackageSignatureDomain), digest[:]...)
	signature := ed25519.Sign(privateKey, message)
	stage, err := manager.Stage(bytes.NewReader(archive), trustKey.ID, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		t.Fatalf("Stage(signed) error = %v", err)
	}
	if !stage.Trusted || !stage.Signed || stage.SignerID != trustKey.ID {
		t.Fatalf("signed stage = %+v", stage)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID}); err != nil {
		t.Fatalf("ApplyStage(signed) error = %v", err)
	}

	badSignature := append([]byte(nil), signature...)
	badSignature[0] ^= 0xff
	if _, err := manager.Stage(bytes.NewReader(archive), trustKey.ID, base64.StdEncoding.EncodeToString(badSignature)); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("Stage(bad signature) error = %v", err)
	}
	keys, err := manager.ListTrustKeys()
	if err != nil || len(keys) != 1 || keys[0].ID != trustKey.ID {
		t.Fatalf("ListTrustKeys() = %+v, err=%v", keys, err)
	}
}

func TestPluginPackageUpdateFailureRestoresSourceAndRuntime(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	runtimeCalls := 0
	failRuntime := false
	manager.runtimeApply = func(pluginID string) (bool, error) {
		runtimeCalls++
		if pluginID != "rollback_plugin" {
			t.Fatalf("runtime plugin id = %q", pluginID)
		}
		if failRuntime {
			failRuntime = false
			return false, errors.New("injected runtime failure")
		}
		return true, nil
	}
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "rollback_plugin", Version: "1.0.0"}))
	stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "rollback_plugin", Version: "2.0.0"}))
	failRuntime = true
	_, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
	if err == nil || !strings.Contains(err.Error(), "injected runtime failure") {
		t.Fatalf("ApplyStage(failing update) error = %v", err)
	}
	plugin, loadErr := manager.loadCurrentPlugin("rollback_plugin")
	if loadErr != nil || plugin == nil || plugin.Version != "1.0.0" {
		t.Fatalf("plugin after failed update = %+v, err=%v", plugin, loadErr)
	}
	if runtimeCalls != 3 {
		t.Fatalf("runtime calls = %d, want install + failed update + restore", runtimeCalls)
	}
	transactions, err := os.ReadDir(filepath.Join(manager.stateRoot, "transactions"))
	if err != nil || len(transactions) != 0 {
		t.Fatalf("transactions after rollback = %+v, err=%v", transactions, err)
	}
}

func TestPluginPackageBatchAppliesDependentUpdatesAtomically(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "batch_dependency", Version: "1.0.0"}))
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "batch_consumer", Version: "1.0.0", Dependencies: []PluginDependency{{ID: "batch_dependency", Version: ">=1.0.0 <2.0.0"}},
	}))

	dependency := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "batch_dependency", Version: "2.0.0"}))
	consumer := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "batch_consumer", Version: "2.0.0", Dependencies: []PluginDependency{{ID: "batch_dependency", Version: ">=2.0.0 <3.0.0"}},
	}))
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: dependency.ID, AllowUnsigned: true}); err == nil || !strings.Contains(err.Error(), "part of a batch") {
		t.Fatalf("ApplyStage(deferred) error = %v", err)
	}
	if _, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: []PluginPackageApplyRequest{{StageID: dependency.ID, AllowUnsigned: true}}}); err == nil || !strings.Contains(err.Error(), "batch_consumer") {
		t.Fatalf("ApplyBatch(incomplete dependency update) error = %v", err)
	}

	runtimeCalls := 0
	manager.runtimeApplyBatch = func(pluginIDs []string) (bool, error) {
		runtimeCalls++
		if strings.Join(pluginIDs, ",") != "batch_consumer,batch_dependency" {
			t.Fatalf("batch runtime plugin ids = %v", pluginIDs)
		}
		return true, nil
	}
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: []PluginPackageApplyRequest{
		{StageID: dependency.ID, AllowUnsigned: true},
		{StageID: consumer.ID, AllowUnsigned: true},
	}})
	if err != nil {
		t.Fatalf("ApplyBatch() error = %v", err)
	}
	if result.Operation != "batch_apply" || len(result.Plugins) != 2 || runtimeCalls != 1 {
		t.Fatalf("batch result = %+v, runtime calls = %d", result, runtimeCalls)
	}
	for _, pluginID := range []string{"batch_consumer", "batch_dependency"} {
		plugin, err := manager.loadCurrentPlugin(pluginID)
		if err != nil || plugin == nil || plugin.Version != "2.0.0" {
			t.Fatalf("plugin %s after batch = %+v, err=%v", pluginID, plugin, err)
		}
		history, err := manager.ListHistory(pluginID)
		if err != nil || len(history) != 1 || history[0].Version != "1.0.0" {
			t.Fatalf("plugin %s history = %+v, err=%v", pluginID, history, err)
		}
	}
	if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "batches")); err != nil || len(entries) != 0 {
		t.Fatalf("batch transactions after apply = %+v, err=%v", entries, err)
	}
}

func TestPluginPackageBatchProbationRecoversDependencyGroupAtomically(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_dependency", Version: "1.0.0"}))
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "group_consumer", Version: "1.0.0", Dependencies: []PluginDependency{{ID: "group_dependency", Version: ">=1.0.0 <2.0.0"}},
	}))
	manager.suppressProbation = false
	dependency := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_dependency", Version: "2.0.0"}))
	consumer := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "group_consumer", Version: "2.0.0", Dependencies: []PluginDependency{{ID: "group_dependency", Version: ">=2.0.0 <3.0.0"}},
	}))
	runtimeCalls := 0
	manager.runtimeApplyBatch = func(pluginIDs []string) (bool, error) {
		runtimeCalls++
		if strings.Join(pluginIDs, ",") != "group_consumer,group_dependency" {
			t.Fatalf("runtime plugin ids = %v", pluginIDs)
		}
		return true, nil
	}
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: []PluginPackageApplyRequest{
		{StageID: dependency.ID, AllowUnsigned: true}, {StageID: consumer.ID, AllowUnsigned: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Plugins) != 2 || result.Plugins[0].Probation == nil || result.Plugins[1].Probation == nil {
		t.Fatalf("batch probations = %+v", result.Plugins)
	}
	groupID := result.Plugins[0].Probation.GroupID
	if groupID == "" || result.Plugins[1].Probation.GroupID != groupID || groupID != result.ID {
		t.Fatalf("probation group ids = %q / %q, batch=%q", groupID, result.Plugins[1].Probation.GroupID, result.ID)
	}
	group, err := manager.loadPluginPackageProbationGroup(groupID)
	if err != nil || len(group.Members) != 2 {
		t.Fatalf("probation group = %+v, err=%v", group, err)
	}
	if _, err := manager.recoverPluginPackageProbation(*result.Plugins[0].Probation, "injected grouped runtime failure", "test"); err != nil {
		t.Fatalf("recoverPluginPackageProbation(group) error = %v", err)
	}
	if runtimeCalls != 2 {
		t.Fatalf("runtime calls = %d, want batch apply plus grouped recovery", runtimeCalls)
	}
	for _, pluginID := range []string{"group_consumer", "group_dependency"} {
		plugin, err := manager.loadCurrentPlugin(pluginID)
		if err != nil || plugin == nil || plugin.Version != "1.0.0" {
			t.Fatalf("plugin %s after grouped recovery = %+v, err=%v", pluginID, plugin, err)
		}
		if _, err := manager.loadPluginPackageProbation(pluginID); !os.IsNotExist(err) {
			t.Fatalf("probation %s after grouped recovery error = %v", pluginID, err)
		}
	}
	if _, err := manager.loadPluginPackageProbationGroup(groupID); !os.IsNotExist(err) {
		t.Fatalf("probation group after recovery error = %v", err)
	}
}

func TestPluginPackageBatchProbationRemovesNewInstallsDuringRecovery(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_existing", Version: "1.0.0"}))
	manager.suppressProbation = false
	existing := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_existing", Version: "2.0.0"}))
	added := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_added", Version: "1.0.0"}))
	manager.runtimeApplyBatch = func([]string) (bool, error) { return true, nil }
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: []PluginPackageApplyRequest{
		{StageID: existing.ID, AllowUnsigned: true}, {StageID: added.ID, AllowUnsigned: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.recoverPluginPackageProbation(*result.Plugins[0].Probation, "injected install group failure", "test"); err != nil {
		t.Fatal(err)
	}
	plugin, err := manager.loadCurrentPlugin("group_existing")
	if err != nil || plugin == nil || plugin.Version != "1.0.0" {
		t.Fatalf("existing plugin after recovery = %+v, err=%v", plugin, err)
	}
	addedPlugin, err := manager.loadCurrentPlugin("group_added")
	if err != nil || addedPlugin != nil {
		t.Fatalf("new plugin after recovery = %+v, err=%v; want removed", addedPlugin, err)
	}
	history, err := manager.ListHistory("group_added")
	if err != nil || len(history) != 1 || history[0].Version != "1.0.0" {
		t.Fatalf("removed plugin history = %+v, err=%v", history, err)
	}
}

func TestPluginPackageBatchProbationRecoveryFailureKeepsWholeCandidateGroup(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	for _, pluginID := range []string{"group_retry_a", "group_retry_b"} {
		installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "1.0.0"}))
	}
	manager.suppressProbation = false
	requests := make([]PluginPackageApplyRequest, 0, 2)
	for _, pluginID := range []string{"group_retry_a", "group_retry_b"} {
		stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "2.0.0"}))
		requests = append(requests, PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
	}
	runtimeCalls := 0
	manager.runtimeApplyBatch = func([]string) (bool, error) {
		runtimeCalls++
		if runtimeCalls == 2 {
			return false, errors.New("injected grouped recovery failure")
		}
		return true, nil
	}
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: requests})
	if err != nil {
		t.Fatal(err)
	}
	record := *result.Plugins[0].Probation
	if _, err := manager.recoverPluginPackageProbation(record, "fatal group failure", "test"); err == nil || !strings.Contains(err.Error(), "injected grouped recovery failure") {
		t.Fatalf("first grouped recovery error = %v", err)
	}
	if runtimeCalls != 3 {
		t.Fatalf("runtime calls after failed recovery = %d, want apply/fail/restore", runtimeCalls)
	}
	for _, pluginID := range []string{"group_retry_a", "group_retry_b"} {
		plugin, err := manager.loadCurrentPlugin(pluginID)
		if err != nil || plugin == nil || plugin.Version != "2.0.0" {
			t.Fatalf("plugin %s after failed recovery = %+v, err=%v", pluginID, plugin, err)
		}
		probation, err := manager.loadPluginPackageProbation(pluginID)
		if err != nil || probation.RecoveryAttempts != 1 || probation.NextRecoveryAt == "" {
			t.Fatalf("plugin %s retry probation = %+v, err=%v", pluginID, probation, err)
		}
	}
	group, err := manager.loadPluginPackageProbationGroup(record.GroupID)
	if err != nil || group.RecoveryAttempts != 1 || group.NextRecoveryAt == "" {
		t.Fatalf("retry group = %+v, err=%v", group, err)
	}
	if _, err := manager.recoverPluginPackageProbation(record, "fatal group failure", "test"); err != nil {
		t.Fatalf("retry grouped recovery error = %v", err)
	}
	for _, pluginID := range []string{"group_retry_a", "group_retry_b"} {
		plugin, err := manager.loadCurrentPlugin(pluginID)
		if err != nil || plugin == nil || plugin.Version != "1.0.0" {
			t.Fatalf("plugin %s after retry = %+v, err=%v", pluginID, plugin, err)
		}
	}
}

func TestPluginPackageBatchProbationRecoveryJournalCompletesAfterRestart(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	for _, pluginID := range []string{"group_crash_a", "group_crash_b"} {
		installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "1.0.0"}))
	}
	manager.suppressProbation = false
	requests := make([]PluginPackageApplyRequest, 0, 2)
	for _, pluginID := range []string{"group_crash_a", "group_crash_b"} {
		stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "2.0.0"}))
		requests = append(requests, PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
	}
	manager.runtimeApplyBatch = func([]string) (bool, error) { return true, nil }
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: requests})
	if err != nil {
		t.Fatal(err)
	}
	manager.batchFault = func(point string) error {
		if point == "journal."+pluginPackageBatchPhaseRuntimeApplied {
			return errors.New("injected recovery journal crash")
		}
		return nil
	}
	if _, err := manager.recoverPluginPackageProbation(*result.Plugins[0].Probation, "fatal group failure", "test"); err == nil || !strings.Contains(err.Error(), "injected recovery journal crash") {
		t.Fatalf("group recovery crash error = %v", err)
	}
	manager.batchFault = nil
	if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "batches")); err != nil || len(entries) != 1 {
		t.Fatalf("pending recovery batch = %+v, err=%v", entries, err)
	}
	if err := manager.recoverBatchTransactions(); err != nil {
		t.Fatalf("recoverBatchTransactions() error = %v", err)
	}
	for _, pluginID := range []string{"group_crash_a", "group_crash_b"} {
		plugin, err := manager.loadCurrentPlugin(pluginID)
		if err != nil || plugin == nil || plugin.Version != "1.0.0" {
			t.Fatalf("plugin %s after journal recovery = %+v, err=%v", pluginID, plugin, err)
		}
	}
	if _, err := manager.loadPluginPackageProbationGroup(result.ID); !os.IsNotExist(err) {
		t.Fatalf("probation group after journal recovery error = %v", err)
	}
}

func TestPluginPackageProbationGroupBlocksMemberMutation(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_locked", Version: "1.0.0"}))
	manager.suppressProbation = false
	stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_locked", Version: "2.0.0"}))
	manager.runtimeApplyBatch = func([]string) (bool, error) { return true, nil }
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: []PluginPackageApplyRequest{{StageID: stage.ID, AllowUnsigned: true}}})
	if err != nil || result.Plugins[0].Probation == nil {
		t.Fatalf("batch result = %+v, err=%v", result, err)
	}
	next := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "group_locked", Version: "3.0.0"}))
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: next.ID, AllowUnsigned: true}); err == nil || !strings.Contains(err.Error(), "probation group") {
		t.Fatalf("ApplyStage(group member) error = %v", err)
	}
	if _, err := manager.Uninstall(PluginPackageUninstallRequest{PluginID: "group_locked"}); err == nil || !strings.Contains(err.Error(), "probation group") {
		t.Fatalf("Uninstall(group member) error = %v", err)
	}
}

func TestPluginPackageProbationGroupPassesOnlyAfterEveryMember(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	for _, pluginID := range []string{"group_pass_a", "group_pass_b"} {
		installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "1.0.0"}))
	}
	manager.suppressProbation = false
	requests := make([]PluginPackageApplyRequest, 0, 2)
	for _, pluginID := range []string{"group_pass_a", "group_pass_b"} {
		stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "2.0.0"}))
		requests = append(requests, PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
	}
	manager.runtimeApplyBatch = func([]string) (bool, error) { return true, nil }
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: requests})
	if err != nil {
		t.Fatal(err)
	}
	groupID := result.ID
	if err := manager.completePluginPackageProbation(*result.Plugins[0].Probation, "test member passed"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.loadPluginPackageProbationGroup(groupID); err != nil {
		t.Fatalf("group removed before every member passed: %v", err)
	}
	if err := manager.completePluginPackageProbation(*result.Plugins[1].Probation, "test member passed"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.loadPluginPackageProbationGroup(groupID); !os.IsNotExist(err) {
		t.Fatalf("group after all members passed error = %v", err)
	}
}

func TestPluginPackageBatchRuntimeFailureRestoresEveryPlugin(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	for _, pluginID := range []string{"batch_restore_a", "batch_restore_b"} {
		installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "1.0.0"}))
	}
	stages := make([]PluginPackageApplyRequest, 0, 2)
	for _, pluginID := range []string{"batch_restore_a", "batch_restore_b"} {
		stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "2.0.0"}))
		stages = append(stages, PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
	}
	runtimeCalls := 0
	manager.runtimeApplyBatch = func([]string) (bool, error) {
		runtimeCalls++
		if runtimeCalls == 1 {
			return false, errors.New("injected batch runtime failure")
		}
		return true, nil
	}
	if _, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: stages}); err == nil || !strings.Contains(err.Error(), "injected batch runtime failure") {
		t.Fatalf("ApplyBatch(failing runtime) error = %v", err)
	}
	if runtimeCalls != 2 {
		t.Fatalf("batch runtime calls = %d, want failed apply plus one restore", runtimeCalls)
	}
	for _, pluginID := range []string{"batch_restore_a", "batch_restore_b"} {
		plugin, err := manager.loadCurrentPlugin(pluginID)
		if err != nil || plugin == nil || plugin.Version != "1.0.0" {
			t.Fatalf("plugin %s after rollback = %+v, err=%v", pluginID, plugin, err)
		}
	}
	if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "batches")); err != nil || len(entries) != 0 {
		t.Fatalf("batch transactions after rollback = %+v, err=%v", entries, err)
	}
}

func TestPluginPackageBatchRecoversEveryJournalPhase(t *testing.T) {
	phases := []string{
		pluginPackageBatchPhasePrepared,
		pluginPackageBatchPhaseSourcesApplying,
		pluginPackageBatchPhaseSourcesApplied,
		pluginPackageBatchPhaseRuntimePreparing,
		pluginPackageBatchPhaseRuntimePrepared,
		pluginPackageBatchPhaseRuntimeApplied,
	}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			manager := newPluginPackageManagerForTest(t)
			manager.suppressProbation = true
			for _, pluginID := range []string{"batch_recover_a", "batch_recover_b"} {
				installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "1.0.0"}))
				if err := manager.applyPluginPackageProvenance(pluginID, pluginPackageProvenanceForTest(pluginID, "1.0.0", "a"), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			requests := make([]PluginPackageApplyRequest, 0, 2)
			for _, pluginID := range []string{"batch_recover_a", "batch_recover_b"} {
				stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "2.0.0"}))
				requests = append(requests, PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
			}
			candidates, err := manager.validatePluginPackageBatchRequest(PluginPackageBatchApplyRequest{Stages: requests})
			if err != nil {
				t.Fatal(err)
			}
			for i := range candidates {
				candidates[i].stage.Provenance = pluginPackageProvenanceForTest(candidates[i].stage.PluginID, "2.0.0", "b")
			}
			tx, err := manager.preparePluginPackageBatchTransaction(candidates)
			if err != nil {
				t.Fatal(err)
			}
			if phase != pluginPackageBatchPhasePrepared {
				limit := len(tx.Items)
				if phase == pluginPackageBatchPhaseSourcesApplying {
					limit = 1
				}
				for _, item := range tx.Items[:limit] {
					if err := os.Rename(item.TargetDir, item.BackupDir); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(item.CandidateDir, item.TargetDir); err != nil {
						t.Fatal(err)
					}
				}
			}
			tx.Phase = phase
			if err := manager.writePluginPackageBatchTransaction(tx); err != nil {
				t.Fatal(err)
			}
			if err := manager.applyPluginPackageBatchProvenance(tx, true); err != nil {
				t.Fatal(err)
			}
			runtimeCalls := 0
			manager.runtimeApplyBatch = func([]string) (bool, error) {
				runtimeCalls++
				return true, nil
			}
			if err := manager.recoverBatchTransactions(); err != nil {
				t.Fatalf("recoverBatchTransactions() error = %v", err)
			}
			committed := phase == pluginPackageBatchPhaseRuntimePrepared || phase == pluginPackageBatchPhaseRuntimeApplied
			wantVersion := "1.0.0"
			wantHistory := 0
			wantRuntimeCalls := 0
			if committed {
				wantVersion = "2.0.0"
				wantHistory = 1
			} else if phase == pluginPackageBatchPhaseRuntimePreparing {
				wantRuntimeCalls = 1
			}
			for _, pluginID := range []string{"batch_recover_a", "batch_recover_b"} {
				plugin, err := manager.loadCurrentPlugin(pluginID)
				if err != nil || plugin == nil || plugin.Version != wantVersion {
					t.Fatalf("plugin %s after %s recovery = %+v, err=%v; want %s", pluginID, phase, plugin, err, wantVersion)
				}
				provenance, err := manager.loadPluginPackageProvenance(pluginID)
				if err != nil || provenance == nil || provenance.Version != wantVersion {
					t.Fatalf("plugin %s provenance after %s = %+v, err=%v; want %s", pluginID, phase, provenance, err, wantVersion)
				}
				history, err := manager.ListHistory(pluginID)
				if err != nil || len(history) != wantHistory {
					t.Fatalf("plugin %s history after %s = %+v, err=%v", pluginID, phase, history, err)
				}
				if wantHistory == 1 && (history[0].Provenance == nil || history[0].Provenance.Version != "1.0.0") {
					t.Fatalf("plugin %s history provenance after %s = %+v", pluginID, phase, history[0].Provenance)
				}
			}
			if runtimeCalls != wantRuntimeCalls {
				t.Fatalf("runtime calls after %s = %d, want %d", phase, runtimeCalls, wantRuntimeCalls)
			}
			if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "batches")); err != nil || len(entries) != 0 {
				t.Fatalf("batch transactions after %s recovery = %+v, err=%v", phase, entries, err)
			}
			if err := manager.recoverBatchTransactions(); err != nil {
				t.Fatalf("second recovery error = %v", err)
			}
			if runtimeCalls != wantRuntimeCalls {
				t.Fatalf("second recovery changed runtime calls to %d", runtimeCalls)
			}
		})
	}
}

func TestPluginPackageBatchJournalWriteFailuresRemainAtomic(t *testing.T) {
	for _, tt := range []struct {
		phase               string
		wantVersion         string
		wantRuntimeCalls    int
		wantPendingRecovery bool
	}{
		{phase: pluginPackageBatchPhaseSourcesApplying, wantVersion: "1.0.0"},
		{phase: pluginPackageBatchPhaseSourcesApplied, wantVersion: "1.0.0"},
		{phase: pluginPackageBatchPhaseRuntimePreparing, wantVersion: "1.0.0"},
		{phase: pluginPackageBatchPhaseRuntimePrepared, wantVersion: "1.0.0", wantRuntimeCalls: 2},
		{phase: pluginPackageBatchPhaseRuntimeApplied, wantVersion: "2.0.0", wantRuntimeCalls: 1, wantPendingRecovery: true},
	} {
		t.Run(tt.phase, func(t *testing.T) {
			manager := newPluginPackageManagerForTest(t)
			manager.suppressProbation = true
			for _, pluginID := range []string{"batch_fault_a", "batch_fault_b"} {
				installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "1.0.0"}))
			}
			stages := make([]PluginPackageApplyRequest, 0, 2)
			for _, pluginID := range []string{"batch_fault_a", "batch_fault_b"} {
				stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "2.0.0"}))
				stages = append(stages, PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
			}
			runtimeCalls := 0
			manager.runtimeApplyBatch = func([]string) (bool, error) {
				runtimeCalls++
				return true, nil
			}
			manager.batchFault = func(point string) error {
				if point == "journal."+tt.phase {
					return errors.New("injected journal write failure")
				}
				return nil
			}
			if _, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: stages}); err == nil || !strings.Contains(err.Error(), "injected journal write failure") {
				t.Fatalf("ApplyBatch() error = %v", err)
			}
			manager.batchFault = nil
			if tt.wantPendingRecovery {
				entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "batches"))
				if err != nil || len(entries) != 1 {
					t.Fatalf("pending batch transaction = %+v, err=%v", entries, err)
				}
				if err := manager.recoverBatchTransactions(); err != nil {
					t.Fatalf("recoverBatchTransactions() error = %v", err)
				}
			}
			for _, pluginID := range []string{"batch_fault_a", "batch_fault_b"} {
				plugin, err := manager.loadCurrentPlugin(pluginID)
				if err != nil || plugin == nil || plugin.Version != tt.wantVersion {
					t.Fatalf("plugin %s after %s failure = %+v, err=%v; want %s", pluginID, tt.phase, plugin, err, tt.wantVersion)
				}
			}
			if runtimeCalls != tt.wantRuntimeCalls {
				t.Fatalf("runtime calls after %s failure = %d, want %d", tt.phase, runtimeCalls, tt.wantRuntimeCalls)
			}
			if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "batches")); err != nil || len(entries) != 0 {
				t.Fatalf("batch transactions after %s handling = %+v, err=%v", tt.phase, entries, err)
			}
		})
	}
}

func TestPluginPackageBatchCopyFailureDoesNotTouchInstalledSources(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "batch_disk_full", Version: "1.0.0"}))
	stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "batch_disk_full", Version: "2.0.0"}))
	manager.batchFault = func(point string) error {
		if strings.HasPrefix(point, "copy.") {
			return errors.New("injected disk full")
		}
		return nil
	}
	if _, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: []PluginPackageApplyRequest{{StageID: stage.ID, AllowUnsigned: true}}}); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("ApplyBatch(copy failure) error = %v", err)
	}
	plugin, err := manager.loadCurrentPlugin("batch_disk_full")
	if err != nil || plugin == nil || plugin.Version != "1.0.0" {
		t.Fatalf("plugin after copy failure = %+v, err=%v", plugin, err)
	}
	if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "batches")); err != nil || len(entries) != 0 {
		t.Fatalf("batch transactions after copy failure = %+v, err=%v", entries, err)
	}
}

func TestPluginPackageBatchRecoveryCoordinatesResourceMigration(t *testing.T) {
	for _, tt := range []struct {
		phase       string
		wantVersion string
		wantSchema  int
		wantValue   string
	}{
		{phase: pluginPackageBatchPhaseRuntimePreparing, wantVersion: "1.0.0", wantSchema: 1, wantValue: "old"},
		{phase: pluginPackageBatchPhaseRuntimePrepared, wantVersion: "2.0.0", wantSchema: 2, wantValue: "new"},
	} {
		t.Run(tt.phase, func(t *testing.T) {
			manager := newPluginPackageManagerForTest(t)
			manager.suppressProbation = true
			installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "batch_migration", Version: "1.0.0"}))
			if _, err := store.AddPluginRecord(manager.db, &store.PluginRecord{
				PluginID: "batch_migration", ResourceID: "settings", RecordKey: "default", DataJSON: `{"value":"old"}`, Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertPluginResourceSchemaState(manager.db, store.PluginResourceSchemaState{
				PluginID: "batch_migration", ResourceID: "settings", SchemaVersion: 1, SchemaDigest: "schema-v1", Status: "active",
			}); err != nil {
				t.Fatal(err)
			}
			stage := stagePluginPackageDeferredForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "batch_migration", Version: "2.0.0"}))
			candidates, err := manager.validatePluginPackageBatchRequest(PluginPackageBatchApplyRequest{Stages: []PluginPackageApplyRequest{{StageID: stage.ID, AllowUnsigned: true}}})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := manager.preparePluginPackageBatchTransaction(candidates)
			if err != nil {
				t.Fatal(err)
			}
			item := tx.Items[0]
			if err := os.Rename(item.TargetDir, item.BackupDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(item.CandidateDir, item.TargetDir); err != nil {
				t.Fatal(err)
			}
			previousState, err := store.PluginResourceSchemaStateOrNil(manager.db, "batch_migration", "settings")
			if err != nil || previousState == nil {
				t.Fatalf("previous schema = %+v, err=%v", previousState, err)
			}
			previousRecords, err := store.GetPluginRecords(manager.db, "batch_migration", "settings")
			if err != nil {
				t.Fatal(err)
			}
			if err := stagePluginResourceMigration(manager.db, tx.ResourceMigrationID,
				LoadedPlugin{PluginManifest: PluginManifest{ID: "batch_migration"}},
				PluginResource{ID: "settings", SchemaVersion: 2, SchemaDigest: "schema-v2"},
				previousState, previousRecords,
				pluginResourceMigrationResult{Records: []pluginResourceMigrationOutputRecord{{Key: "default", DataJSON: `{"value":"new"}`, Enabled: true}}},
			); err != nil {
				t.Fatal(err)
			}
			tx.Phase = tt.phase
			if err := manager.writePluginPackageBatchTransaction(tx); err != nil {
				t.Fatal(err)
			}
			manager.runtimeApplyBatch = func([]string) (bool, error) { return true, nil }
			if err := manager.recoverBatchTransactions(); err != nil {
				t.Fatalf("recoverBatchTransactions() error = %v", err)
			}
			plugin, err := manager.loadCurrentPlugin("batch_migration")
			if err != nil || plugin == nil || plugin.Version != tt.wantVersion {
				t.Fatalf("plugin after migration recovery = %+v, err=%v", plugin, err)
			}
			state, err := store.PluginResourceSchemaStateOrNil(manager.db, "batch_migration", "settings")
			if err != nil || state == nil || state.Status != "active" || state.SchemaVersion != tt.wantSchema || state.TransactionID != "" {
				t.Fatalf("schema after migration recovery = %+v, err=%v", state, err)
			}
			records, err := store.GetPluginRecords(manager.db, "batch_migration", "settings")
			if err != nil || len(records) != 1 || !strings.Contains(records[0].DataJSON, `"value":"`+tt.wantValue+`"`) {
				t.Fatalf("records after migration recovery = %+v, err=%v", records, err)
			}
		})
	}
}

func TestPluginPackageHistoryRollback(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "versioned_plugin", Version: "1.0.0"}))
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "versioned_plugin", Version: "2.0.0"}))
	history, err := manager.ListHistory("versioned_plugin")
	if err != nil || len(history) != 1 || history[0].Version != "1.0.0" {
		t.Fatalf("history = %+v, err=%v", history, err)
	}
	stage, err := manager.PrepareRollback(PluginPackageRollbackRequest{PluginID: "versioned_plugin", HistoryID: history[0].ID})
	if err != nil {
		t.Fatalf("PrepareRollback() error = %v", err)
	}
	if !stage.Trusted || stage.HistoryID != history[0].ID || stage.Version != "1.0.0" {
		t.Fatalf("rollback stage = %+v", stage)
	}
	result, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest})
	if err != nil {
		t.Fatalf("ApplyStage(rollback) error = %v", err)
	}
	if result.Operation != "rollback" {
		t.Fatalf("rollback result = %+v", result)
	}
	plugin, err := manager.loadCurrentPlugin("versioned_plugin")
	if err != nil || plugin.Version != "1.0.0" {
		t.Fatalf("plugin after rollback = %+v, err=%v", plugin, err)
	}
	history, err = manager.ListHistory("versioned_plugin")
	if err != nil || len(history) != 2 || history[0].Version != "2.0.0" {
		t.Fatalf("history after rollback = %+v, err=%v", history, err)
	}
}

func TestPluginPackageProbationAutomaticallyRollsBackUpdate(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "probation_update", Version: "1.0.0"}))
	result := installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "probation_update", Version: "2.0.0"}))
	if result.Probation == nil || result.Probation.PreviousHistoryID == "" || !result.Probation.Pending {
		t.Fatalf("update probation = %+v, want pending state with rollback history", result.Probation)
	}
	recovery, err := manager.recoverPluginPackageProbation(*result.Probation, "injected fatal runtime failure", "test")
	if err != nil {
		t.Fatalf("recoverPluginPackageProbation() error = %v", err)
	}
	if recovery.Operation != "rollback" || recovery.Version != "1.0.0" {
		t.Fatalf("recovery result = %+v, want rollback to 1.0.0", recovery)
	}
	current, err := manager.loadCurrentPlugin("probation_update")
	if err != nil || current == nil || current.Version != "1.0.0" {
		t.Fatalf("current plugin after probation recovery = %+v, err=%v", current, err)
	}
	if _, err := manager.loadPluginPackageProbation("probation_update"); !os.IsNotExist(err) {
		t.Fatalf("probation after recovery error = %v, want removed", err)
	}
}

func TestPluginPackageProbationDisablesFirstInstallWithoutHistory(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	result := installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "probation_install", Version: "1.0.0"}))
	if result.Probation == nil || result.Probation.PreviousHistoryID != "" {
		t.Fatalf("install probation = %+v, want no rollback history", result.Probation)
	}
	recovery, err := manager.recoverPluginPackageProbation(*result.Probation, "injected fatal runtime failure", "test")
	if err != nil {
		t.Fatalf("recoverPluginPackageProbation() error = %v", err)
	}
	if recovery.Operation != "auto_disable" {
		t.Fatalf("recovery result = %+v, want auto_disable", recovery)
	}
	state, err := store.GetPluginState(manager.db, "probation_install")
	if err != nil || state.Enabled {
		t.Fatalf("plugin state after probation recovery = %+v, err=%v, want disabled", state, err)
	}
	current, err := manager.loadCurrentPlugin("probation_install")
	if err != nil || current == nil || current.Version != "1.0.0" {
		t.Fatalf("disabled plugin source = %+v, err=%v, want retained", current, err)
	}
}

func TestPluginPackageProbationCleanShutdownAndCrashLoop(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.runtimeApply = func(string) (bool, error) { return true, nil }
	result := installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "probation_boot", Version: "1.0.0"}))
	if result.Probation == nil || result.Probation.Pending {
		t.Fatalf("active probation = %+v", result.Probation)
	}
	if err := manager.markPluginPackageProbationsCleanShutdown(); err != nil {
		t.Fatalf("mark clean shutdown: %v", err)
	}
	if err := manager.recoverPluginPackageProbationsOnStartup(time.Now()); err != nil {
		t.Fatalf("recover after clean shutdown: %v", err)
	}
	record, err := manager.loadPluginPackageProbation("probation_boot")
	if err != nil || record.CleanShutdown || record.UncleanStarts != 0 {
		t.Fatalf("probation after clean startup = %+v, err=%v", record, err)
	}
	for i := 1; i <= pluginPackageProbationBoots; i++ {
		if err := manager.recoverPluginPackageProbationsOnStartup(time.Now()); err != nil {
			t.Fatalf("recover unclean startup %d: %v", i, err)
		}
	}
	state, err := store.GetPluginState(manager.db, "probation_boot")
	if err != nil || state.Enabled {
		t.Fatalf("plugin state after crash loop = %+v, err=%v, want disabled", state, err)
	}
	if _, err := manager.loadPluginPackageProbation("probation_boot"); !os.IsNotExist(err) {
		t.Fatalf("probation after crash-loop recovery error = %v, want removed", err)
	}
}

func TestPluginPackageProbationFatalErrorClassification(t *testing.T) {
	for _, message := range []string{
		"plugin control execution timed out", "plugin host process exited", "out of memory", "plugin host protocol violation", "stack overflow",
	} {
		if !pluginPackageProbationFatalControlError(message) {
			t.Fatalf("fatal error %q was not classified", message)
		}
	}
	for _, message := range []string{
		"PPPoE discovery timed out", "link eth1 not found", "dial tcp: network is unreachable", "authentication rejected",
	} {
		if pluginPackageProbationFatalControlError(message) {
			t.Fatalf("external error %q was classified as fatal", message)
		}
	}
}

func TestPluginPackagePermissionExpansionRequiresNewApproval(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "permission_plugin", Version: "1.0.0", Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	}))
	stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "permission_plugin", Version: "2.0.0", Permissions: []string{"plugin.register", "secret"}, Control: `exports.onReconcile = function () {};`,
	}))
	if len(stage.PrivilegeAdditions) != 1 || stage.PrivilegeAdditions[0] != "permission:secret" {
		t.Fatalf("privilege additions = %+v", stage.PrivilegeAdditions)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true, ApprovedPrivilegeDigest: strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "approval digest") {
		t.Fatalf("ApplyStage(wrong approval) error = %v", err)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true, ApprovedPrivilegeDigest: stage.PrivilegeDigest}); err != nil {
		t.Fatalf("ApplyStage(approved) error = %v", err)
	}
}

func TestPluginPrivilegeSummaryIncludesCrossPluginEventScope(t *testing.T) {
	base := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "event_consumer",
		Control: &PluginControl{
			Permissions: []string{"event", "plugin.event", "worker"},
			EventAccess: []PluginEventAccess{{
				Plugin: "event_source", TopicPrefixes: []string{"plugin.event_source.status"},
			}},
		},
	}}
	baseEntries, baseDigest := pluginPrivilegeSummary(base)
	found := false
	for _, entry := range baseEntries {
		if entry == "event:event_source:plugin.event_source.status" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("privilege entries = %v", baseEntries)
	}

	candidate := base
	control := *base.Control
	control.EventAccess = []PluginEventAccess{{
		Plugin: "event_source", TopicPrefixes: []string{"plugin.event_source"},
	}}
	candidate.Control = &control
	candidateEntries, candidateDigest := pluginPrivilegeSummary(candidate)
	if candidateDigest == baseDigest {
		t.Fatal("wider event access did not change privilege digest")
	}
	additions := pluginPrivilegeAdditions(baseEntries, candidateEntries)
	if len(additions) != 1 || additions[0] != "event:event_source:plugin.event_source" {
		t.Fatalf("privilege additions = %v", additions)
	}
}

func TestPluginPrivilegeSummaryIncludesNamespaceScope(t *testing.T) {
	base := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "namespace_plugin",
		Control: &PluginControl{
			Permissions:     []string{"net.namespace"},
			NamespaceAccess: []string{"veer-owned"},
		},
	}}
	baseEntries, baseDigest := pluginPrivilegeSummary(base)
	candidate := base
	control := *base.Control
	control.NamespaceAccess = []string{"veer-*"}
	candidate.Control = &control
	candidateEntries, candidateDigest := pluginPrivilegeSummary(candidate)
	if candidateDigest == baseDigest {
		t.Fatal("wider namespace access did not change privilege digest")
	}
	additions := pluginPrivilegeAdditions(baseEntries, candidateEntries)
	if len(additions) != 1 || additions[0] != "namespace:veer-*" {
		t.Fatalf("namespace privilege additions = %v", additions)
	}
}

func TestPluginPrivilegeSummaryIncludesUICapabilities(t *testing.T) {
	base := LoadedPlugin{UI: &PluginUI{
		Resources: []PluginUIResourceAccess{{Resource: "profiles", Methods: []string{"list"}}},
		Actions:   []string{"refresh"},
		ResourceAccess: []PluginResourceAccess{{
			Plugin: "wan_core", Resource: "status", Methods: []string{"list"},
		}},
	}}
	baseEntries, baseDigest := pluginPrivilegeSummary(base)
	for _, want := range []string{
		"ui-resource:profiles:list",
		"ui-action:refresh",
		"ui-cross-resource:wan_core/status:list",
	} {
		if !slices.Contains(baseEntries, want) {
			t.Fatalf("privilege entries = %v, want %q", baseEntries, want)
		}
	}

	candidate := base
	candidate.UI = clonePluginUI(base.UI)
	candidate.UI.Actions = append(candidate.UI.Actions, "apply")
	candidateEntries, candidateDigest := pluginPrivilegeSummary(candidate)
	if candidateDigest == baseDigest {
		t.Fatal("wider UI action access did not change privilege digest")
	}
	additions := pluginPrivilegeAdditions(baseEntries, candidateEntries)
	if len(additions) != 1 || additions[0] != "ui-action:apply" {
		t.Fatalf("UI privilege additions = %v", additions)
	}
}

func TestPluginPackageUninstallProtectsRequiredDependents(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "base_plugin", Version: "1.0.0"}))
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "dependent_plugin", Version: "1.0.0", Dependencies: []PluginDependency{{ID: "base_plugin", Version: "^1.0.0"}},
	}))
	if _, err := manager.Uninstall(PluginPackageUninstallRequest{PluginID: "base_plugin"}); err == nil || !strings.Contains(err.Error(), "dependent_plugin") {
		t.Fatalf("Uninstall(required plugin) error = %v", err)
	}
	result, err := manager.Uninstall(PluginPackageUninstallRequest{PluginID: "base_plugin", Force: true})
	if err != nil {
		t.Fatalf("Uninstall(force) error = %v", err)
	}
	if result.Operation != "uninstall" || result.HistoryID == "" {
		t.Fatalf("uninstall result = %+v", result)
	}
	if _, err := os.Lstat(filepath.Join(manager.pluginsRoot, "base_plugin")); !os.IsNotExist(err) {
		t.Fatalf("base plugin still exists: %v", err)
	}
}

func TestPluginPackageRejectsUnsafeTarEntries(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	tests := []struct {
		name   string
		header tar.Header
		want   string
	}{
		{name: "traversal", header: tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}, want: "canonical relative path"},
		{name: "absolute", header: tar.Header{Name: "/escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}, want: "absolute"},
		{name: "symlink", header: tar.Header{Name: "unsafe/link", Typeflag: tar.TypeSymlink, Linkname: "../outside"}, want: "unsupported tar type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload []byte
			if tt.header.Size > 0 {
				payload = []byte("x")
			}
			archive := buildRawPluginArchiveForTest(t, []tar.Header{tt.header}, [][]byte{payload})
			if _, err := manager.Stage(bytes.NewReader(archive), "", ""); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Stage() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPluginPackageRecoversTransactionPhases(t *testing.T) {
	for _, phase := range []string{"prepared", "old_moved", "new_moved", "runtime_prepared", "runtime_applied"} {
		t.Run(phase, func(t *testing.T) {
			manager := newPluginPackageManagerForTest(t)
			installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "recovery_plugin", Version: "1.0.0"}))
			previousProvenance := pluginPackageProvenanceForTest("recovery_plugin", "1.0.0", "a")
			if err := manager.applyPluginPackageProvenance("recovery_plugin", previousProvenance, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "recovery_plugin", Version: "2.0.0"}))
			stage.Provenance = pluginPackageProvenanceForTest("recovery_plugin", "2.0.0", "b")
			current, err := manager.loadCurrentPlugin("recovery_plugin")
			if err != nil || current == nil {
				t.Fatalf("load current plugin: plugin=%+v err=%v", current, err)
			}
			tx, err := manager.prepareInstallTransaction(stage, current)
			if err != nil {
				t.Fatalf("prepareInstallTransaction() error = %v", err)
			}
			switch phase {
			case "old_moved":
				if err := os.Rename(tx.TargetDir, tx.BackupDir); err != nil {
					t.Fatal(err)
				}
			case "new_moved", "runtime_prepared", "runtime_applied":
				if err := os.Rename(tx.TargetDir, tx.BackupDir); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tx.CandidateDir, tx.TargetDir); err != nil {
					t.Fatal(err)
				}
			}
			tx.Phase = phase
			if err := manager.writeTransaction(tx); err != nil {
				t.Fatalf("writeTransaction() error = %v", err)
			}
			if err := manager.applyPluginPackageProvenance("recovery_plugin", tx.CandidateProvenance, tx.CreatedAt); err != nil {
				t.Fatal(err)
			}
			runtimeCalls := 0
			manager.runtimeApply = func(pluginID string) (bool, error) {
				runtimeCalls++
				if pluginID != "recovery_plugin" {
					t.Fatalf("runtime plugin id = %q", pluginID)
				}
				return true, nil
			}
			if err := manager.recoverTransactions(); err != nil {
				t.Fatalf("recoverTransactions() error = %v", err)
			}
			expectedVersion := "1.0.0"
			expectedRuntimeCalls := 1
			expectedHistory := 0
			if phase == "runtime_prepared" || phase == "runtime_applied" {
				expectedVersion = "2.0.0"
				expectedRuntimeCalls = 0
				expectedHistory = 1
			}
			plugin, err := manager.loadCurrentPlugin("recovery_plugin")
			if err != nil || plugin == nil || plugin.Version != expectedVersion {
				t.Fatalf("plugin after %s recovery = %+v, err=%v; want version %s", phase, plugin, err, expectedVersion)
			}
			provenance, err := manager.loadPluginPackageProvenance("recovery_plugin")
			if err != nil || provenance == nil || provenance.Version != expectedVersion {
				t.Fatalf("provenance after %s recovery = %+v, err=%v; want version %s", phase, provenance, err, expectedVersion)
			}
			if runtimeCalls != expectedRuntimeCalls {
				t.Fatalf("runtime calls after %s recovery = %d, want %d", phase, runtimeCalls, expectedRuntimeCalls)
			}
			history, err := manager.ListHistory("recovery_plugin")
			if err != nil || len(history) != expectedHistory {
				t.Fatalf("history after %s recovery = %+v, err=%v", phase, history, err)
			}
			if expectedHistory == 1 && (history[0].Provenance == nil || history[0].Provenance.Version != "1.0.0") {
				t.Fatalf("history provenance after %s recovery = %+v", phase, history[0].Provenance)
			}
			if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "transactions")); err != nil || len(entries) != 0 {
				t.Fatalf("transactions after %s recovery = %+v, err=%v", phase, entries, err)
			}
			if err := manager.recoverTransactions(); err != nil {
				t.Fatalf("second recoverTransactions() error = %v", err)
			}
			if runtimeCalls != expectedRuntimeCalls {
				t.Fatalf("second recovery changed runtime calls to %d", runtimeCalls)
			}
		})
	}
}

func TestPluginPackageRecoveryCoordinatesResourceMigration(t *testing.T) {
	for _, tt := range []struct {
		phase       string
		wantVersion string
		wantSchema  int
		wantValue   string
	}{
		{phase: "new_moved", wantVersion: "1.0.0", wantSchema: 1, wantValue: "old"},
		{phase: "runtime_prepared", wantVersion: "2.0.0", wantSchema: 2, wantValue: "new"},
	} {
		t.Run(tt.phase, func(t *testing.T) {
			manager := newPluginPackageManagerForTest(t)
			installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "migration_recovery", Version: "1.0.0"}))
			if _, err := store.AddPluginRecord(manager.db, &store.PluginRecord{
				PluginID: "migration_recovery", ResourceID: "settings", RecordKey: "default", DataJSON: `{"value":"old"}`, Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertPluginResourceSchemaState(manager.db, store.PluginResourceSchemaState{
				PluginID: "migration_recovery", ResourceID: "settings", SchemaVersion: 1, SchemaDigest: "schema-v1", Status: "active",
			}); err != nil {
				t.Fatal(err)
			}

			stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "migration_recovery", Version: "2.0.0"}))
			current, err := manager.loadCurrentPlugin("migration_recovery")
			if err != nil || current == nil {
				t.Fatalf("load current plugin: plugin=%+v err=%v", current, err)
			}
			tx, err := manager.prepareInstallTransaction(stage, current)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tx.TargetDir, tx.BackupDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tx.CandidateDir, tx.TargetDir); err != nil {
				t.Fatal(err)
			}

			previousState, err := store.PluginResourceSchemaStateOrNil(manager.db, "migration_recovery", "settings")
			if err != nil || previousState == nil {
				t.Fatalf("previous schema state = %+v, err=%v", previousState, err)
			}
			previousRecords, err := store.GetPluginRecords(manager.db, "migration_recovery", "settings")
			if err != nil {
				t.Fatal(err)
			}
			plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "migration_recovery"}}
			resource := PluginResource{ID: "settings", SchemaVersion: 2, SchemaDigest: "schema-v2"}
			if err := stagePluginResourceMigration(manager.db, tx.ResourceMigrationID, plugin, resource, previousState, previousRecords, pluginResourceMigrationResult{
				Records: []pluginResourceMigrationOutputRecord{{Key: "default", DataJSON: `{"value":"new"}`, Enabled: true}},
			}); err != nil {
				t.Fatal(err)
			}
			tx.Phase = tt.phase
			if err := manager.writeTransaction(tx); err != nil {
				t.Fatal(err)
			}
			manager.runtimeApply = func(string) (bool, error) { return true, nil }

			if err := manager.recoverTransactions(); err != nil {
				t.Fatalf("recoverTransactions() error = %v", err)
			}
			loaded, err := manager.loadCurrentPlugin("migration_recovery")
			if err != nil || loaded == nil || loaded.Version != tt.wantVersion {
				t.Fatalf("plugin after recovery = %+v, err=%v; want version %s", loaded, err, tt.wantVersion)
			}
			state, err := store.PluginResourceSchemaStateOrNil(manager.db, "migration_recovery", "settings")
			if err != nil || state == nil || state.Status != "active" || state.TransactionID != "" || state.SchemaVersion != tt.wantSchema {
				t.Fatalf("schema after recovery = %+v, err=%v; want active v%d", state, err, tt.wantSchema)
			}
			records, err := store.GetPluginRecords(manager.db, "migration_recovery", "settings")
			if err != nil || len(records) != 1 || !strings.Contains(records[0].DataJSON, `"value":"`+tt.wantValue+`"`) {
				t.Fatalf("records after recovery = %+v, err=%v; want value %s", records, err, tt.wantValue)
			}
			migrations, err := store.GetPluginResourceMigrations(manager.db, tx.ResourceMigrationID)
			if err != nil || len(migrations) != 0 {
				t.Fatalf("pending migrations after recovery = %+v, err=%v", migrations, err)
			}
		})
	}
}

func TestPluginPackageHistoryFinalizationIsCrashIdempotent(t *testing.T) {
	for _, crashPoint := range []string{"metadata_written", "source_moved"} {
		t.Run(crashPoint, func(t *testing.T) {
			manager := newPluginPackageManagerForTest(t)
			installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "history_recovery", Version: "1.0.0"}))
			stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "history_recovery", Version: "2.0.0"}))
			current, err := manager.loadCurrentPlugin("history_recovery")
			if err != nil || current == nil {
				t.Fatalf("load current plugin: plugin=%+v err=%v", current, err)
			}
			tx, err := manager.prepareInstallTransaction(stage, current)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tx.TargetDir, tx.BackupDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tx.CandidateDir, tx.TargetDir); err != nil {
				t.Fatal(err)
			}
			tx.Phase = "runtime_applied"
			if err := manager.writeTransaction(tx); err != nil {
				t.Fatal(err)
			}
			createdAt, err := time.Parse(time.RFC3339Nano, tx.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			historyDir := filepath.Join(manager.stateRoot, "history", tx.PluginID, tx.HistoryID)
			if err := os.MkdirAll(historyDir, 0o700); err != nil {
				t.Fatal(err)
			}
			entry := PluginPackageHistoryEntry{
				ID:                tx.HistoryID,
				PluginID:          tx.PluginID,
				Version:           tx.PreviousVersion,
				SourceFingerprint: tx.PreviousFingerprint,
				PrivilegeDigest:   tx.PreviousPrivilegeDigest,
				CreatedAt:         createdAt.UTC().Format(time.RFC3339Nano),
				Reason:            pluginPackageTransactionHistoryReason(tx),
			}
			if err := writePluginPackageJSONAtomic(filepath.Join(historyDir, pluginPackageHistoryMetadataFile), entry, false); err != nil {
				t.Fatal(err)
			}
			if crashPoint == "source_moved" {
				if err := os.Rename(tx.BackupDir, filepath.Join(historyDir, "plugin")); err != nil {
					t.Fatal(err)
				}
			}
			if err := manager.recoverTransactions(); err != nil {
				t.Fatalf("recoverTransactions() error = %v", err)
			}
			history, err := manager.ListHistory("history_recovery")
			if err != nil || len(history) != 1 || history[0].ID != tx.HistoryID || history[0].Version != "1.0.0" {
				t.Fatalf("history after recovery = %+v, err=%v", history, err)
			}
			if err := manager.recoverTransactions(); err != nil {
				t.Fatalf("second recoverTransactions() error = %v", err)
			}
		})
	}
}

func TestPluginPackageStageIntegrityAndBounds(t *testing.T) {
	t.Run("archive tampering", func(t *testing.T) {
		manager := newPluginPackageManagerForTest(t)
		stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "archive_tamper", Version: "1.0.0"}))
		file, err := os.OpenFile(stage.archivePath, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("tampered")); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.LoadStage(stage.ID); err == nil || !strings.Contains(err.Error(), "archive failed integrity") {
			t.Fatalf("LoadStage(tampered archive) error = %v", err)
		}
	})

	t.Run("candidate tampering", func(t *testing.T) {
		manager := newPluginPackageManagerForTest(t)
		stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "candidate_tamper", Version: "1.0.0"}))
		file, err := os.OpenFile(filepath.Join(stage.candidateDir, "plugin.json"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write([]byte(" "))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("tamper candidate: write=%v close=%v", writeErr, closeErr)
		}
		if _, err := manager.LoadStage(stage.ID); err == nil || !strings.Contains(err.Error(), "candidate failed integrity") {
			t.Fatalf("LoadStage(tampered candidate) error = %v", err)
		}
	})

	t.Run("metadata trailing JSON", func(t *testing.T) {
		manager := newPluginPackageManagerForTest(t)
		stage := stagePluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "metadata_tamper", Version: "1.0.0"}))
		path := filepath.Join(stage.stageDir, pluginPackageStageMetadataFile)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write([]byte("{}\n"))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("tamper metadata: write=%v close=%v", writeErr, closeErr)
		}
		if _, err := manager.LoadStage(stage.ID); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
			t.Fatalf("LoadStage(trailing JSON) error = %v", err)
		}
	})

	t.Run("duplicate archive entry", func(t *testing.T) {
		manager := newPluginPackageManagerForTest(t)
		headers := []tar.Header{
			{Name: "duplicate/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "duplicate/plugin.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
			{Name: "duplicate/plugin.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
		}
		archive := buildRawPluginArchiveForTest(t, headers, [][]byte{nil, []byte("{}"), []byte("{}")})
		if _, err := manager.Stage(bytes.NewReader(archive), "", ""); err == nil || !strings.Contains(err.Error(), "duplicate entry") {
			t.Fatalf("Stage(duplicate entry) error = %v", err)
		}
	})

	t.Run("archive size", func(t *testing.T) {
		manager := newPluginPackageManagerForTest(t)
		reader := io.LimitReader(pluginPackageZeroReader{}, pluginPackageMaxArchiveBytes+1)
		if _, err := manager.Stage(reader, "", ""); err == nil || !strings.Contains(err.Error(), "archive exceeds") {
			t.Fatalf("Stage(oversize archive) error = %v", err)
		}
	})
}

func TestPluginPackageSignedStageRequiresSignerToRemainTrusted(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := manager.AddTrustKey(PluginTrustKeyRequest{Name: "Removed Publisher", PublicKey: base64.StdEncoding.EncodeToString(publicKey)})
	if err != nil {
		t.Fatal(err)
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "removed_signer", Version: "1.0.0"})
	digest := sha256.Sum256(archive)
	signature := ed25519.Sign(privateKey, append([]byte(pluginPackageSignatureDomain), digest[:]...))
	stage, err := manager.Stage(bytes.NewReader(archive), key.ID, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteTrustKey(key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LoadStage(stage.ID); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("LoadStage(after trust removal) error = %v", err)
	}
}

func TestPluginPackageUninstallCanPurgePluginData(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "purge_plugin", Version: "1.0.0"}))
	blobs, err := newPluginBlobStore(manager.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Put("purge_plugin", "generation-a", "state", []byte("persistent"), ""); err != nil {
		t.Fatal(err)
	}
	blobDir := filepath.Join(blobs.blobRoot, "purge_plugin")
	if err := blobs.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddPluginRecord(manager.db, &store.PluginRecord{PluginID: "purge_plugin", ResourceID: "settings", RecordKey: "default", DataJSON: `{}`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPluginEnabled(manager.db, "purge_plugin", false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPluginRuntimeStatus(manager.db, store.PluginRuntimeStatus{PluginID: "purge_plugin", TargetType: "resource", TargetID: "settings", Status: "applied"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Uninstall(PluginPackageUninstallRequest{PluginID: "purge_plugin", PurgeData: true}); err != nil {
		t.Fatalf("Uninstall(purge_data) error = %v", err)
	}
	for _, table := range []string{"plugin_records", "plugin_states", "plugin_runtime_status"} {
		var count int
		if err := manager.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE plugin_id = ?`, "purge_plugin").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d purge_plugin rows", table, count)
		}
	}
	if _, err := os.Stat(blobDir); !os.IsNotExist(err) {
		t.Fatalf("purge_data retained plugin blob directory: %v", err)
	}
}

func TestPluginPackageRecoveryCompletesUninstallDataPurge(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "recover_purge", Version: "1.0.0"}))
	blobs, err := newPluginBlobStore(manager.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Put("recover_purge", "generation-a", "state", []byte("persistent"), ""); err != nil {
		t.Fatal(err)
	}
	blobDir := filepath.Join(blobs.blobRoot, "recover_purge")
	if err := blobs.Close(); err != nil {
		t.Fatal(err)
	}
	previousProvenance := pluginPackageProvenanceForTest("recover_purge", "1.0.0", "d")
	if err := manager.applyPluginPackageProvenance("recover_purge", previousProvenance, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	previousProvenance, err = manager.loadPluginPackageProvenance("recover_purge")
	if err != nil || previousProvenance == nil {
		t.Fatalf("load recover_purge provenance = %+v, err=%v", previousProvenance, err)
	}
	if _, err := store.AddPluginRecord(manager.db, &store.PluginRecord{PluginID: "recover_purge", ResourceID: "settings", RecordKey: "default", DataJSON: `{}`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	txID, err := newPluginPackageID()
	if err != nil {
		t.Fatal(err)
	}
	txDir := filepath.Join(manager.stateRoot, "transactions", txID)
	if err := os.Mkdir(txDir, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err := manager.loadCurrentPlugin("recover_purge")
	if err != nil || current == nil {
		t.Fatalf("load current plugin: plugin=%+v err=%v", current, err)
	}
	_, privilegeDigest := pluginPrivilegeSummary(*current)
	fingerprint, err := buildPluginDirectoryFingerprint(filepath.Join(manager.pluginsRoot, current.ID))
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC()
	tx := pluginPackageTransaction{
		ID:                      txID,
		HistoryID:               pluginPackageHistoryID(createdAt, txID),
		Operation:               "uninstall",
		PluginID:                current.ID,
		PreviousVersion:         current.Version,
		PreviousPrivilegeDigest: privilegeDigest,
		PreviousFingerprint:     fingerprint,
		Phase:                   "runtime_applied",
		TargetDir:               filepath.Join(manager.pluginsRoot, current.ID),
		BackupDir:               filepath.Join(txDir, "backup"),
		PurgeData:               true,
		CreatedAt:               createdAt.Format(time.RFC3339Nano),
		PreviousProvenance:      clonePluginPackageProvenance(previousProvenance),
	}
	if err := os.Rename(tx.TargetDir, tx.BackupDir); err != nil {
		t.Fatal(err)
	}
	if err := manager.writeTransaction(tx); err != nil {
		t.Fatal(err)
	}
	if err := manager.recoverTransactions(); err != nil {
		t.Fatalf("recoverTransactions() error = %v", err)
	}
	var count int
	if err := manager.db.QueryRow(`SELECT COUNT(*) FROM plugin_records WHERE plugin_id = ?`, current.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("plugin records after recovered purge = %d", count)
	}
	if provenance, err := manager.loadPluginPackageProvenance(current.ID); err != nil || provenance != nil {
		t.Fatalf("plugin provenance after recovered uninstall = %+v, err=%v", provenance, err)
	}
	history, err := manager.ListHistory(current.ID)
	if err != nil || len(history) != 1 || history[0].Provenance == nil || history[0].Provenance.Version != current.Version {
		t.Fatalf("plugin history after recovered uninstall = %+v, err=%v", history, err)
	}
	if entries, err := os.ReadDir(filepath.Join(manager.stateRoot, "transactions")); err != nil || len(entries) != 0 {
		t.Fatalf("transactions after recovered purge = %+v, err=%v", entries, err)
	}
	if _, err := os.Stat(blobDir); !os.IsNotExist(err) {
		t.Fatalf("recovered purge retained plugin blob directory: %v", err)
	}
}

type pluginPackageZeroReader struct{}

func (pluginPackageZeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

type pluginPackageTestSpec struct {
	ID            string
	Version       string
	Stability     string
	Permissions   []string
	Dependencies  []PluginDependency
	Compatibility *PluginCompatibility
	Control       string
}

func newPluginPackageManagerForTest(t *testing.T) *pluginPackageManager {
	t.Helper()
	pluginsDir := filepath.Join(t.TempDir(), "plugins")
	manager, err := newPluginPackageManager(pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir}), openTestDB(t), nil)
	if err != nil {
		t.Fatalf("newPluginPackageManager() error = %v", err)
	}
	return manager
}

func buildPluginPackageForTest(t *testing.T, spec pluginPackageTestSpec) []byte {
	t.Helper()
	stability := spec.Stability
	if stability == "" {
		stability = pluginStabilityLab
	}
	manifest := PluginManifest{
		APIVersion:    pluginAPIVersionV1,
		ID:            spec.ID,
		Name:          spec.ID,
		Version:       spec.Version,
		Kind:          "control",
		Stability:     stability,
		Dependencies:  append([]PluginDependency(nil), spec.Dependencies...),
		Compatibility: spec.Compatibility,
	}
	if spec.Control != "" || len(spec.Permissions) > 0 {
		manifest.Control = &PluginControl{Main: "control.js", Permissions: append([]string(nil), spec.Permissions...)}
		if stability == pluginStabilityStable || stability == pluginStabilityPreview {
			digest := sha256.Sum256([]byte(spec.Control))
			manifest.Control.SHA256 = hex.EncodeToString(digest[:])
		}
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestData = append(manifestData, '\n')
	headers := []tar.Header{
		{Name: spec.ID + "/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: spec.ID + "/plugin.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(manifestData))},
	}
	payloads := [][]byte{nil, manifestData}
	if manifest.Control != nil {
		controlData := []byte(spec.Control)
		headers = append(headers, tar.Header{Name: spec.ID + "/control.js", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(controlData))})
		payloads = append(payloads, controlData)
	}
	return buildRawPluginArchiveForTest(t, headers, payloads)
}

func buildRawPluginArchiveForTest(t *testing.T, headers []tar.Header, payloads [][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for i := range headers {
		header := headers[i]
		if err := tarWriter.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if i < len(payloads) && len(payloads[i]) > 0 {
			if _, err := io.Copy(tarWriter, bytes.NewReader(payloads[i])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func stagePluginPackageForTest(t *testing.T, manager *pluginPackageManager, archive []byte) PluginPackageStage {
	t.Helper()
	stage, err := manager.Stage(bytes.NewReader(archive), "", "")
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	return stage
}

func stagePluginPackageDeferredForTest(t *testing.T, manager *pluginPackageManager, archive []byte) PluginPackageStage {
	t.Helper()
	stage, err := manager.StageWithDeferredRelationships(bytes.NewReader(archive), "", "", true)
	if err != nil {
		t.Fatalf("StageWithDeferredRelationships() error = %v", err)
	}
	return stage
}

func installPluginPackageForTest(t *testing.T, manager *pluginPackageManager, archive []byte) PluginPackageOperationResult {
	t.Helper()
	stage := stagePluginPackageForTest(t, manager, archive)
	result, err := manager.ApplyStage(PluginPackageApplyRequest{
		StageID:                 stage.ID,
		ApprovedPrivilegeDigest: stage.PrivilegeDigest,
		AllowUnsigned:           true,
	})
	if err != nil {
		t.Fatalf("ApplyStage() error = %v", err)
	}
	return result
}

func pluginPackageProvenanceForTest(pluginID, version, digestByte string) *PluginPackageProvenance {
	return &PluginPackageProvenance{
		FormatVersion:     pluginRepositoryFormatVersion,
		PluginID:          pluginID,
		Version:           version,
		Source:            "tuf",
		RepositoryID:      "test_repo",
		RepositoryTarget:  "plugins/stable/" + pluginID + "/" + version + "/package.tar.gz",
		RepositoryChannel: pluginRepositoryChannelStable,
		RepositoryVersion: 1,
		ArchiveSHA256:     strings.Repeat(digestByte, sha256.Size*2),
	}
}
