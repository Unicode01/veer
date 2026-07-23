package app

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

type pluginRepositoryTestTarget struct {
	path          string
	archive       []byte
	pluginID      string
	version       string
	channel       string
	stability     string
	compatibility *PluginCompatibility
	dependencies  []PluginDependency
	conflicts     []PluginConflict
	revoked       bool
	reason        string
}

type pluginRepositoryTestServer struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
	root   json.RawMessage
	keys   map[string]ed25519.PrivateKey
	mu     sync.RWMutex
	files  map[string][]byte
}

func newPluginRepositoryTestServer(t *testing.T) *pluginRepositoryTestServer {
	t.Helper()
	repository := &pluginRepositoryTestServer{t: t, keys: make(map[string]ed25519.PrivateKey), files: make(map[string][]byte)}
	root := tufmetadata.Root(time.Now().Add(365 * 24 * time.Hour))
	root.Signed.ConsistentSnapshot = true
	for _, role := range []string{tufmetadata.ROOT, tufmetadata.TARGETS, tufmetadata.SNAPSHOT, tufmetadata.TIMESTAMP} {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		repository.keys[role] = privateKey
		key, err := tufmetadata.KeyFromPublicKey(privateKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
	}
	pluginRepositorySignMetadata(t, root, repository.keys[tufmetadata.ROOT])
	rootBytes, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	repository.root = rootBytes
	repository.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		repository.mu.RLock()
		data, ok := repository.files[request.URL.Path]
		repository.mu.RUnlock()
		if !ok {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	}))
	repository.client = repository.server.Client()
	repository.client.Timeout = 5 * time.Second
	t.Cleanup(repository.server.Close)
	return repository
}

func (repository *pluginRepositoryTestServer) publish(version int64, targets []pluginRepositoryTestTarget) {
	repository.t.Helper()
	expires := time.Now().Add(7 * 24 * time.Hour)
	targetsMetadata := tufmetadata.Targets(expires)
	targetsMetadata.Signed.Version = version
	files := make(map[string][]byte)
	for _, target := range targets {
		info, err := tufmetadata.TargetFile().FromBytes(target.path, target.archive, "sha256")
		if err != nil {
			repository.t.Fatal(err)
		}
		custom, err := json.Marshal(pluginRepositoryTargetMetadata{
			FormatVersion: pluginRepositoryTargetFormatVersion, Kind: pluginRepositoryTargetKind,
			PluginID: target.pluginID, Name: target.pluginID, Version: target.version, Channel: target.channel, Stability: target.stability,
			Compatibility: target.compatibility, Dependencies: target.dependencies, Conflicts: target.conflicts,
			Revoked: target.revoked, RevocationReason: target.reason,
		})
		if err != nil {
			repository.t.Fatal(err)
		}
		customRaw := json.RawMessage(custom)
		info.Custom = &customRaw
		targetsMetadata.Signed.Targets[target.path] = info
		digest := hex.EncodeToString(info.Hashes["sha256"])
		directory, base := path.Split(target.path)
		remote := "/targets/" + directory + digest + "." + base
		files[remote] = append([]byte(nil), target.archive...)
	}
	pluginRepositorySignMetadata(repository.t, targetsMetadata, repository.keys[tufmetadata.TARGETS])

	snapshotMetadata := tufmetadata.Snapshot(expires)
	snapshotMetadata.Signed.Version = version
	snapshotMetadata.Signed.Meta["targets.json"] = tufmetadata.MetaFile(version)
	pluginRepositorySignMetadata(repository.t, snapshotMetadata, repository.keys[tufmetadata.SNAPSHOT])

	timestampMetadata := tufmetadata.Timestamp(time.Now().Add(24 * time.Hour))
	timestampMetadata.Signed.Version = version
	timestampMetadata.Signed.Meta["snapshot.json"] = tufmetadata.MetaFile(version)
	pluginRepositorySignMetadata(repository.t, timestampMetadata, repository.keys[tufmetadata.TIMESTAMP])

	metadataValues := []struct {
		path string
		meta interface{ ToBytes(bool) ([]byte, error) }
	}{
		{path: fmt.Sprintf("/metadata/%d.targets.json", version), meta: targetsMetadata},
		{path: fmt.Sprintf("/metadata/%d.snapshot.json", version), meta: snapshotMetadata},
		{path: "/metadata/timestamp.json", meta: timestampMetadata},
	}
	for _, item := range metadataValues {
		data, err := item.meta.ToBytes(false)
		if err != nil {
			repository.t.Fatal(err)
		}
		files[item.path] = data
	}
	repository.mu.Lock()
	repository.files = files
	repository.mu.Unlock()
}

func pluginRepositorySignMetadata[T tufmetadata.Roles](t *testing.T, value *tufmetadata.Metadata[T], privateKey ed25519.PrivateKey) {
	t.Helper()
	signer, err := signature.LoadSigner(privateKey, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := value.Sign(signer); err != nil {
		t.Fatal(err)
	}
}

func (repository *pluginRepositoryTestServer) request(id, channel string) PluginRepositoryRequest {
	return PluginRepositoryRequest{
		ID: id, Name: "Test Repository", MetadataURL: repository.server.URL + "/metadata/",
		TargetsURL: repository.server.URL + "/targets/", Channel: channel, Root: repository.root,
	}
}

func TestPluginRepositoryRequiresHTTPSAndValidTUFRoot(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	_, err := manager.AddRepository(PluginRepositoryRequest{
		ID: "insecure", Name: "Insecure", MetadataURL: "http://example.test/metadata/",
		TargetsURL: "https://example.test/targets/", Channel: "stable", Root: json.RawMessage(`{}`),
	})
	if err == nil || !strings.Contains(err.Error(), "absolute HTTPS") {
		t.Fatalf("insecure repository error = %v", err)
	}
	_, err = manager.AddRepository(PluginRepositoryRequest{
		ID: "bad_root", Name: "Bad Root", MetadataURL: "https://example.test/metadata/",
		TargetsURL: "https://example.test/targets/", Channel: "stable", Root: json.RawMessage(`{}`),
	})
	if err == nil || !strings.Contains(err.Error(), "valid TUF metadata") {
		t.Fatalf("invalid root repository error = %v", err)
	}
}

func TestPluginRepositoryStagesTrustedPackageAndPreventsDowngrade(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	repositoryServer := newPluginRepositoryTestServer(t)
	archiveV1 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "repo_plugin", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	archiveV2 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "repo_plugin", Version: "2.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	repositoryServer.publish(1, []pluginRepositoryTestTarget{
		{path: "plugins/stable/repo_plugin/1.0.0/package.tar.gz", archive: archiveV1, pluginID: "repo_plugin", version: "1.0.0", channel: "stable", stability: "stable"},
		{path: "plugins/stable/repo_plugin/2.0.0/package.tar.gz", archive: archiveV2, pluginID: "repo_plugin", version: "2.0.0", channel: "stable", stability: "stable"},
	})
	repository, err := manager.AddRepository(repositoryServer.request("official", "stable"))
	if err != nil {
		t.Fatalf("AddRepository() error = %v", err)
	}
	manager.repositoryHTTPClient = repositoryServer.client
	catalog, err := manager.RefreshRepository(repository.ID)
	if err != nil || len(catalog.Targets) != 2 || catalog.TargetsVersion != 1 {
		t.Fatalf("RefreshRepository() = %+v, err=%v", catalog, err)
	}
	stage, err := manager.StageFromRepository(PluginRepositoryStageRequest{RepositoryID: repository.ID, PluginID: "repo_plugin"})
	if err != nil {
		t.Fatalf("StageFromRepository(latest) error = %v", err)
	}
	if !stage.Trusted || stage.TrustSource != "tuf" || stage.Version != "2.0.0" || stage.RepositoryVersion != 1 {
		t.Fatalf("repository stage = %+v", stage)
	}
	loaded, err := manager.LoadStage(stage.ID)
	if err != nil || !loaded.Trusted || loaded.RepositoryTarget != stage.RepositoryTarget {
		t.Fatalf("LoadStage(repository) = %+v, err=%v", loaded, err)
	}
	result, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest})
	if err != nil || result.Version != "2.0.0" {
		t.Fatalf("ApplyStage(repository) = %+v, err=%v", result, err)
	}

	_, err = manager.StageFromRepository(PluginRepositoryStageRequest{RepositoryID: repository.ID, PluginID: "repo_plugin", Version: "1.0.0"})
	if err == nil || (!strings.Contains(err.Error(), "highest trusted version") && !strings.Contains(err.Error(), "not newer")) {
		t.Fatalf("repository downgrade error = %v", err)
	}
}

func TestPluginRepositoryProvenanceSurvivesUpdateRollbackAndUninstall(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	repositoryServer := newPluginRepositoryTestServer(t)
	archiveV1 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "provenance_plugin", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	archiveV2 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "provenance_plugin", Version: "2.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	repositoryServer.publish(1, []pluginRepositoryTestTarget{
		{path: "plugins/stable/provenance_plugin/1.0.0/package.tar.gz", archive: archiveV1, pluginID: "provenance_plugin", version: "1.0.0", channel: "stable", stability: "stable"},
		{path: "plugins/stable/provenance_plugin/2.0.0/package.tar.gz", archive: archiveV2, pluginID: "provenance_plugin", version: "2.0.0", channel: "stable", stability: "stable"},
	})
	repository, err := manager.AddRepository(repositoryServer.request("provenance_repo", "stable"))
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = repositoryServer.client

	stageV1, err := manager.StageFromRepository(PluginRepositoryStageRequest{
		RepositoryID: repository.ID, PluginID: "provenance_plugin", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stageV1.ID, ApprovedPrivilegeDigest: stageV1.PrivilegeDigest}); err != nil {
		t.Fatal(err)
	}
	assertPluginPackageProvenanceVersion(t, manager, "provenance_plugin", "1.0.0")

	stageV2, err := manager.StageFromRepository(PluginRepositoryStageRequest{
		RepositoryID: repository.ID, PluginID: "provenance_plugin", Version: "2.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stageV2.ID, ApprovedPrivilegeDigest: stageV2.PrivilegeDigest}); err != nil {
		t.Fatal(err)
	}
	assertPluginPackageProvenanceVersion(t, manager, "provenance_plugin", "2.0.0")
	history, err := manager.ListHistory("provenance_plugin")
	if err != nil || len(history) != 1 || history[0].Provenance == nil || history[0].Provenance.Version != "1.0.0" {
		t.Fatalf("history after repository update = %+v, err=%v", history, err)
	}

	rollback, err := manager.PrepareRollback(PluginPackageRollbackRequest{PluginID: "provenance_plugin", HistoryID: history[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if rollback.Provenance == nil || rollback.Provenance.Version != "1.0.0" {
		t.Fatalf("rollback provenance = %+v", rollback.Provenance)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: rollback.ID, ApprovedPrivilegeDigest: rollback.PrivilegeDigest}); err != nil {
		t.Fatal(err)
	}
	assertPluginPackageProvenanceVersion(t, manager, "provenance_plugin", "1.0.0")
	statuses, err := manager.ListPluginPackageProvenance()
	if err != nil || len(statuses) != 1 || statuses[0].Status != "trusted" {
		t.Fatalf("installed provenance statuses = %+v, err=%v", statuses, err)
	}

	if _, err := manager.Uninstall(PluginPackageUninstallRequest{PluginID: "provenance_plugin"}); err != nil {
		t.Fatal(err)
	}
	if provenance, err := manager.loadPluginPackageProvenance("provenance_plugin"); err != nil || provenance != nil {
		t.Fatalf("provenance after uninstall = %+v, err=%v", provenance, err)
	}
	history, err = manager.ListHistory("provenance_plugin")
	if err != nil || len(history) < 1 || history[0].Reason != "uninstalled" || history[0].Provenance == nil || history[0].Provenance.Version != "1.0.0" {
		t.Fatalf("history after uninstall = %+v, err=%v", history, err)
	}
}

func TestPluginRepositoryInstallPlanStagesDependencyClosureAtomically(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	repositoryServer := newPluginRepositoryTestServer(t)
	dependency := PluginDependency{ID: "plan_dependency", Version: ">=1.0.0 <2.0.0"}
	dependencyArchive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "plan_dependency", Version: "1.1.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	rootArchive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "plan_root", Version: "2.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Dependencies: []PluginDependency{dependency},
		Control: `exports.onReconcile = function () {};`,
	})
	repositoryServer.publish(1, []pluginRepositoryTestTarget{
		{
			path: "plugins/stable/plan_dependency/1.1.0/package.tar.gz", archive: dependencyArchive,
			pluginID: "plan_dependency", version: "1.1.0", channel: "stable", stability: "stable",
		},
		{
			path: "plugins/stable/plan_root/2.0.0/package.tar.gz", archive: rootArchive,
			pluginID: "plan_root", version: "2.0.0", channel: "stable", stability: "stable",
			dependencies: []PluginDependency{dependency},
		},
	})
	repository, err := manager.AddRepository(repositoryServer.request("plan_repo", "stable"))
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = repositoryServer.client
	plan, err := manager.PrepareRepositoryInstallPlan(PluginRepositoryInstallPlanRequest{
		RepositoryID: repository.ID, PluginID: "plan_root",
	})
	if err != nil {
		t.Fatalf("PrepareRepositoryInstallPlan() error = %v", err)
	}
	if plan.RepositoryID != repository.ID || plan.RequestedPlugin != "plan_root" || len(plan.Stages) != 2 || len(plan.Reused) != 0 {
		t.Fatalf("repository install plan = %+v", plan)
	}
	requests := make([]PluginPackageApplyRequest, 0, len(plan.Stages))
	for _, stage := range plan.Stages {
		if !stage.DeferredRelationships || !stage.Trusted || stage.TrustSource != "tuf" {
			t.Fatalf("planned stage = %+v", stage)
		}
		requests = append(requests, PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest})
	}
	result, err := manager.ApplyBatch(PluginPackageBatchApplyRequest{Stages: requests})
	if err != nil {
		t.Fatalf("ApplyBatch(repository plan) error = %v", err)
	}
	if len(result.Plugins) != 2 {
		t.Fatalf("repository plan apply result = %+v", result)
	}
	for pluginID, version := range map[string]string{"plan_dependency": "1.1.0", "plan_root": "2.0.0"} {
		plugin, err := manager.loadCurrentPlugin(pluginID)
		if err != nil || plugin == nil || plugin.Version != version {
			t.Fatalf("installed plugin %s = %+v, err=%v", pluginID, plugin, err)
		}
		assertPluginPackageProvenanceVersion(t, manager, pluginID, version)
	}
}

func TestPluginRepositoryInstallPlanReusesSatisfiedInstalledDependency(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	installPluginPackageForTest(t, manager, buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "plan_reused", Version: "1.5.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	}))
	repositoryServer := newPluginRepositoryTestServer(t)
	dependency := PluginDependency{ID: "plan_reused", Version: ">=1.0.0 <2.0.0"}
	rootArchive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "plan_reuse_root", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Dependencies: []PluginDependency{dependency},
		Control: `exports.onReconcile = function () {};`,
	})
	repositoryServer.publish(1, []pluginRepositoryTestTarget{{
		path: "plugins/stable/plan_reuse_root/1.0.0/package.tar.gz", archive: rootArchive,
		pluginID: "plan_reuse_root", version: "1.0.0", channel: "stable", stability: "stable",
		dependencies: []PluginDependency{dependency},
	}})
	repository, err := manager.AddRepository(repositoryServer.request("plan_reuse_repo", "stable"))
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = repositoryServer.client
	plan, err := manager.PrepareRepositoryInstallPlan(PluginRepositoryInstallPlanRequest{RepositoryID: repository.ID, PluginID: "plan_reuse_root"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Stages) != 1 || plan.Stages[0].PluginID != "plan_reuse_root" || len(plan.Reused) != 1 ||
		plan.Reused[0].PluginID != "plan_reused" || plan.Reused[0].Version != "1.5.0" {
		t.Fatalf("repository reuse plan = %+v", plan)
	}
}

func TestPluginRepositoryInstallPlanBacktracksAcrossSharedDependencyConstraints(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	repositoryServer := newPluginRepositoryTestServer(t)
	leftV2Dependency := PluginDependency{ID: "plan_shared", Version: "<2.0.0"}
	leftV1Dependency := PluginDependency{ID: "plan_shared", Version: ">=2.0.0 <3.0.0"}
	rightDependency := PluginDependency{ID: "plan_shared", Version: ">=2.0.0 <3.0.0"}
	rootDependencies := []PluginDependency{{ID: "plan_left", Version: "*"}, {ID: "plan_right", Version: "*"}}
	makeArchive := func(id, version string, dependencies []PluginDependency) []byte {
		return buildPluginPackageForTest(t, pluginPackageTestSpec{
			ID: id, Version: version, Stability: pluginStabilityStable,
			Permissions: []string{"plugin.register"}, Dependencies: dependencies,
			Control: `exports.onReconcile = function () {};`,
		})
	}
	target := func(id, version string, archive []byte, dependencies []PluginDependency) pluginRepositoryTestTarget {
		return pluginRepositoryTestTarget{
			path: "plugins/stable/" + id + "/" + version + "/package.tar.gz", archive: archive,
			pluginID: id, version: version, channel: "stable", stability: "stable", dependencies: dependencies,
		}
	}
	repositoryServer.publish(1, []pluginRepositoryTestTarget{
		target("plan_solver_root", "1.0.0", makeArchive("plan_solver_root", "1.0.0", rootDependencies), rootDependencies),
		target("plan_left", "1.0.0", makeArchive("plan_left", "1.0.0", []PluginDependency{leftV1Dependency}), []PluginDependency{leftV1Dependency}),
		target("plan_left", "2.0.0", makeArchive("plan_left", "2.0.0", []PluginDependency{leftV2Dependency}), []PluginDependency{leftV2Dependency}),
		target("plan_right", "1.0.0", makeArchive("plan_right", "1.0.0", []PluginDependency{rightDependency}), []PluginDependency{rightDependency}),
		target("plan_shared", "2.1.0", makeArchive("plan_shared", "2.1.0", nil), nil),
	})
	repository, err := manager.AddRepository(repositoryServer.request("plan_solver_repo", "stable"))
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = repositoryServer.client
	plan, err := manager.PrepareRepositoryInstallPlan(PluginRepositoryInstallPlanRequest{RepositoryID: repository.ID, PluginID: "plan_solver_root"})
	if err != nil {
		t.Fatalf("PrepareRepositoryInstallPlan(backtracking) error = %v", err)
	}
	versions := make(map[string]string, len(plan.Stages))
	for _, stage := range plan.Stages {
		versions[stage.PluginID] = stage.Version
	}
	want := map[string]string{"plan_solver_root": "1.0.0", "plan_left": "1.0.0", "plan_right": "1.0.0", "plan_shared": "2.1.0"}
	if !reflect.DeepEqual(versions, want) {
		t.Fatalf("backtracked repository plan versions = %+v, want %+v", versions, want)
	}
}

func assertPluginPackageProvenanceVersion(t *testing.T, manager *pluginPackageManager, pluginID, version string) {
	t.Helper()
	provenance, err := manager.loadPluginPackageProvenance(pluginID)
	if err != nil || provenance == nil || provenance.Version != version || provenance.PluginID != pluginID || provenance.AppliedAt == "" {
		t.Fatalf("plugin %s provenance = %+v, err=%v; want version %s", pluginID, provenance, err, version)
	}
}

func TestPluginRepositoryRevocationInvalidatesPendingStage(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	repositoryServer := newPluginRepositoryTestServer(t)
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "revoked_plugin", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	target := pluginRepositoryTestTarget{
		path: "plugins/stable/revoked_plugin/1.0.0/package.tar.gz", archive: archive,
		pluginID: "revoked_plugin", version: "1.0.0", channel: "stable", stability: "stable",
	}
	repositoryServer.publish(1, []pluginRepositoryTestTarget{target})
	repository, err := manager.AddRepository(repositoryServer.request("revocations", "stable"))
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = repositoryServer.client
	stage, err := manager.StageFromRepository(PluginRepositoryStageRequest{RepositoryID: repository.ID, PluginID: "revoked_plugin"})
	if err != nil {
		t.Fatalf("StageFromRepository() error = %v", err)
	}
	target.revoked = true
	target.reason = "publisher security advisory"
	repositoryServer.publish(2, []pluginRepositoryTestTarget{target})
	if _, err := manager.LoadStage(stage.ID); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("LoadStage(revoked) error = %v", err)
	}
}

func TestPluginRepositoryTargetDigestCannotChangeAtSameVersion(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	repository := PluginRepository{ID: "ledger"}
	first := PluginRepositoryTarget{PluginID: "same_version", Version: "1.0.0", SHA256: strings.Repeat("a", sha256.Size*2), Target: "plugins/a.tar.gz"}
	if err := manager.recordPluginRepositoryVersion(repository, first); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.SHA256 = strings.Repeat("b", sha256.Size*2)
	if err := manager.checkPluginRepositoryLedger(repository, changed); err == nil || !strings.Contains(err.Error(), "changed digest") {
		t.Fatalf("same-version digest change error = %v", err)
	}

	if bytes.Equal([]byte(first.SHA256), []byte(changed.SHA256)) {
		t.Fatal("test digest setup is invalid")
	}
}
