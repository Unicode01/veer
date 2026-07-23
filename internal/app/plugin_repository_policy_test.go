package app

import (
	"strings"
	"testing"
)

func TestPluginRepositoryPolicyPinsAndHoldsInstalledVersion(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	repositoryServer := newPluginRepositoryTestServer(t)
	archiveV1 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "policy_plugin", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	archiveV2 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "policy_plugin", Version: "2.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	repositoryServer.publish(1, []pluginRepositoryTestTarget{
		{path: "plugins/stable/policy_plugin/1.0.0/package.tar.gz", archive: archiveV1, pluginID: "policy_plugin", version: "1.0.0", channel: "stable", stability: "stable"},
		{path: "plugins/stable/policy_plugin/2.0.0/package.tar.gz", archive: archiveV2, pluginID: "policy_plugin", version: "2.0.0", channel: "stable", stability: "stable"},
	})
	repository, err := manager.AddRepository(repositoryServer.request("policy_repo", "stable"))
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = repositoryServer.client
	if _, err := manager.RefreshRepository(repository.ID); err != nil {
		t.Fatal(err)
	}
	policy, err := manager.SetRepositoryPolicy(PluginRepositoryPolicyRequest{
		PluginID: "policy_plugin", RepositoryID: repository.ID, Channel: "stable", PinnedVersion: "1.0.0",
	})
	if err != nil || policy.PinnedVersion != "1.0.0" {
		t.Fatalf("SetRepositoryPolicy(pin) = %+v/%v", policy, err)
	}
	stage, err := manager.StageFromRepository(PluginRepositoryStageRequest{RepositoryID: repository.ID, PluginID: "policy_plugin"})
	if err != nil || stage.Version != "1.0.0" {
		t.Fatalf("StageFromRepository(pinned) = %+v/%v", stage, err)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetRepositoryPolicy(PluginRepositoryPolicyRequest{
		PluginID: "policy_plugin", RepositoryID: repository.ID, Channel: "stable", PinnedVersion: "2.0.0", Hold: true,
	}); err == nil || !strings.Contains(err.Error(), "hold requires") {
		t.Fatalf("contradictory hold/pin error = %v", err)
	}
	policy, err = manager.SetRepositoryPolicy(PluginRepositoryPolicyRequest{
		PluginID: "policy_plugin", RepositoryID: repository.ID, Channel: "stable", Hold: true,
	})
	if err != nil || !policy.Hold || policy.CreatedAt == policy.UpdatedAt {
		t.Fatalf("SetRepositoryPolicy(hold) = %+v/%v", policy, err)
	}
	if _, err := manager.StageFromRepository(PluginRepositoryStageRequest{
		RepositoryID: repository.ID, PluginID: "policy_plugin", Version: "2.0.0",
	}); err == nil || !strings.Contains(err.Error(), "on hold") {
		t.Fatalf("held update error = %v", err)
	}
	updates, err := manager.ListRepositoryUpdates()
	if err != nil || len(updates) != 1 || updates[0].Status != pluginRepositoryUpdateHeld || updates[0].AvailableVersion != "2.0.0" {
		t.Fatalf("ListRepositoryUpdates(held) = %+v/%v", updates, err)
	}
	if err := manager.DeleteRepository(repository.ID); err == nil || !strings.Contains(err.Error(), "referenced by policy") {
		t.Fatalf("DeleteRepository(with policy) error = %v", err)
	}
	if err := manager.DeleteRepositoryPolicy("policy_plugin"); err != nil {
		t.Fatal(err)
	}
}

func TestPluginRepositoryPolicyConstrainsDependencySolver(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	repositoryServer := newPluginRepositoryTestServer(t)
	dependencyV1 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "policy_dependency", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	dependencyV2 := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "policy_dependency", Version: "2.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
	})
	dependency := PluginDependency{ID: "policy_dependency", Version: ">=1.0.0 <3.0.0"}
	root := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "policy_root", Version: "1.0.0", Stability: pluginStabilityStable,
		Permissions: []string{"plugin.register"}, Dependencies: []PluginDependency{dependency}, Control: `exports.onReconcile = function () {};`,
	})
	repositoryServer.publish(1, []pluginRepositoryTestTarget{
		{path: "plugins/stable/policy_dependency/1.0.0/package.tar.gz", archive: dependencyV1, pluginID: "policy_dependency", version: "1.0.0", channel: "stable", stability: "stable"},
		{path: "plugins/stable/policy_dependency/2.0.0/package.tar.gz", archive: dependencyV2, pluginID: "policy_dependency", version: "2.0.0", channel: "stable", stability: "stable"},
		{path: "plugins/stable/policy_root/1.0.0/package.tar.gz", archive: root, pluginID: "policy_root", version: "1.0.0", channel: "stable", stability: "stable", dependencies: []PluginDependency{dependency}},
	})
	repository, err := manager.AddRepository(repositoryServer.request("policy_solver", "stable"))
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = repositoryServer.client
	stage, err := manager.StageFromRepository(PluginRepositoryStageRequest{
		RepositoryID: repository.ID, PluginID: "policy_dependency", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetRepositoryPolicy(PluginRepositoryPolicyRequest{
		PluginID: "policy_dependency", RepositoryID: repository.ID, Channel: "stable", Hold: true,
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := manager.PrepareRepositoryInstallPlan(PluginRepositoryInstallPlanRequest{RepositoryID: repository.ID, PluginID: "policy_root"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Stages) != 1 || plan.Stages[0].PluginID != "policy_root" || len(plan.Reused) != 1 ||
		plan.Reused[0].PluginID != "policy_dependency" || plan.Reused[0].Version != "1.0.0" {
		t.Fatalf("dependency plan ignored hold policy: %+v", plan)
	}
}
