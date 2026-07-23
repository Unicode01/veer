package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPluginRepositoryCLIWorkspaceLockIsExclusive(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "repository-workspace")
	runPluginPackageCLIForTest(t, "repository", "init", "--directory", workspace)
	_, lock, err := acquirePluginRepositoryPublisherLock(workspace)
	if err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	err = runPluginRepositoryCLI([]string{"status", "--directory", workspace}, &stdout, &stderr)
	if !errors.Is(err, errPluginRepositoryPublisherLocked) {
		t.Fatalf("status while publisher lock is held: stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runPluginRepositoryCLI([]string{"status", "--directory", workspace}, &stdout, &stderr); err != nil {
		t.Fatalf("status after publisher lock release: %v", err)
	}
}

func TestPluginRepositoryPublisherRecoversEveryPublishPhase(t *testing.T) {
	testCases := []struct {
		name         string
		phase        string
		moveOld      bool
		activateNext bool
		commitState  bool
		removeBackup bool
	}{
		{name: "prepared", phase: "prepared"},
		{name: "old renamed before phase write", phase: "prepared", moveOld: true},
		{name: "old moved", phase: "old_moved", moveOld: true},
		{name: "candidate activated before phase write", phase: "old_moved", moveOld: true, activateNext: true},
		{name: "new moved", phase: "new_moved", moveOld: true, activateNext: true},
		{name: "state committed", phase: "new_moved", moveOld: true, activateNext: true, commitState: true},
		{name: "backup cleaned", phase: "new_moved", moveOld: true, activateNext: true, commitState: true, removeBackup: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			workspace, current, candidate, journal := preparePluginRepositoryPublishRecoveryTest(t)
			publicDir := filepath.Join(workspace, "public")
			nextDir := filepath.Join(workspace, journal.NextDir)
			backupDir := filepath.Join(workspace, journal.BackupDir)
			journal.Phase = testCase.phase
			if testCase.moveOld {
				if err := os.Rename(publicDir, backupDir); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.activateNext {
				if err := os.Rename(nextDir, publicDir); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.commitState {
				if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), candidate, true); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.removeBackup {
				if err := removePluginPackageManagedPath(workspace, backupDir); err != nil {
					t.Fatal(err)
				}
			}
			if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherJournalFile), journal, false); err != nil {
				t.Fatal(err)
			}

			if err := recoverPluginRepositoryPublisherPublish(workspace); err != nil {
				t.Fatalf("recover publish from %s: %v", testCase.name, err)
			}
			var recovered pluginRepositoryPublisherState
			if err := readPluginRepositoryJSON(filepath.Join(workspace, pluginRepositoryPublisherStateFile), pluginRepositoryPublisherMaxStateBytes, &recovered); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(recovered, candidate) {
				t.Fatalf("recovered state = %+v, want %+v (previous %+v)", recovered, candidate, current)
			}
			if err := validatePluginRepositoryPublisherPublicTree(publicDir, candidate); err != nil {
				t.Fatalf("recovered public tree: %v", err)
			}
			for _, path := range []string{nextDir, backupDir, filepath.Join(workspace, pluginRepositoryPublisherJournalFile)} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("recovery artifact still exists at %s: %v", path, err)
				}
			}
		})
	}
}

func TestPluginRepositoryPublisherRejectsMissingPublishCandidate(t *testing.T) {
	workspace, current, _, journal := preparePluginRepositoryPublishRecoveryTest(t)
	if err := removePluginPackageManagedPath(workspace, filepath.Join(workspace, journal.NextDir)); err != nil {
		t.Fatal(err)
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherJournalFile), journal, false); err != nil {
		t.Fatal(err)
	}
	if err := recoverPluginRepositoryPublisherPublish(workspace); err == nil || !strings.Contains(err.Error(), "candidate and backup disappeared") {
		t.Fatalf("recover missing candidate error = %v", err)
	}
	var recovered pluginRepositoryPublisherState
	if err := readPluginRepositoryJSON(filepath.Join(workspace, pluginRepositoryPublisherStateFile), pluginRepositoryPublisherMaxStateBytes, &recovered); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recovered, current) {
		t.Fatalf("missing candidate changed state: got %+v want %+v", recovered, current)
	}
}

func TestPluginRepositoryPublisherRecoversEveryRotationPhase(t *testing.T) {
	testCases := []struct {
		name        string
		writeKey    bool
		writeRoot   bool
		commitState bool
	}{
		{name: "journal prepared"},
		{name: "key written", writeKey: true},
		{name: "root written", writeKey: true, writeRoot: true},
		{name: "state committed", writeKey: true, writeRoot: true, commitState: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			workspace := filepath.Join(t.TempDir(), "repository-workspace")
			runPluginPackageCLIForTest(t, "repository", "init", "--directory", workspace)
			_, previous, err := loadPluginRepositoryPublisherWorkspace(workspace)
			if err != nil {
				t.Fatal(err)
			}
			runPluginPackageCLIForTest(t, "repository", "rotate-key", "--directory", workspace, "--role", "root")
			_, candidate, err := loadPluginRepositoryPublisherWorkspace(workspace)
			if err != nil {
				t.Fatal(err)
			}
			keyPath := pluginRepositoryPublisherKeyPath(workspace, "root", candidate.KeyVersions["root"])
			rootPath := pluginRepositoryPublisherRootPath(workspace, candidate.RootVersion)
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			rootBytes, err := os.ReadFile(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			journal := pluginRepositoryPublisherRotationJournal{
				FormatVersion:  pluginRepositoryPublisherFormatVersion,
				Role:           "root",
				NewKeyVersion:  candidate.KeyVersions["root"],
				NewRootVersion: candidate.RootVersion,
				PrivateKeyPEM:  keyPEM,
				Root:           append(json.RawMessage(nil), rootBytes...),
				State:          candidate,
			}
			if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), previous, true); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(keyPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(rootPath); err != nil {
				t.Fatal(err)
			}
			if testCase.writeKey {
				if err := writePluginRepositoryPublisherFileIdempotent(keyPath, keyPEM, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.writeRoot {
				if err := writePluginRepositoryPublisherFileIdempotent(rootPath, rootBytes, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.commitState {
				if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), candidate, true); err != nil {
					t.Fatal(err)
				}
			}
			rotationPath := filepath.Join(workspace, "rotation.json")
			if err := writePluginPackageJSONAtomic(rotationPath, journal, false); err != nil {
				t.Fatal(err)
			}

			if err := recoverPluginRepositoryPublisherRotation(workspace); err != nil {
				t.Fatalf("recover rotation from %s: %v", testCase.name, err)
			}
			var recovered pluginRepositoryPublisherState
			if err := readPluginRepositoryJSON(filepath.Join(workspace, pluginRepositoryPublisherStateFile), pluginRepositoryPublisherMaxStateBytes, &recovered); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(recovered, candidate) {
				t.Fatalf("recovered rotation state = %+v, want %+v", recovered, candidate)
			}
			for path, expected := range map[string][]byte{keyPath: keyPEM, rootPath: rootBytes} {
				actual, err := os.ReadFile(path)
				if err != nil || !reflect.DeepEqual(actual, expected) {
					t.Fatalf("recovered rotation artifact %s does not match: err=%v", path, err)
				}
			}
			if _, err := os.Lstat(rotationPath); !os.IsNotExist(err) {
				t.Fatalf("rotation journal still exists: %v", err)
			}
		})
	}
}

func preparePluginRepositoryPublishRecoveryTest(t *testing.T) (string, pluginRepositoryPublisherState, pluginRepositoryPublisherState, pluginRepositoryPublisherJournal) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "repository-workspace")
	runPluginPackageCLIForTest(t, "repository", "init", "--directory", workspace)
	workspace, current, err := loadPluginRepositoryPublisherWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newPluginPackageID()
	if err != nil {
		t.Fatal(err)
	}
	nextName := ".public-next-" + id
	backupName := ".public-backup-" + id
	nextDir := filepath.Join(workspace, nextName)
	if err := os.Mkdir(nextDir, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := current
	candidate.MetadataVersion++
	candidate.UpdatedAt = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	if _, err := buildPluginRepositoryPublicTree(workspace, nextDir, current, candidate.MetadataVersion); err != nil {
		t.Fatal(err)
	}
	journal := pluginRepositoryPublisherJournal{
		FormatVersion: pluginRepositoryPublisherFormatVersion,
		ID:            id,
		Phase:         "prepared",
		NextDir:       nextName,
		BackupDir:     backupName,
		State:         candidate,
	}
	return workspace, current, candidate, journal
}

func TestPluginRepositoryCLIEndToEndWithClientAndKeyRotation(t *testing.T) {
	root := t.TempDir()
	writeTestPlugin(t, root, "repository_cli_plugin", `{
  "api_version": "v1",
  "id": "repository_cli_plugin",
  "name": "Repository CLI Plugin",
  "description": "Published through the Veer TUF CLI.",
  "version": "1.2.3",
  "kind": "ui",
  "stability": "stable"
}`)
	archive := filepath.Join(root, "repository-cli-plugin.tar.gz")
	runPluginPackageCLIForTest(t, "pack", "--source", filepath.Join(root, "repository_cli_plugin"), "--output", archive)
	workspace := filepath.Join(root, "repository-workspace")
	initOutput := runPluginPackageCLIForTest(t, "repository", "init", "--directory", workspace)
	var initResult map[string]any
	if err := json.Unmarshal(initOutput, &initResult); err != nil || initResult["metadata_version"] != float64(1) || initResult["target_count"] != float64(0) {
		t.Fatalf("repository init result = %s, err=%v", initOutput, err)
	}
	rootV1, err := os.ReadFile(filepath.Join(workspace, "public", "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	addOutput := runPluginPackageCLIForTest(t, "repository", "add", "--directory", workspace, "--archive", archive, "--channel", "stable")
	if !strings.Contains(string(addOutput), `"status": "added"`) {
		t.Fatalf("repository add result = %s", addOutput)
	}
	publishOutput := runPluginPackageCLIForTest(t, "repository", "publish", "--directory", workspace)
	var publishResult map[string]any
	if err := json.Unmarshal(publishOutput, &publishResult); err != nil || publishResult["metadata_version"] != float64(2) || publishResult["target_count"] != float64(1) {
		t.Fatalf("repository publish result = %s, err=%v", publishOutput, err)
	}
	assertPluginRepositoryPublicTreeContainsNoPrivateState(t, filepath.Join(workspace, "public"))

	server := httptest.NewTLSServer(http.FileServer(http.Dir(filepath.Join(workspace, "public"))))
	t.Cleanup(server.Close)
	manager := newPluginPackageManagerForTest(t)
	manager.suppressProbation = true
	repository, err := manager.AddRepository(PluginRepositoryRequest{
		ID: "cli_repository", Name: "CLI Repository",
		MetadataURL: server.URL + "/metadata/", TargetsURL: server.URL + "/targets/",
		Channel: "stable", Root: rootV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.repositoryHTTPClient = server.Client()
	initialCatalog, err := manager.RefreshRepository(repository.ID)
	if err != nil || len(initialCatalog.Targets) != 1 {
		targetsMetadata, _ := os.ReadFile(filepath.Join(workspace, "public", "metadata", "2.targets.json"))
		t.Fatalf("refresh CLI-published catalog = %+v, err=%v; targets=%s", initialCatalog, err, targetsMetadata)
	}
	stage, err := manager.StageFromRepository(PluginRepositoryStageRequest{RepositoryID: repository.ID, PluginID: "repository_cli_plugin"})
	if err != nil {
		t.Fatalf("stage CLI-published plugin: %v", err)
	}
	if stage.Name != "Repository CLI Plugin" || stage.Version != "1.2.3" || stage.RepositoryVersion != 2 {
		t.Fatalf("CLI-published stage = %+v", stage)
	}
	if _, err := manager.ApplyStage(PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest}); err != nil {
		t.Fatalf("apply CLI-published plugin: %v", err)
	}

	runPluginPackageCLIForTest(t, "repository", "revoke", "--directory", workspace,
		"--plugin", "repository_cli_plugin", "--version", "1.2.3", "--channel", "stable", "--reason", "security advisory")
	runPluginPackageCLIForTest(t, "repository", "publish", "--directory", workspace)
	if _, err := manager.RefreshRepository(repository.ID); err != nil {
		t.Fatalf("refresh revoked CLI repository: %v", err)
	}
	statuses, err := manager.ListPluginPackageProvenance()
	if err != nil || len(statuses) != 1 || statuses[0].Status != "revoked" || statuses[0].RevocationReason != "security advisory" {
		t.Fatalf("revoked CLI provenance = %+v, err=%v", statuses, err)
	}

	runPluginPackageCLIForTest(t, "repository", "rotate-key", "--directory", workspace, "--role", "root")
	if _, err := manager.RefreshRepository(repository.ID); err != nil {
		t.Fatalf("refresh after root rotation: %v", err)
	}
	runPluginPackageCLIForTest(t, "repository", "rotate-key", "--directory", workspace, "--role", "targets")
	catalog, err := manager.RefreshRepository(repository.ID)
	if err != nil || catalog.RootVersion != 3 {
		t.Fatalf("refresh after targets rotation = %+v, err=%v", catalog, err)
	}
	statusOutput := runPluginPackageCLIForTest(t, "repository", "status", "--directory", workspace)
	var status map[string]any
	if err := json.Unmarshal(statusOutput, &status); err != nil || status["root_version"] != float64(3) || status["metadata_version"] != float64(5) {
		t.Fatalf("repository status = %s, err=%v", statusOutput, err)
	}
}

func assertPluginRepositoryPublicTreeContainsNoPrivateState(t *testing.T, publicRoot string) {
	t.Helper()
	err := filepath.WalkDir(publicRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".pem") || name == pluginRepositoryPublisherStateFile || name == pluginRepositoryPublisherJournalFile || name == "rotation.json" {
			t.Fatalf("private publisher state leaked into public tree: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
