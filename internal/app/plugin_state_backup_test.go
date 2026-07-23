package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	storepkg "github.com/Unicode01/veer/internal/store"
)

func TestPluginStateBackupRestoreEndToEnd(t *testing.T) {
	sourceRoot := t.TempDir()
	sourceDB := filepath.Join(sourceRoot, "forward.db")
	sourcePlugins := filepath.Join(sourceRoot, "plugins")
	preparePluginStateBackupFixture(t, sourceDB, sourcePlugins, "restored")

	archive := filepath.Join(sourceRoot, "plugin-state.tar.gz")
	output := runPluginPackageCLIForTest(t, "backup", "--database", sourceDB, "--plugins-dir", sourcePlugins, "--output", archive)
	var backup pluginStateBackupResult
	if err := json.Unmarshal(output, &backup); err != nil {
		t.Fatal(err)
	}
	if backup.ArchiveSHA256 == "" || backup.Files < 4 || backup.Bytes == 0 {
		t.Fatalf("backup result = %+v", backup)
	}

	targetRoot := t.TempDir()
	targetDB := filepath.Join(targetRoot, "forward.db")
	targetPlugins := filepath.Join(targetRoot, "plugins")
	preparePluginStateBackupFixture(t, targetDB, targetPlugins, "original")
	stageOutput := runPluginPackageCLIForTest(t, "restore", "--archive", archive, "--database", targetDB, "--plugins-dir", targetPlugins)
	var staged pluginStateRestoreStageResult
	if err := json.Unmarshal(stageOutput, &staged); err != nil {
		t.Fatal(err)
	}
	if !staged.RestartRequired || staged.ArchiveSHA256 != backup.ArchiveSHA256 {
		t.Fatalf("restore stage result = %+v", staged)
	}

	result, err := recoverPendingPluginStateRestore(targetDB, targetPlugins)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || result.Failed {
		t.Fatalf("restore result = %+v", result)
	}
	assertPluginStateBackupFixture(t, targetDB, targetPlugins, "restored")
	for _, path := range []string{staged.JournalPath, targetDB + pluginStateRestoreJournalSuffix} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("restore metadata %s remains: %v", path, err)
		}
	}
}

func TestPluginStateBackupRestorePreservesEncryptedOperation(t *testing.T) {
	sourceRoot := t.TempDir()
	sourceDB := filepath.Join(sourceRoot, "forward.db")
	sourcePlugins := filepath.Join(sourceRoot, "plugins")
	preparePluginStateBackupFixture(t, sourceDB, sourcePlugins, "restored")
	addPluginStateBackupOperationFixture(t, sourceDB, "operation-backup-secret")

	archive := filepath.Join(sourceRoot, "plugin-state.tar.gz")
	runPluginPackageCLIForTest(t, "backup", "--database", sourceDB, "--plugins-dir", sourcePlugins, "--output", archive)

	targetRoot := t.TempDir()
	targetDB := filepath.Join(targetRoot, "forward.db")
	targetPlugins := filepath.Join(targetRoot, "plugins")
	preparePluginStateBackupFixture(t, targetDB, targetPlugins, "original")
	output := runPluginPackageCLIForTest(t, "restore", "--archive", archive, "--database", targetDB, "--plugins-dir", targetPlugins)
	var staged pluginStateRestoreStageResult
	if err := json.Unmarshal(output, &staged); err != nil {
		t.Fatal(err)
	}
	result, err := recoverPendingPluginStateRestore(targetDB, targetPlugins)
	if err != nil || !result.Applied || result.Failed {
		t.Fatalf("restore encrypted operation result = %+v, err=%v", result, err)
	}

	db, err := initDB(targetDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := storepkg.PluginOperationByKey(db, "state_plugin", "backup")
	if err != nil || operation == nil {
		t.Fatalf("restored operation = %+v, err=%v", operation, err)
	}
	plaintext, err := decryptPluginOperationPayload(secrets, *operation, "input", operation.InputJSON)
	if err != nil || string(plaintext) != `{"password":"operation-backup-secret"}` {
		t.Fatalf("restored operation input = %s, err=%v", plaintext, err)
	}
}

func TestPluginStateRestoreRejectsCorruptOperationCiphertext(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "forward.db")
	pluginsRoot := filepath.Join(root, "plugins")
	preparePluginStateBackupFixture(t, database, pluginsRoot, "corrupt")
	addPluginStateBackupOperationFixture(t, database, "private")
	db, err := initDB(database)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := storepkg.PluginOperationByKey(db, "state_plugin", "backup")
	if err != nil || operation == nil {
		_ = db.Close()
		t.Fatalf("stored operation = %+v, err=%v", operation, err)
	}
	operation.InputJSON = corruptPluginOperationCiphertextForTest(t, operation.InputJSON)
	if err := storepkg.RewritePluginOperationPayloads(db, *operation); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginStateSecretEnvelopes(database, true); err == nil || !strings.Contains(err.Error(), "authenticate plugin secret") {
		t.Fatalf("corrupt operation restore validation error = %v", err)
	}
}

func TestPluginStateRestoreContinuesPartialJournal(t *testing.T) {
	archive, targetDB, targetPlugins, journalPath := preparePluginStateRestoreTest(t)
	_ = archive
	journal := readPluginStateRestoreJournalForTest(t, journalPath)
	if err := refreshPluginStateRestorePayload(journal); err != nil {
		t.Fatal(err)
	}
	journal.Phase = pluginStateRestorePhaseApplying
	for index := range journal.Items {
		if err := preparePluginStateRestoreItem(&journal.Items[index]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
		t.Fatal(err)
	}
	if err := installPluginStateRestoreItem(journalPath, &journal, 0); err != nil {
		t.Fatal(err)
	}
	if err := installPluginStateRestoreItem(journalPath, &journal, 1); err != nil {
		t.Fatal(err)
	}

	result, err := recoverPendingPluginStateRestore(targetDB, targetPlugins)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || result.Failed {
		t.Fatalf("restore result = %+v", result)
	}
	assertPluginStateBackupFixture(t, targetDB, targetPlugins, "restored")
}

func TestPluginStateRestoreRollsBackPartialApplyWhenStageIsCorrupt(t *testing.T) {
	_, targetDB, targetPlugins, journalPath := preparePluginStateRestoreTest(t)
	journal := readPluginStateRestoreJournalForTest(t, journalPath)
	if err := refreshPluginStateRestorePayload(journal); err != nil {
		t.Fatal(err)
	}
	journal.Phase = pluginStateRestorePhaseApplying
	for index := range journal.Items {
		if err := preparePluginStateRestoreItem(&journal.Items[index]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
		t.Fatal(err)
	}
	if err := installPluginStateRestoreItem(journalPath, &journal, 0); err != nil {
		t.Fatal(err)
	}
	stagedArchive := filepath.Join(journal.StageRoot, "backup.tar.gz")
	file, err := os.OpenFile(stagedArchive, os.O_WRONLY, 0) // #nosec G304 -- private test path.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("corrupt"), 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := recoverPendingPluginStateRestore(targetDB, targetPlugins)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failed || result.Applied || !strings.Contains(result.Error, "SHA256") {
		t.Fatalf("restore result = %+v", result)
	}
	assertPluginStateBackupFixture(t, targetDB, targetPlugins, "original")
	failed := readPluginStateRestoreJournalForTest(t, journalPath)
	if failed.Phase != pluginStateRestorePhaseFailed {
		t.Fatalf("journal phase = %q", failed.Phase)
	}
}

func TestPluginStateBackupRejectsSymlinkSource(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "forward.db")
	pluginsRoot := filepath.Join(root, "plugins")
	preparePluginStateBackupFixture(t, database, pluginsRoot, "source")
	link := filepath.Join(pluginsRoot, "state_plugin", "linked.json")
	if err := os.Symlink(filepath.Join(pluginsRoot, "state_plugin", "plugin.json"), link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := runPluginPackageCLIWithError("backup", "--database", database, "--plugins-dir", pluginsRoot, "--output", filepath.Join(root, "backup.tar.gz")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("backup symlink error = %v", err)
	}
}

func TestPluginStateRestoreManagementRetryAndCancel(t *testing.T) {
	_, targetDB, targetPlugins, journalPath := preparePluginStateRestoreTest(t)
	status, err := managePluginStateRestore(targetDB, targetPlugins, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Pending || status.Phase != pluginStateRestorePhaseStaged {
		t.Fatalf("restore status = %+v", status)
	}

	journal := readPluginStateRestoreJournalForTest(t, journalPath)
	journal.Phase = pluginStateRestorePhaseFailed
	journal.LastError = "synthetic failure"
	if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
		t.Fatal(err)
	}
	retry, err := managePluginStateRestore(targetDB, targetPlugins, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.RetryStaged || retry.Phase != pluginStateRestorePhaseStaged {
		t.Fatalf("restore retry = %+v", retry)
	}
	result, err := recoverPendingPluginStateRestore(targetDB, targetPlugins)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied {
		t.Fatalf("retried restore result = %+v", result)
	}

	archive, cancelDB, cancelPlugins, cancelJournal := preparePluginStateRestoreTest(t)
	_ = archive
	cancelled, err := managePluginStateRestore(cancelDB, cancelPlugins, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !cancelled.Cancelled || cancelled.Pending {
		t.Fatalf("restore cancel = %+v", cancelled)
	}
	if _, err := os.Lstat(cancelJournal); !os.IsNotExist(err) {
		t.Fatalf("cancelled restore journal remains: %v", err)
	}
}

func preparePluginStateRestoreTest(t *testing.T) (archive, targetDB, targetPlugins, journalPath string) {
	t.Helper()
	sourceRoot := t.TempDir()
	sourceDB := filepath.Join(sourceRoot, "forward.db")
	sourcePlugins := filepath.Join(sourceRoot, "plugins")
	preparePluginStateBackupFixture(t, sourceDB, sourcePlugins, "restored")
	archive = filepath.Join(sourceRoot, "plugin-state.tar.gz")
	runPluginPackageCLIForTest(t, "backup", "--database", sourceDB, "--plugins-dir", sourcePlugins, "--output", archive)

	targetRoot := t.TempDir()
	targetDB = filepath.Join(targetRoot, "forward.db")
	targetPlugins = filepath.Join(targetRoot, "plugins")
	preparePluginStateBackupFixture(t, targetDB, targetPlugins, "original")
	output := runPluginPackageCLIForTest(t, "restore", "--archive", archive, "--database", targetDB, "--plugins-dir", targetPlugins)
	var staged pluginStateRestoreStageResult
	if err := json.Unmarshal(output, &staged); err != nil {
		t.Fatal(err)
	}
	return archive, targetDB, targetPlugins, staged.JournalPath
}

func preparePluginStateBackupFixture(t *testing.T, database, pluginsRoot, marker string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := initDB(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO rules (in_port, out_ip, out_port, remark) VALUES (41000, '192.0.2.10', 41000, ?)`, marker); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := storepkg.AddPluginRecord(db, &storepkg.PluginRecord{
		PluginID: "state_plugin", ResourceID: "settings", RecordKey: "default",
		DataJSON: `{"marker":` + mustPluginStateJSONString(t, marker) + `}`, Enabled: true,
	}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := newPluginSecretStore(db); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pluginsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestPlugin(t, pluginsRoot, "state_plugin", `{
  "api_version": "v1",
  "id": "state_plugin",
  "name": "State Plugin",
  "version": "1.0.0",
  "kind": "ui",
  "stability": "stable"
}`)
	if err := os.WriteFile(filepath.Join(pluginsRoot, "state_plugin", "marker.txt"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	stateRoot := pluginsRoot + pluginPackageStateSuffix
	if err := os.MkdirAll(filepath.Join(stateRoot, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "fixture.txt"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
}

func addPluginStateBackupOperationFixture(t *testing.T, database, password string) {
	t.Helper()
	db, err := initDB(database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	const operationID = "00000000000000000000000000000001"
	encrypt := func(field, value string) string {
		t.Helper()
		encrypted, err := secrets.encryptJSON("state_plugin", pluginOperationSecretResourceID, operationID, field, []byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return string(encrypted)
	}
	operation := storepkg.PluginOperation{
		OperationID: operationID, PluginID: "state_plugin", OperationKey: "backup", Kind: "router.apply", Status: "pending",
		InputJSON: encrypt("input", `{"password":`+mustPluginStateJSONString(t, password)+`}`),
		StateJSON: encrypt("state", `{"step":1}`), ResultJSON: encrypt("result", `null`), ErrorJSON: encrypt("error", `null`),
	}
	if err := storepkg.AddPluginOperation(db, operation); err != nil {
		t.Fatal(err)
	}
}

func assertPluginStateBackupFixture(t *testing.T, database, pluginsRoot, marker string) {
	t.Helper()
	db, err := initDB(database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var remark string
	if err := db.QueryRow(`SELECT remark FROM rules ORDER BY id LIMIT 1`).Scan(&remark); err != nil {
		t.Fatal(err)
	}
	if remark != marker {
		t.Fatalf("database marker = %q, want %q", remark, marker)
	}
	pluginMarker, err := os.ReadFile(filepath.Join(pluginsRoot, "state_plugin", "marker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	stateMarker, err := os.ReadFile(filepath.Join(pluginsRoot+pluginPackageStateSuffix, "fixture.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pluginMarker) != marker || string(stateMarker) != marker {
		t.Fatalf("restored markers plugin=%q state=%q want=%q", pluginMarker, stateMarker, marker)
	}
	if _, err := loadOrCreatePluginSecretKeyring(database + pluginSecretKeyFileSuffix); err != nil {
		t.Fatal(err)
	}
}

func readPluginStateRestoreJournalForTest(t *testing.T, path string) pluginStateRestoreJournal {
	t.Helper()
	var journal pluginStateRestoreJournal
	if err := readPluginPackageJSON(path, &journal); err != nil {
		t.Fatal(err)
	}
	return journal
}

func mustPluginStateJSONString(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
