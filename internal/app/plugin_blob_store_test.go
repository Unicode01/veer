package app

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPluginBlobStoreAtomicLifecycleAndPersistence(t *testing.T) {
	pluginsDir := filepath.Join(t.TempDir(), "plugins")
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir})
	store, err := newPluginBlobStore(cfg)
	if err != nil {
		t.Fatalf("newPluginBlobStore() error = %v", err)
	}
	first, err := store.Put("blob_plugin", "generation-a", "cache", []byte{0x01, 0x02, 0x03}, "")
	if err != nil {
		t.Fatalf("Put(first) error = %v", err)
	}
	if first.Bytes != 3 || first.SHA256 != sha256Hex([]byte{0x01, 0x02, 0x03}) {
		t.Fatalf("first blob = %+v", first)
	}
	read, err := store.Read("blob_plugin", "cache", 1, 1)
	if err != nil || string(read.Data) != "\x02" || read.EOF {
		t.Fatalf("Read(partial) = %+v/%v", read, err)
	}
	read, err = store.Read("blob_plugin", "cache", 2, 64)
	if err != nil || string(read.Data) != "\x03" || !read.EOF {
		t.Fatalf("Read(final) = %+v/%v", read, err)
	}
	second, err := store.Put("blob_plugin", "generation-a", "cache", []byte{0xaa}, "")
	if err != nil {
		t.Fatalf("Put(replace) error = %v", err)
	}
	if second.CreatedAt != first.CreatedAt || second.Bytes != 1 || second.SHA256 != sha256Hex([]byte{0xaa}) {
		t.Fatalf("replacement blob = %+v, first = %+v", second, first)
	}
	listed, err := store.List("blob_plugin", "", 100)
	if err != nil || len(listed) != 1 || listed[0].Key != "cache" {
		t.Fatalf("List() = %+v/%v", listed, err)
	}
	if _, err := store.Verify("blob_plugin", "cache"); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := newPluginBlobStore(cfg)
	if err != nil {
		t.Fatalf("reopen blob store error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	stat, err := reopened.Stat("blob_plugin", "cache")
	if err != nil || stat.SHA256 != second.SHA256 {
		t.Fatalf("Stat(after reopen) = %+v/%v", stat, err)
	}
	deleted, err := reopened.Delete("blob_plugin", "cache")
	if err != nil || !deleted {
		t.Fatalf("Delete() = %t/%v", deleted, err)
	}
	if _, err := reopened.Stat("blob_plugin", "cache"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(deleted) error = %v", err)
	}
}

func TestPluginBlobStoreChunkedUploadIntegrityAndGenerationIsolation(t *testing.T) {
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: filepath.Join(t.TempDir(), "plugins")})
	store, err := newPluginBlobStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	payload := []byte("abcdef")
	upload, err := store.Begin("blob_plugin", "generation-a", "routes", int64(len(payload)), sha256Hex(payload))
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if _, err := store.Write("blob_plugin", "generation-a", upload.UploadID, 1, payload[:3]); err == nil || !strings.Contains(err.Error(), "next offset 0") {
		t.Fatalf("Write(wrong offset) error = %v", err)
	}
	if _, err := store.Write("blob_plugin", "generation-b", upload.UploadID, 0, payload[:3]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cross-generation Write() error = %v", err)
	}
	if _, err := store.Write("blob_plugin", "generation-a", upload.UploadID, 0, payload[:3]); err != nil {
		t.Fatalf("Write(first) error = %v", err)
	}
	if _, err := store.Write("blob_plugin", "generation-a", upload.UploadID, 3, payload[3:]); err != nil {
		t.Fatalf("Write(second) error = %v", err)
	}
	info, err := store.Commit("blob_plugin", "generation-a", upload.UploadID)
	if err != nil || info.Bytes != int64(len(payload)) || info.SHA256 != sha256Hex(payload) {
		t.Fatalf("Commit() = %+v/%v", info, err)
	}

	bad, err := store.Begin("blob_plugin", "generation-a", "bad", 1, strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write("blob_plugin", "generation-a", bad.UploadID, 0, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit("blob_plugin", "generation-a", bad.UploadID); err == nil || !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("Commit(bad digest) error = %v", err)
	}
	if aborted := store.AbortGeneration("blob_plugin", "generation-a"); aborted != 1 {
		t.Fatalf("AbortGeneration() = %d, want 1", aborted)
	}
}

func TestPluginBlobStoreEnforcesObjectTemporaryAndCountQuotas(t *testing.T) {
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsDir: filepath.Join(t.TempDir(), "plugins"),
		PluginsResourceLimits: PluginResourceLimitConfig{
			BlobObjectsPerPlugin: 1, BlobObjectMB: 1, PluginBlobMB: 1, GlobalBlobMB: 1,
		},
	})
	store, err := newPluginBlobStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Begin("blob_plugin", "generation-a", "too_large", (1<<20)+1, ""); err == nil {
		t.Fatal("Begin() accepted an object above blob_object_mb")
	}
	if _, err := store.Put("blob_plugin", "generation-a", "one", []byte{0x01}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("blob_plugin", "generation-a", "two", []byte{0x02}, ""); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("Put(second object) error = %v", err)
	}
	first, err := store.Begin("temp_plugin", "generation-a", "one", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write("temp_plugin", "generation-a", first.UploadID, 0, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	second, err := store.Begin("temp_plugin", "generation-a", "two", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write("temp_plugin", "generation-a", second.UploadID, 0, []byte{0x01}); err == nil || !strings.Contains(err.Error(), "temporary quota") {
		t.Fatalf("Write(over temporary quota) error = %v", err)
	}
}

func TestPluginBlobStoreBackupIncludesCommittedDataAndSkipsUploads(t *testing.T) {
	root := t.TempDir()
	pluginsDir := filepath.Join(root, "plugins")
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir})
	store, err := newPluginBlobStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Put("blob_plugin", "generation-a", "committed", []byte("ok"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("blob_plugin", "generation-a", "pending", 0, ""); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, "snapshot.db")
	if err := os.WriteFile(database, []byte("database"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources, err := collectPluginStateBackupSources(database, "", pluginsDir)
	if err != nil {
		t.Fatal(err)
	}
	foundBlob := false
	for _, source := range sources {
		if strings.Contains(source.archivePath, pluginBlobUploadDirectoryName) || strings.HasSuffix(source.archivePath, pluginBlobUploadSuffix) {
			t.Fatalf("backup includes volatile upload %s", source.archivePath)
		}
		if source.archivePath == "state/blobs/blob_plugin/committed.blob" {
			foundBlob = true
		}
	}
	if !foundBlob {
		t.Fatalf("backup sources do not include committed blob: %+v", sources)
	}
}

func TestPluginBlobHeaderRejectsMalformedAndTrailingContent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	header := pluginBlobHeader{
		FormatVersion: pluginBlobFormatVersion,
		Key:           "state",
		Bytes:         1,
		SHA256:        sha256Hex([]byte{0x01}),
		CreatedAt:     now.Format(time.RFC3339Nano),
		UpdatedAt:     now.Format(time.RFC3339Nano),
	}
	valid, err := encodePluginBlobHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodePluginBlobHeader(valid, "state", 1024, pluginBlobHeaderBytes+1); err != nil || decoded != header {
		t.Fatalf("decode valid header = %+v/%v", decoded, err)
	}

	badMagic := append([]byte(nil), valid...)
	badMagic[0] ^= 0xff
	badLength := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(badLength[8:12], uint32(pluginBlobHeaderBytes))
	wrongKey := header
	wrongKey.Key = "other"
	wrongKeyBytes, err := encodePluginBlobHeader(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	unknownField := pluginBlobRawHeaderForTest(t, strings.TrimSuffix(string(pluginBlobJSONForTest(t, header)), "}")+`,"unknown":true}`)
	trailingJSON := pluginBlobRawHeaderForTest(t, string(pluginBlobJSONForTest(t, header))+` {}`)

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "short", data: valid[:pluginBlobHeaderBytes-1]},
		{name: "magic", data: badMagic},
		{name: "length", data: badLength},
		{name: "key", data: wrongKeyBytes},
		{name: "unknown_field", data: unknownField},
		{name: "trailing_json", data: trailingJSON},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodePluginBlobHeader(test.data, "state", 1024, pluginBlobHeaderBytes+1); err == nil {
				t.Fatalf("decodePluginBlobHeader(%s) accepted malformed data", test.name)
			}
		})
	}
}

func TestPluginBlobStoreRejectsInvalidOwnersPathsAndSymlinks(t *testing.T) {
	pluginsDir := filepath.Join(t.TempDir(), "plugins")
	store, err := newPluginBlobStore(pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for _, test := range []struct {
		pluginID   string
		generation string
		key        string
	}{
		{pluginID: "../escape", generation: "generation-a", key: "state"},
		{pluginID: "veer_core", generation: "generation-a", key: "state"},
		{pluginID: "blob_plugin", generation: "", key: "state"},
		{pluginID: "blob_plugin", generation: "generation-a", key: "../state"},
		{pluginID: "blob_plugin", generation: "generation-a", key: "nested/state"},
	} {
		if _, err := store.Begin(test.pluginID, test.generation, test.key, 0, ""); err == nil {
			t.Fatalf("Begin(%q, %q, %q) accepted an invalid owner or path", test.pluginID, test.generation, test.key)
		}
	}
	if _, err := store.Put("blob_plugin", "generation-a", "state", []byte("ok"), ""); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(store.blobRoot, "blob_plugin")
	if err := os.Symlink(filepath.Join(pluginDir, "state"+pluginBlobFileSuffix), filepath.Join(pluginDir, "alias"+pluginBlobFileSuffix)); err != nil {
		t.Skipf("symbolic links are unavailable in this test environment: %v", err)
	}
	if _, err := store.Stat("blob_plugin", "alias"); err == nil || !strings.Contains(err.Error(), "not a regular blob file") {
		t.Fatalf("Stat(symlink) error = %v", err)
	}
}

func TestPluginControlBlobAPIWorksAcrossHandlersAndWorkers(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "blob_control"), 0o755); err != nil {
		t.Fatal(err)
	}
	writePluginControlScript(t, dir, "blob_control", `
exports.onAction = function (ctx) {
  if (ctx.payload.op === 'put') {
    blob.put({key: 'state', payload_hex: '00010203'});
    worker.call('reader', 'readBlob', {});
    return;
  }
  var upload = blob.begin({key: 'chunked', expected_bytes: 3});
  blob.write({upload_id: upload.upload_id, offset: 0, payload_hex: 'aabb'});
  blob.write({upload_id: upload.upload_id, offset: 2, payload_hex: 'cc'});
  blob.commit({upload_id: upload.upload_id});
  kv.set('chunked', blob.read({key: 'chunked', offset: 1, max_bytes: 2}));
};
exports.readBlob = function () {
  var value = blob.read({key: 'state', offset: 1, max_bytes: 2});
  kv.set('worker_read', {payload: value.payload_hex, verified: blob.verify({key: 'state'}).verified});
};
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	plugin := testPersistentSocketPlugin(dir, "blob_control", []string{"blob", "kv", "worker"}, nil)
	action := PluginAction{ID: "blob"}
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"op":"put"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(put) error = %v", err)
	}
	workerRead := pluginControlKVDataForTest(t, db, plugin.ID, "worker_read")
	if workerRead["payload"] != "0102" || workerRead["verified"] != true {
		t.Fatalf("worker blob read = %+v", workerRead)
	}
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(`{"op":"chunk"}`)); err != nil {
		t.Fatalf("ApplyPluginAction(chunk) error = %v", err)
	}
	chunked := pluginControlKVDataForTest(t, db, plugin.ID, "chunked")
	if chunked["payload_hex"] != "bbcc" || chunked["eof"] != true {
		t.Fatalf("chunked blob read = %+v", chunked)
	}
}

func TestPluginControlUpgradeAbortsOldBlobUploadsAndKeepsCommittedData(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	writeTestPlugin(t, dir, "blob_upgrade", `{
  "api_version":"v1",
  "id":"blob_upgrade",
  "name":"Blob Upgrade",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "control":{"main":"control.js","permissions":["blob"]}
}`)
	writeVersion := func(version int) {
		writePluginControlScript(t, dir, "blob_upgrade", fmt.Sprintf(`
var version = %d;
exports.onUpgradeSnapshot = function () { return {schema_version: 1, version: version}; };
exports.onUpgradeRestore = function () {};
`, version))
	}
	writeVersion(1)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	first := runtime.Reconcile(loadPluginCatalogWithControlRegistrationAndState(cfg, db))
	if state := first.Plugins["blob_upgrade"]; state.Error != "" {
		t.Fatalf("initial blob plugin reconcile = %+v", state)
	}
	runtime.mu.Lock()
	oldVM := runtime.controlVMs["blob_upgrade"]
	runtime.mu.Unlock()
	if oldVM == nil || oldVM.key == "" {
		t.Fatal("initial blob plugin VM was not installed")
	}
	blobs, err := runtime.pluginBlobStoreOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	committed, err := blobs.Put("blob_upgrade", oldVM.key, "committed", []byte("keep"), "")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := blobs.Begin("blob_upgrade", oldVM.key, "pending", 4, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Write("blob_upgrade", oldVM.key, upload.UploadID, 0, []byte("pa")); err != nil {
		t.Fatal(err)
	}
	blobs.mu.Lock()
	pendingPath := blobs.uploads[upload.UploadID].path
	blobs.mu.Unlock()

	writeVersion(2)
	second := runtime.Reconcile(loadPluginCatalogWithControlRegistrationAndState(cfg, db))
	if state := second.Plugins["blob_upgrade"]; state.Error != "" {
		t.Fatalf("upgraded blob plugin reconcile = %+v", state)
	}
	runtime.mu.Lock()
	newVM := runtime.controlVMs["blob_upgrade"]
	runtime.mu.Unlock()
	if newVM == nil || newVM.key == oldVM.key {
		t.Fatalf("upgraded blob plugin VM = %+v, old key = %q", newVM, oldVM.key)
	}
	if _, err := blobs.Write("blob_upgrade", oldVM.key, upload.UploadID, 2, []byte("rt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old-generation blob upload remained writable: %v", err)
	}
	if _, err := os.Lstat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("old-generation blob upload file remained after upgrade: %v", err)
	}
	if info, err := blobs.Stat("blob_upgrade", "committed"); err != nil || info.SHA256 != committed.SHA256 {
		t.Fatalf("committed blob after upgrade = %+v/%v", info, err)
	}
	if _, err := blobs.Put("blob_upgrade", newVM.key, "after_upgrade", []byte("ok"), ""); err != nil {
		t.Fatalf("new-generation blob write failed: %v", err)
	}
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func pluginBlobJSONForTest(t *testing.T, header pluginBlobHeader) []byte {
	t.Helper()
	data, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func pluginBlobRawHeaderForTest(t *testing.T, data string) []byte {
	t.Helper()
	if len(data) > pluginBlobHeaderBytes-12 {
		t.Fatal("test blob header is too large")
	}
	out := make([]byte, pluginBlobHeaderBytes)
	copy(out[:8], pluginBlobMagic[:])
	binary.BigEndian.PutUint32(out[8:12], uint32(len(data)))
	copy(out[12:], data)
	return out
}
