package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func FuzzNormalizePluginPackageEntryName(f *testing.F) {
	for _, seed := range []string{
		"plugin/plugin.json",
		"./plugin/ui/index.html",
		"../escape",
		"plugin/../../escape",
		"/absolute",
		"plugin\\windows",
		"plugin/\x00invalid",
		"0:/0",
		"plugin/file:stream",
		"plugin/NUL",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		name, err := normalizePluginPackageEntryName(value)
		if err != nil || name == "" {
			return
		}
		if name != path.Clean(name) || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") ||
			strings.ContainsAny(name, "\\\x00") {
			t.Fatalf("accepted unsafe archive entry %q as %q", value, name)
		}
		root := filepath.Join(os.TempDir(), "veer-fuzz-extract-root")
		target := filepath.Join(root, filepath.FromSlash(name))
		if target == root || !pathWithinRoot(root, target) {
			t.Fatalf("accepted archive entry escapes extraction root: %q", name)
		}
	})
}

func FuzzExtractPluginPackageArchive(f *testing.F) {
	f.Add([]byte("not a gzip stream"))
	f.Add(pluginPackageFuzzArchive("plugin/plugin.json", []byte(`{"api_version":"v1"}`)))
	f.Add(pluginPackageFuzzArchive("../escape", []byte("escape")))
	f.Fuzz(func(t *testing.T, archive []byte) {
		if len(archive) == 0 || len(archive) > 1<<20 {
			return
		}
		root := t.TempDir()
		archivePath := filepath.Join(root, "candidate.tar.gz")
		if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
			t.Fatal(err)
		}
		sentinelPath := filepath.Join(root, "sentinel")
		const sentinel = "unchanged"
		if err := os.WriteFile(sentinelPath, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(root, "extract")
		pluginRoot, err := extractPluginPackageArchive(archivePath, destination)
		if current, readErr := os.ReadFile(sentinelPath); readErr != nil || string(current) != sentinel {
			t.Fatalf("archive extraction modified a path outside its root: content=%q err=%v", current, readErr)
		}
		if err != nil {
			return
		}
		if !pathWithinRoot(destination, pluginRoot) || pluginRoot == destination {
			t.Fatalf("successful extraction returned unsafe plugin root %q", pluginRoot)
		}
		if walkErr := filepath.WalkDir(destination, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !pathWithinRoot(destination, current) && current != destination {
				t.Fatalf("archive extraction created an out-of-root path %q", current)
			}
			if info, infoErr := entry.Info(); infoErr != nil {
				return infoErr
			} else if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				t.Fatalf("archive extraction created unsupported file mode %s at %q", info.Mode(), current)
			}
			return nil
		}); walkErr != nil {
			t.Fatal(walkErr)
		}
	})
}

func FuzzPluginManifestDecodeAndNormalize(f *testing.F) {
	f.Add([]byte(`{"api_version":"v1","id":"fuzz_plugin","name":"Fuzz","version":"1.0.0","kind":"control","stability":"lab"}`))
	f.Add([]byte(`{"id":"../escape","name":"bad","version":"1.0.0"}`))
	f.Add([]byte(`{"id":"duplicate","id":"other","name":"duplicate","version":"1.0.0"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > pluginPackageMaxEntryBytes {
			return
		}
		var manifest PluginManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return
		}
		if err := normalizePluginManifest(&manifest); err != nil {
			return
		}
		if !pluginIDPattern.MatchString(manifest.ID) || reservedBuiltinPluginID(manifest.ID) || manifest.Name == "" || manifest.Version == "" {
			t.Fatalf("manifest normalization accepted an invalid identity: %+v", manifest)
		}
	})
}

func FuzzPluginHostFrameDecode(f *testing.F) {
	f.Add(framedPluginHostJSON(`{"type":"event","id":1,"payload":{"ok":true}}`))
	f.Add(framedPluginHostJSON(`{"type":"event","type":"shutdown"}`))
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		message, err := newPluginHostFrameReader(bytes.NewReader(data), 64<<10).Read()
		if err != nil {
			return
		}
		if strings.TrimSpace(message.Type) == "" || len(message.Error) > pluginHostMaxErrorBytes {
			t.Fatalf("frame decoder accepted an invalid message: %+v", message)
		}
	})
}

func FuzzDecodePluginBlobHeader(f *testing.F) {
	header, err := encodePluginBlobHeader(pluginBlobHeader{
		FormatVersion: pluginBlobFormatVersion,
		Key:           "state",
		Bytes:         3,
		SHA256:        strings.Repeat("0", 64),
		CreatedAt:     "2026-01-01T00:00:00Z",
		UpdatedAt:     "2026-01-01T00:00:00Z",
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(header, uint16(3))
	f.Add([]byte("not a blob header"), uint16(0))
	f.Fuzz(func(t *testing.T, input []byte, payloadBytes uint16) {
		if len(input) > pluginBlobHeaderBytes {
			return
		}
		data := make([]byte, pluginBlobHeaderBytes)
		copy(data, input)
		decoded, err := decodePluginBlobHeader(data, "state", 1<<20, pluginBlobHeaderBytes+int64(payloadBytes))
		if err != nil {
			return
		}
		if decoded.FormatVersion != pluginBlobFormatVersion || decoded.Key != "state" || decoded.Bytes != int64(payloadBytes) || len(decoded.SHA256) != 64 {
			t.Fatalf("accepted inconsistent blob header: %+v, payload_bytes=%d", decoded, payloadBytes)
		}
	})
}

func FuzzNormalizePluginOperationJSONAndStatus(f *testing.F) {
	for _, seed := range []struct {
		value  string
		status string
	}{
		{`null`, "pending"},
		{`{"step":1,"nested":{"ok":true}}`, "running"},
		{`[1,2,3] trailing`, "retry_wait"},
		{strings.Repeat("[", 80) + strings.Repeat("]", 80), "completed"},
		{`{"unterminated":`, "unknown"},
	} {
		f.Add([]byte(seed.value), seed.status, int64(0))
	}
	f.Fuzz(func(t *testing.T, input []byte, status string, nextAttempt int64) {
		if len(input) <= pluginOperationMaxFieldBytes {
			normalized, err := normalizePluginOperationJSON(input, "operation fuzz")
			if err == nil && (!json.Valid(normalized) || len(normalized) > pluginOperationMaxFieldBytes) {
				t.Fatalf("operation normalization returned invalid output: %q", normalized)
			}
		}
		known := map[string]bool{
			"pending": true, "running": true, "retry_wait": true,
			"completed": true, "failed": true, "cancelled": true,
		}
		if pluginOperationStatus(status) != known[status] {
			t.Fatalf("operation status classification accepted %q", status)
		}
		item := storePluginOperationForFuzz(status, nextAttempt)
		if pluginOperationTerminal(status) && pluginOperationResumable(item, 0) {
			t.Fatalf("terminal operation %q is resumable", status)
		}
	})
}

func FuzzPluginOperationSecretEnvelope(f *testing.F) {
	key := bytes.Repeat([]byte{0x5a}, pluginSecretMasterKeyBytes)
	keyID := pluginSecretKeyID(key)
	secrets := &pluginSecretStore{activeID: keyID, keys: map[string][]byte{keyID: key}}
	const operationID = "00000000000000000000000000000001"
	valid, err := secrets.encryptJSON("fuzz_plugin", pluginOperationSecretResourceID, operationID, "state", []byte(`{"step":1}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(valid))
	f.Add([]byte(`{"$veer_secret":{"v":1,"kid":"00000000000000000000000000000000","nonce":"AA==","ciphertext":"AA=="}}`))
	f.Add([]byte(`not-an-envelope`))
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) == 0 || len(value) > pluginOperationMaxEnvelopeBytes {
			return
		}
		item := storePluginOperationForFuzz("pending", 0)
		item.OperationID = operationID
		item.PluginID = "fuzz_plugin"
		plaintext, err := decryptPluginOperationPayload(secrets, item, "state", string(value))
		if err == nil && (!json.Valid(plaintext) || len(plaintext) > pluginOperationMaxFieldBytes) {
			t.Fatalf("operation envelope returned invalid plaintext: %q", plaintext)
		}
	})
}

func storePluginOperationForFuzz(status string, nextAttempt int64) store.PluginOperation {
	return store.PluginOperation{Status: status, NextAttemptUnixMS: nextAttempt}
}

func TestPluginSecurityJSONRejectsDuplicateKeys(t *testing.T) {
	var manifest PluginManifest
	if err := json.Unmarshal([]byte(`{"id":"first","id":"second","name":"Duplicate","version":"1.0.0"}`), &manifest); err == nil ||
		!strings.Contains(err.Error(), `duplicate key "id"`) {
		t.Fatalf("duplicate manifest key error = %v", err)
	}
	var metadata pluginRepositoryTargetMetadata
	if err := decodePluginRepositoryJSON([]byte(`{"format_version":1,"kind":"veer-plugin","plugin_id":"first","plugin_id":"second"}`), &metadata); err == nil ||
		!strings.Contains(err.Error(), `duplicate key "plugin_id"`) {
		t.Fatalf("duplicate repository metadata key error = %v", err)
	}
}

func TestPluginSecurityJSONRejectsExcessiveDepth(t *testing.T) {
	data := []byte(strings.Repeat(`{"nested":`, pluginJSONMaxDepth+1) + `true` + strings.Repeat(`}`, pluginJSONMaxDepth+1))
	if err := rejectPluginDuplicateJSONKeys(data); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("deep JSON error = %v", err)
	}
}

func pluginPackageFuzzArchive(name string, data []byte) []byte {
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	_ = tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg})
	_, _ = tarWriter.Write(data)
	_ = tarWriter.Close()
	_ = gzipWriter.Close()
	return output.Bytes()
}
