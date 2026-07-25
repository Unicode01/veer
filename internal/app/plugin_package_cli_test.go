package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPluginPackageCLIEndToEnd(t *testing.T) {
	root := t.TempDir()
	writeTestPlugin(t, root, "cli_plugin", `{
  "api_version": "v1",
  "id": "cli_plugin",
  "name": "CLI Plugin",
  "version": "1.2.3",
  "kind": "ui",
  "stability": "stable"
}`)
	source := filepath.Join(root, "cli_plugin")
	archiveA := filepath.Join(root, "cli-plugin-a.tar.gz")
	archiveB := filepath.Join(root, "cli-plugin-b.tar.gz")
	packA := runPluginPackageCLIForTest(t, "pack", "--source", source, "--output", archiveA)
	packB := runPluginPackageCLIForTest(t, "pack", "--source", source, "--output", archiveB)
	var infoA, infoB pluginPackageCLIArchiveInfo
	if err := json.Unmarshal(packA, &infoA); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(packB, &infoB); err != nil {
		t.Fatal(err)
	}
	if infoA.PluginID != "cli_plugin" || infoA.Version != "1.2.3" || infoA.ArchiveSHA256 == "" || infoA.ArchiveSHA256 != infoB.ArchiveSHA256 {
		t.Fatalf("pack results A=%+v B=%+v", infoA, infoB)
	}
	dataA, err := os.ReadFile(archiveA)
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := os.ReadFile(archiveB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dataA, dataB) {
		t.Fatal("deterministic plugin pack produced different archive bytes")
	}

	privateKey := filepath.Join(root, "publisher.key")
	publicKey := filepath.Join(root, "publisher.pub")
	keygen := runPluginPackageCLIForTest(t, "keygen", "--private-key", privateKey, "--public-key", publicKey)
	var keyInfo map[string]any
	if err := json.Unmarshal(keygen, &keyInfo); err != nil || keyInfo["signer_id"] == "" {
		t.Fatalf("keygen result = %s, err=%v", keygen, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(privateKey)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode = %+v, err=%v", info, err)
		}
	}

	signedPath := filepath.Join(root, "cli-plugin.veerpkg")
	signed := runPluginPackageCLIForTest(t, "sign", "--archive", archiveA, "--private-key", privateKey, "--output", signedPath)
	var signInfo map[string]any
	if err := json.Unmarshal(signed, &signInfo); err != nil || signInfo["signer_id"] != keyInfo["signer_id"] || signInfo["package"] != signedPath {
		t.Fatalf("sign result = %s, err=%v", signed, err)
	}
	verified := runPluginPackageCLIForTest(t, "verify", "--package", signedPath, "--public-key", publicKey)
	var verifyInfo map[string]any
	if err := json.Unmarshal(verified, &verifyInfo); err != nil || verifyInfo["verified"] != true || verifyInfo["plugin_id"] != "cli_plugin" {
		t.Fatalf("verify result = %s, err=%v", verified, err)
	}

	otherPrivate := filepath.Join(root, "other.key")
	otherPublic := filepath.Join(root, "other.pub")
	runPluginPackageCLIForTest(t, "keygen", "--private-key", otherPrivate, "--public-key", otherPublic)
	if _, err := runPluginPackageCLIWithError("verify", "--package", signedPath, "--public-key", otherPublic); err == nil || !strings.Contains(err.Error(), "signer id") {
		t.Fatalf("verify with wrong public key error = %v", err)
	}

	extractedArchive := filepath.Join(root, "signed-payload.tar.gz")
	_, candidate, err := extractPluginPackageContainer(signedPath, extractedArchive)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.PublicKey != keyInfo["public_key"] || candidate.SignerID != keyInfo["signer_id"] {
		t.Fatalf("signed package identity = %+v, keygen=%+v", candidate, keyInfo)
	}
	metadata := pluginPackageSignatureFile{
		Version: 1, SignerID: candidate.SignerID, PublicKey: candidate.PublicKey,
		ArchiveSHA256: infoA.ArchiveSHA256, Signature: candidate.Signature, CreatedAt: "2026-01-01T00:00:00Z",
	}
	if err := os.WriteFile(signedPath, buildPluginPackageContainerForTest(t, dataA, metadata), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runPluginPackageCLIWithError("verify", "--package", signedPath, "--public-key", publicKey); err == nil || !strings.Contains(err.Error(), "version is unsupported") {
		t.Fatalf("verify with v1 metadata error = %v", err)
	}
	metadata.Version = pluginPackageSignatureFileVersion
	signature, err := base64.StdEncoding.DecodeString(metadata.Signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0xff
	metadata.Signature = base64.StdEncoding.EncodeToString(signature)
	if err := os.WriteFile(signedPath, buildPluginPackageContainerForTest(t, dataA, metadata), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runPluginPackageCLIWithError("verify", "--package", signedPath, "--public-key", publicKey); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("verify with tampered signature error = %v", err)
	}
}

func TestPluginPackageCLIRejectsUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	writeTestPlugin(t, root, "unsafe_plugin", `{
  "api_version": "v1",
  "id": "unsafe_plugin",
  "name": "Unsafe Plugin",
  "version": "1.0.0",
  "kind": "ui"
}`)
	source := filepath.Join(root, "unsafe_plugin")
	insideOutput := filepath.Join(source, "package.tar.gz")
	if _, err := runPluginPackageCLIWithError("pack", "--source", source, "--output", insideOutput); err == nil || !strings.Contains(err.Error(), "outside the source") {
		t.Fatalf("pack inside source error = %v", err)
	}
	archive := filepath.Join(root, "unsigned.tar.gz")
	runPluginPackageCLIForTest(t, "pack", "--source", source, "--output", archive)
	privateKey := filepath.Join(root, "publisher.key")
	publicKey := filepath.Join(root, "publisher.pub")
	runPluginPackageCLIForTest(t, "keygen", "--private-key", privateKey, "--public-key", publicKey)
	if _, err := runPluginPackageCLIWithError("sign", "--archive", archive, "--private-key", privateKey, "--output", filepath.Join(root, "legacy.sig")); err == nil || !strings.Contains(err.Error(), ".veerpkg extension") {
		t.Fatalf("sign with non-.veerpkg output error = %v", err)
	}
	if err := os.Symlink(filepath.Join(source, "plugin.json"), filepath.Join(source, "manifest-link")); err == nil {
		if _, err := runPluginPackageCLIWithError("pack", "--source", source, "--output", filepath.Join(root, "unsafe.tar.gz")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("pack symlink source error = %v", err)
		}
	}

	var stdout bytes.Buffer
	handled, err := runPluginPackageCLI([]string{"other"}, &stdout, &stdout)
	if handled || err != nil {
		t.Fatalf("non-plugin CLI handled=%v err=%v", handled, err)
	}
}

func runPluginPackageCLIForTest(t *testing.T, args ...string) []byte {
	t.Helper()
	output, err := runPluginPackageCLIWithError(args...)
	if err != nil {
		t.Fatalf("plugin CLI %v: %v", args, err)
	}
	return output
}

func runPluginPackageCLIWithError(args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	handled, err := runPluginPackageCLI(append([]string{"plugin"}, args...), &stdout, &stderr)
	if !handled {
		return nil, os.ErrInvalid
	}
	if err != nil && stderr.Len() > 0 {
		return stdout.Bytes(), &pluginPackageCLITestError{err: err, stderr: stderr.String()}
	}
	return stdout.Bytes(), err
}

type pluginPackageCLITestError struct {
	err    error
	stderr string
}

func (err *pluginPackageCLITestError) Error() string {
	return err.err.Error() + ": " + strings.TrimSpace(err.stderr)
}

func (err *pluginPackageCLITestError) Unwrap() error {
	return err.err
}
