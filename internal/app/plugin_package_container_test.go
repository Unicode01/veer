package app

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

type pluginPackageContainerTestEntry struct {
	name   string
	data   []byte
	method uint16
	extra  []byte
}

func TestPluginPackageContainerRejectsAmbiguousAndUnsafeZIP(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "container_safety", Version: "1.0.0"})
	digest := sha256.Sum256(archive)
	candidate := signPluginPackageForTest(publicKey, privateKey, archive)
	metadata := pluginPackageSignatureFile{
		Version: pluginPackageSignatureFileVersion, SignerID: candidate.SignerID,
		PublicKey: candidate.PublicKey, ArchiveSHA256: hex.EncodeToString(digest[:]),
		Signature: candidate.Signature, CreatedAt: "2026-01-01T00:00:00Z",
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	validEntries := func() []pluginPackageContainerTestEntry {
		return []pluginPackageContainerTestEntry{
			{name: pluginPackageContainerArchiveName, data: archive, method: zip.Store},
			{name: pluginPackageContainerSignatureName, data: metadataData, method: zip.Store},
		}
	}

	tests := []struct {
		name    string
		entries func() []pluginPackageContainerTestEntry
		want    string
	}{
		{
			name: "unexpected entry",
			entries: func() []pluginPackageContainerTestEntry {
				entries := validEntries()
				entries[1].name = "publisher.json"
				return entries
			},
			want: "unexpected entry",
		},
		{
			name: "duplicate entry",
			entries: func() []pluginPackageContainerTestEntry {
				return []pluginPackageContainerTestEntry{
					{name: pluginPackageContainerArchiveName, data: archive, method: zip.Store},
					{name: pluginPackageContainerArchiveName, data: archive, method: zip.Store},
				}
			},
			want: "duplicate entry",
		},
		{
			name: "compressed payload",
			entries: func() []pluginPackageContainerTestEntry {
				entries := validEntries()
				entries[0].method = zip.Deflate
				return entries
			},
			want: "unsupported ZIP metadata",
		},
		{
			name: "extended metadata",
			entries: func() []pluginPackageContainerTestEntry {
				entries := validEntries()
				entries[0].extra = []byte{0x01, 0x00, 0x00, 0x00}
				return entries
			},
			want: "unsupported ZIP metadata",
		},
		{
			name: "payload digest mismatch",
			entries: func() []pluginPackageContainerTestEntry {
				bad := metadata
				bad.ArchiveSHA256 = strings.Repeat("0", sha256.Size*2)
				badData, err := json.Marshal(bad)
				if err != nil {
					t.Fatal(err)
				}
				entries := validEntries()
				entries[1].data = badData
				return entries
			},
			want: "payload digest does not match",
		},
		{
			name: "trailing signature JSON",
			entries: func() []pluginPackageContainerTestEntry {
				entries := validEntries()
				entries[1].data = append(append([]byte(nil), metadataData...), []byte("\n{}")...)
				return entries
			},
			want: "trailing JSON",
		},
		{
			name: "oversized signature metadata",
			entries: func() []pluginPackageContainerTestEntry {
				entries := validEntries()
				entries[1].data = bytes.Repeat([]byte{'x'}, pluginPackageMaxSignatureBytes+1)
				return entries
			},
			want: "signature metadata exceeds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newPluginPackageManagerForTest(t)
			container := buildCustomPluginPackageContainerForTest(t, test.entries())
			if _, err := manager.Stage(bytes.NewReader(container)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Stage() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPluginPackageContainerRejectsDirectoryCountBeforeZIPExpansion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "container_count", Version: "1.0.0"})
	container := signPluginPackageArchiveForTest(t, publicKey, privateKey, archive)
	if len(container) < 22 {
		t.Fatal("test container is too short")
	}
	end := container[len(container)-22:]
	binary.LittleEndian.PutUint16(end[8:10], 0xffff)
	binary.LittleEndian.PutUint16(end[10:12], 0xffff)
	manager := newPluginPackageManagerForTest(t)
	if _, err := manager.Stage(bytes.NewReader(container)); err == nil || !strings.Contains(err.Error(), "exactly two entries") {
		t.Fatalf("Stage(directory count) error = %v", err)
	}
}

func buildCustomPluginPackageContainerForTest(t testing.TB, entries []pluginPackageContainerTestEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: entry.method, Extra: entry.extra}
		header.SetMode(0o644)
		entryWriter, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entryWriter.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
