package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pluginBinaryTestELF() []byte {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	machine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_AARCH64
	}
	binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(data[18:], uint16(machine))
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	return data
}

func pluginBinaryTestArchive(t *testing.T, format, name string, data []byte, kind byte) []byte {
	t.Helper()
	if format == "raw" {
		return data
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if format == "tar.gz" {
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0700, Typeflag: kind, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		if _, err := gz.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func pluginBinaryTestStore(t *testing.T, handler http.HandlerFunc) (*pluginBinaryStore, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	store, err := newPluginBinaryStore(&Config{PluginsDir: filepath.Join(t.TempDir(), "plugins")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.client = server.Client()
	t.Cleanup(func() { store.cancelOwner("", true) })
	return store, server.URL
}

func pluginBinaryTestInstall(t *testing.T, s *pluginBinaryStore, req pluginBinaryRequest) pluginBinaryStatus {
	t.Helper()
	if _, err := s.Install("vpn_test", req); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	done := s.jobs["vpn_test/"+req.ID].done
	s.mu.Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("binary installation did not finish")
	}
	status, err := s.Status("vpn_test", req.ID)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func pluginBinaryTestRequest(raw string, data []byte) pluginBinaryRequest {
	hash := sha256.Sum256(data)
	return pluginBinaryRequest{ID: "mihomo", Version: "v1.0.0", URL: raw, SHA256: hex.EncodeToString(hash[:]), Executable: "mihomo", Format: "raw"}
}

func TestPluginBinaryImmutableInstallSelectRollbackAndPersistence(t *testing.T) {
	data := pluginBinaryTestELF()
	s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) })
	req := pluginBinaryTestRequest(raw, data)
	first := pluginBinaryTestInstall(t, s, req)
	if first.Install.State != "ready" || first.Version != req.Version || len(first.Versions) != 1 {
		t.Fatalf("first install: %+v", first)
	}
	if !strings.Contains(first.Directory, "plugins.veer-state") || strings.Contains(first.Path, ".staging") {
		t.Fatalf("not persistent: %s", first.Path)
	}
	req.Version = "v2.0.0"
	second := pluginBinaryTestInstall(t, s, req)
	if second.Install.State != "ready" || second.Previous != first.Version || second.Version != req.Version || second.Path == first.Path {
		t.Fatalf("update: %+v", second)
	}
	if _, err := os.Stat(first.Path); err != nil {
		t.Fatal("old version was overwritten", err)
	}
	// Package replacement leaves the persistent artifact store intact.
	cfg := &Config{PluginsDir: strings.TrimSuffix(filepath.Dir(s.root), pluginPackageStateSuffix)}
	if err := os.RemoveAll(cfg.PluginsDir); err != nil {
		t.Fatal(err)
	}
	reopened, err := newPluginBinaryStore(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.cancelOwner("", true)
	status, err := reopened.Status("vpn_test", req.ID)
	if err != nil || status.Version != second.Version {
		t.Fatalf("restart lost selection: %+v %v", status, err)
	}
	status, err = reopened.Select("vpn_test", req.ID, status.Previous)
	if err != nil || status.Version != first.Version || status.Previous != second.Version {
		t.Fatalf("rollback: %+v %v", status, err)
	}
	if _, err = reopened.Remove("vpn_test", req.ID, first.Version); err == nil {
		t.Fatal("removed selected version")
	}
	if status, err = reopened.Remove("vpn_test", req.ID, second.Version); err != nil || len(status.Versions) != 1 || status.Previous != "" {
		t.Fatalf("remove: %+v %v", status, err)
	}
}

func TestPluginBinaryFailedUpdatesPreserveDefaultAndCleanStages(t *testing.T) {
	data := pluginBinaryTestELF()
	wrong := append([]byte(nil), data...)
	wrong[18] ^= 1
	s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wrong" {
			_, _ = w.Write(wrong)
		} else {
			_, _ = w.Write(data)
		}
	})
	req := pluginBinaryTestRequest(raw, data)
	first := pluginBinaryTestInstall(t, s, req)
	for _, kind := range []string{"checksum", "not_elf", "wrong_arch", "bad_check"} {
		t.Run(kind, func(t *testing.T) {
			bad := req
			bad.Version = "v2.0.0"
			switch kind {
			case "checksum":
				bad.SHA256 = strings.Repeat("0", 64)
			case "not_elf":
				bad.Format = "gzip"
			case "wrong_arch":
				bad.URL = raw + "/wrong"
				hash := sha256.Sum256(wrong)
				bad.SHA256 = hex.EncodeToString(hash[:])
			case "bad_check":
				bad.CheckArgs = []string{"--version"}
			}
			status := pluginBinaryTestInstall(t, s, bad)
			if status.Install.State != "failed" || status.Install.Error == "" || status.Version != first.Version || status.Path != first.Path || len(status.Versions) != 1 {
				t.Fatalf("failed update affected default: %+v", status)
			}
			entries, err := os.ReadDir(filepath.Join(s.root, ".staging"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("leaked install staging: %v %v", entries, err)
			}
		})
	}
}

func TestPluginBinaryExtractOnlyExpectedRegularExecutable(t *testing.T) {
	for _, format := range []string{"raw", "gzip", "tar.gz"} {
		t.Run(format, func(t *testing.T) {
			data := pluginBinaryTestELF()
			archive := pluginBinaryTestArchive(t, format, "release/mihomo", data, tar.TypeReg)
			file := filepath.Join(t.TempDir(), "mihomo")
			info, err := extractPluginBinary(context.Background(), bytes.NewReader(archive), file, pluginBinaryRequest{Format: format, ArchivePath: "release/mihomo"})
			if err != nil || info.Bytes != int64(len(data)) {
				t.Fatalf("extract: %+v %v", info, err)
			}
			actual, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(actual, data) {
				t.Fatal("binary differs", err)
			}
		})
	}
	for _, name := range []string{"../mihomo", "/mihomo", "release/../mihomo", "release\\mihomo", "missing/mihomo"} {
		t.Run(name, func(t *testing.T) {
			archive := pluginBinaryTestArchive(t, "tar.gz", "release/mihomo", pluginBinaryTestELF(), tar.TypeReg)
			if _, err := extractPluginBinary(context.Background(), bytes.NewReader(archive), filepath.Join(t.TempDir(), "mihomo"), pluginBinaryRequest{Format: "tar.gz", ArchivePath: name}); err == nil {
				t.Fatal("accepted invalid or absent member")
			}
		})
	}
	archive := pluginBinaryTestArchive(t, "tar.gz", "release/mihomo", nil, tar.TypeSymlink)
	if _, err := extractPluginBinary(context.Background(), bytes.NewReader(archive), filepath.Join(t.TempDir(), "mihomo"), pluginBinaryRequest{Format: "tar.gz", ArchivePath: "release/mihomo"}); err == nil {
		t.Fatal("accepted symlink")
	}
}

type pluginBinaryRoundTrip func(*http.Request) (*http.Response, error)

func (fn pluginBinaryRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestPluginBinaryOfficialReleaseDigestResolution(t *testing.T) {
	data := pluginBinaryTestArchive(t, "gzip", "", pluginBinaryTestELF(), tar.TypeReg)
	digest := sha256.Sum256(data)
	var badDigest atomic.Bool
	s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			hash := "sha256:" + hex.EncodeToString(digest[:])
			if badDigest.Load() {
				hash = ""
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.2.3", "assets": []any{map[string]any{"name": "mihomo-v1.2.3.gz", "digest": hash, "browser_download_url": "https://" + r.Host + "/artifact"}}})
			return
		}
		_, _ = w.Write(data)
	})
	transport := s.client.Transport
	s.client.Transport = pluginBinaryRoundTrip(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		copyURL := *req.URL
		clone.URL = &copyURL
		if clone.URL.Host == "api.github.com" {
			u, _ := url.Parse(raw)
			clone.URL.Host = u.Host
		}
		return transport.RoundTrip(clone)
	})
	req := pluginBinaryRequest{ID: "mihomo", Executable: "mihomo", Format: "gzip", ReleaseURL: "https://api.github.com/repos/example/core/releases/latest", Asset: "mihomo-{tag}.gz"}
	status := pluginBinaryTestInstall(t, s, req)
	if status.Install.State != "ready" || status.Version != "v1.2.3" {
		t.Fatalf("release install: %+v", status)
	}
	badDigest.Store(true)
	status = pluginBinaryTestInstall(t, s, req)
	if status.Install.State != "failed" || !strings.Contains(status.Install.Error, "SHA256") {
		t.Fatalf("missing digest accepted: %+v", status)
	}
}

func TestPluginBinaryCancelAndBusyInstall(t *testing.T) {
	started := make(chan struct{})
	s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() })
	req := pluginBinaryTestRequest(raw, pluginBinaryTestELF())
	if _, err := s.Install("vpn_test", req); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not start")
	}
	if _, err := s.Install("vpn_test", req); err == nil {
		t.Fatal("concurrent install accepted")
	}
	s.cancelOwner("vpn_test", false)
	status, err := s.Status("vpn_test", req.ID)
	if err != nil || status.Install.State != "failed" || status.Version != "" {
		t.Fatalf("cancelled install published: %+v %v", status, err)
	}
}

func TestPluginBinaryRejectsUnsafeSourcesOwnersAndChangedArtifacts(t *testing.T) {
	data := pluginBinaryTestELF()
	s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) })
	req := pluginBinaryTestRequest(raw, data)
	for _, source := range []string{"http://example.com/core", "file:///etc/passwd", "https://user:secret@example.com/core", "https://example.com/core#fragment"} {
		bad := req
		bad.URL = source
		if _, err := s.Install("vpn_test", bad); err == nil {
			t.Fatalf("accepted unsafe URL %s", source)
		}
	}
	for _, id := range []string{"../other", "/tmp", "bad.id"} {
		if _, err := s.Status("vpn_test", id); err == nil {
			t.Fatalf("accepted id %s", id)
		}
	}
	status := pluginBinaryTestInstall(t, s, req)
	if err := os.WriteFile(status.Path, bytes.Repeat([]byte{'x'}, len(data)), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Select("vpn_test", req.ID, req.Version); err == nil {
		t.Fatal("selected modified executable")
	}
}

func TestPluginBinaryVersionsAndRunningReferenceLimits(t *testing.T) {
	data := pluginBinaryTestELF()
	s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) })
	req := pluginBinaryTestRequest(raw, data)
	var first pluginBinaryStatus
	for version := 1; version <= 4; version++ {
		req.Version = fmt.Sprintf("v%d.0.0", version)
		status := pluginBinaryTestInstall(t, s, req)
		if status.Install.State != "ready" {
			t.Fatal(status.Install)
		}
		if version == 1 {
			first = status
		}
	}
	req.Version = "v5.0.0"
	status := pluginBinaryTestInstall(t, s, req)
	if status.Install.State != "failed" || status.Version != "v4.0.0" || len(status.Versions) != 4 {
		t.Fatal("version quota corrupted default", status)
	}
	s.registry = &pluginProcessRegistry{entries: map[string]*pluginManagedProcess{"vpn_test/core": {command: first.Path}}}
	if _, err := s.Remove("vpn_test", req.ID, first.Version); err == nil {
		t.Fatal("deleted referenced executable")
	}
	delete(s.registry.entries, "vpn_test/core")
	if _, err := s.Remove("vpn_test", req.ID, first.Version); err != nil {
		t.Fatal(err)
	}
}

func TestPluginBinaryNoSymlinksAndBackupExcludesStaging(t *testing.T) {
	s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) {})
	_ = raw
	status, err := s.Status("vpn_test", "mihomo")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(t.TempDir(), filepath.Join(status.Directory, "v1.0.0")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err = s.Status("vpn_test", "mihomo"); err == nil {
		t.Fatal("followed version directory symlink")
	}
	if !pluginStateBackupSkipVolatile("cores/.staging/123-core/download", nil) || pluginStateBackupSkipVolatile("cores/vpn_test/mihomo/linux-amd64/v1/mihomo", nil) {
		t.Fatal("incorrect backup staging exclusion")
	}
}

// Installed binaries use the same real core version probes as production.
func TestPluginBinaryRealCores(t *testing.T) {
	if os.Getenv("VEER_RUN_VPN_CORE_TESTS") != "1" {
		t.Skip("requires real downloaded VPN cores")
	}
	for _, driver := range []string{"mihomo", "sing_box"} {
		t.Run(driver, func(t *testing.T) {
			executable, envName, format, member, check := "mihomo", "VEER_TEST_MIHOMO", "gzip", "", []string{"-v"}
			if driver == "sing_box" {
				executable, envName, format, member, check = "sing-box", "VEER_TEST_SING_BOX", "tar.gz", "release/sing-box", []string{"version"}
			}
			file, err := os.Open(os.Getenv(envName))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			fi, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			archive, err := os.CreateTemp(t.TempDir(), "core")
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			gz := gzip.NewWriter(archive)
			var target io.Writer = gz
			var tw *tar.Writer
			if format == "tar.gz" {
				tw = tar.NewWriter(gz)
				if err = tw.WriteHeader(&tar.Header{Name: member, Size: fi.Size(), Mode: 0700, Typeflag: tar.TypeReg}); err != nil {
					t.Fatal(err)
				}
				target = tw
			}
			if _, err = io.Copy(target, file); err != nil {
				t.Fatal(err)
			}
			if tw != nil {
				if err = tw.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err = gz.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = archive.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			hash := sha256.New()
			if _, err = io.Copy(hash, archive); err != nil {
				t.Fatal(err)
			}
			s, raw := pluginBinaryTestStore(t, func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, archive.Name()) })
			req := pluginBinaryRequest{ID: driver, Version: "vtest", URL: raw, SHA256: hex.EncodeToString(hash.Sum(nil)), Executable: executable, Format: format, ArchivePath: member, CheckArgs: check}
			status := pluginBinaryTestInstall(t, s, req)
			if status.Install.State != "ready" {
				t.Fatalf("real core failed install: %+v", status.Install)
			}
			if _, err = os.Stat(status.Path); err != nil {
				t.Fatal(err)
			}
		})
	}
}
