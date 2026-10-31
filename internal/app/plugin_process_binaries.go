package app

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

const (
	pluginBinaryMaxArchive  = 256 << 20
	pluginBinaryMaxFile     = 256 << 20
	pluginBinaryPluginQuota = 1 << 30
	pluginBinaryMaxVersions = 4
)

var pluginBinaryVersionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
var pluginBinaryExecutablePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var pluginBinaryReleasePathPattern = regexp.MustCompile(`^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/(latest|tags/[A-Za-z0-9._-]+)$`)

// Binaries are immutable, plugin-owned artifacts outside the replaceable package.
// Installation is asynchronous; changing the default never restarts a live WAN.
type pluginBinaryRequest struct {
	ID          string   `json:"id"`
	Version     string   `json:"version,omitempty"`
	URL         string   `json:"url,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	ReleaseURL  string   `json:"release_url,omitempty"`
	Asset       string   `json:"asset,omitempty"`
	Executable  string   `json:"executable"`
	Format      string   `json:"format"`
	ArchivePath string   `json:"archive_path,omitempty"`
	CheckArgs   []string `json:"check_args,omitempty"`
}

type pluginBinaryInfo struct {
	Version      string `json:"version"`
	Executable   string `json:"executable"`
	SHA256       string `json:"sha256"`
	BinarySHA256 string `json:"binary_sha256"`
	Bytes        int64  `json:"bytes"`
	Path         string `json:"path"`
	InstalledAt  string `json:"installed_at"`
}

type pluginBinarySelection struct {
	Version  string `json:"version"`
	Previous string `json:"previous,omitempty"`
}

type pluginBinaryProgress struct {
	State           string `json:"state"`
	Version         string `json:"version,omitempty"`
	DownloadedBytes int64  `json:"downloaded_bytes"`
	TotalBytes      int64  `json:"total_bytes,omitempty"`
	Error           string `json:"error,omitempty"`
}

type pluginBinaryStatus struct {
	ID        string                `json:"id"`
	Directory string                `json:"directory"`
	Path      string                `json:"path,omitempty"`
	Version   string                `json:"version,omitempty"`
	Previous  string                `json:"previous,omitempty"`
	Versions  []pluginBinaryInfo    `json:"versions"`
	Install   *pluginBinaryProgress `json:"install,omitempty"`
}

func (status pluginBinaryStatus) value() map[string]any {
	data, _ := json.Marshal(status)
	var value map[string]any
	_ = json.Unmarshal(data, &value)
	return value
}

type pluginBinaryJob struct {
	request  pluginBinaryRequest
	progress pluginBinaryProgress
	cancel   context.CancelFunc
	done     chan struct{}
}

type pluginBinaryStore struct {
	mu       sync.Mutex
	root     string
	client   *http.Client
	registry *pluginProcessRegistry
	jobs     map[string]*pluginBinaryJob
	closed   bool
}

func newPluginBinaryStore(cfg *Config, registry *pluginProcessRegistry) (*pluginBinaryStore, error) {
	dir := normalizePluginsDir("")
	if cfg != nil {
		dir = normalizePluginsDir(cfg.PluginsDir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = ensurePluginPackageDirectory(abs, 0700); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || real != abs {
		return nil, fmt.Errorf("binary storage requires plugins_dir without symbolic links")
	}
	state := abs + pluginPackageStateSuffix
	root := filepath.Join(state, "cores")
	for _, dir := range []string{state, root, filepath.Join(root, ".staging")} {
		if err = ensurePluginPackageDirectory(dir, 0700); err != nil {
			return nil, err
		}
	}
	if err = cleanupPluginBinaryStages(filepath.Join(root, ".staging")); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many binary download redirects")
		}
		return validatePluginBinaryURL(req.URL.String())
	}}
	return &pluginBinaryStore{root: root, client: client, registry: registry, jobs: make(map[string]*pluginBinaryJob)}, nil
}

func validatePluginBinaryURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("binary source must be an HTTPS URL without credentials or fragment")
	}
	return nil
}

func validatePluginBinaryRequest(req pluginBinaryRequest) error {
	if !pluginProcessIDPattern.MatchString(req.ID) || !pluginBinaryExecutablePattern.MatchString(req.Executable) {
		return fmt.Errorf("invalid binary id or executable name")
	}
	if req.Format != "raw" && req.Format != "gzip" && req.Format != "tar.gz" {
		return fmt.Errorf("unsupported binary format")
	}
	if len(req.CheckArgs) > 16 {
		return fmt.Errorf("too many binary check arguments")
	}
	for _, arg := range req.CheckArgs {
		if len(arg) > 256 || strings.ContainsRune(arg, 0) {
			return fmt.Errorf("invalid binary check argument")
		}
	}
	if req.ReleaseURL != "" {
		u, err := url.Parse(req.ReleaseURL)
		if err != nil || validatePluginBinaryURL(req.ReleaseURL) != nil || u.Host != "api.github.com" || !pluginBinaryReleasePathPattern.MatchString(u.Path) || u.RawQuery != "" || req.Asset == "" || req.URL != "" || req.Version != "" {
			return fmt.Errorf("release_url must identify a GitHub release; direct source fields cannot be combined")
		}
		if req.SHA256 != "" {
			if _, err := normalizePluginBlobDigest(req.SHA256); err != nil {
				return err
			}
		}
	} else {
		if err := validatePluginBinaryURL(req.URL); err != nil {
			return err
		}
		if !validPluginBinaryVersion(req.Version) {
			return fmt.Errorf("invalid binary version")
		}
		if digest, err := normalizePluginBlobDigest(req.SHA256); err != nil || digest == "" {
			return fmt.Errorf("binary SHA256 is required")
		}
	}
	if len(req.Asset) > 256 || len(req.ArchivePath) > 256 {
		return fmt.Errorf("binary asset path is too long")
	}
	return nil
}

func validPluginBinaryVersion(v string) bool {
	return pluginBinaryVersionPattern.MatchString(v) && !strings.Contains(v, "..")
}

func (s *pluginBinaryStore) directory(owner, id string) (string, error) {
	if !pluginIDPattern.MatchString(owner) || !pluginProcessIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid binary owner or id")
	}
	dir := s.root
	for index, part := range []string{owner, id, runtime.GOOS + "-" + runtime.GOARCH} {
		if index == 1 {
			if _, err := os.Lstat(filepath.Join(dir, part)); os.IsNotExist(err) {
				entries, err := os.ReadDir(dir)
				if err != nil {
					return "", err
				}
				if len(entries) >= 8 {
					return "", fmt.Errorf("binary id limit reached")
				}
			}
		}
		dir = filepath.Join(dir, part)
		if err := ensurePluginPackageDirectory(dir, 0700); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (s *pluginBinaryStore) statusLocked(owner, id string) (pluginBinaryStatus, error) {
	dir, err := s.directory(owner, id)
	status := pluginBinaryStatus{ID: id, Directory: dir, Versions: []pluginBinaryInfo{}}
	if err != nil {
		return status, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return status, err
	}
	for _, entry := range entries {
		if !validPluginBinaryVersion(entry.Name()) || entry.Name() == "selected.json" {
			continue
		}
		if !entry.IsDir() {
			return status, fmt.Errorf("unexpected binary version entry")
		}
		info, err := readPluginBinaryVersion(dir, entry.Name())
		if err != nil {
			return status, err
		}
		status.Versions = append(status.Versions, info)
	}
	sort.Slice(status.Versions, func(i, j int) bool { return status.Versions[i].InstalledAt > status.Versions[j].InstalledAt })
	selection, err := readPluginBinarySelection(dir)
	if err != nil {
		return status, err
	}
	status.Version, status.Previous = selection.Version, selection.Previous
	if status.Version != "" {
		info, err := readPluginBinaryVersion(dir, status.Version)
		if err != nil {
			return status, fmt.Errorf("selected binary is unavailable: %w", err)
		}
		status.Path = info.Path
	}
	if job := s.jobs[owner+"/"+id]; job != nil {
		progress := job.progress
		status.Install = &progress
	}
	return status, nil
}

func (s *pluginBinaryStore) Status(owner, id string) (pluginBinaryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked(owner, id)
}

func readPluginBinaryJSON(file string, out any) error {
	info, err := os.Lstat(file)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 8192 {
		return fmt.Errorf("invalid binary metadata")
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 8193)).Decode(out)
}

func readPluginBinarySelection(dir string) (pluginBinarySelection, error) {
	var selection pluginBinarySelection
	err := readPluginBinaryJSON(filepath.Join(dir, "selected.json"), &selection)
	if os.IsNotExist(err) {
		return selection, nil
	}
	if err == nil && ((selection.Version != "" && !validPluginBinaryVersion(selection.Version)) || (selection.Previous != "" && !validPluginBinaryVersion(selection.Previous))) {
		err = fmt.Errorf("invalid binary selection")
	}
	return selection, err
}

func readPluginBinaryVersion(dir, version string) (pluginBinaryInfo, error) {
	var info pluginBinaryInfo
	if !validPluginBinaryVersion(version) {
		return info, fmt.Errorf("invalid binary version")
	}
	versionDir := filepath.Join(dir, version)
	fi, err := os.Lstat(versionDir)
	if err != nil {
		return info, err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return info, fmt.Errorf("invalid binary version directory")
	}
	if err = readPluginBinaryJSON(filepath.Join(versionDir, "manifest.json"), &info); err != nil {
		return info, err
	}
	if info.Version != version || !pluginBinaryExecutablePattern.MatchString(info.Executable) || info.Bytes <= 0 || info.Bytes > pluginBinaryMaxFile {
		return info, fmt.Errorf("invalid installed binary manifest")
	}
	info.Path = filepath.Join(versionDir, info.Executable)
	fi, err = os.Lstat(info.Path)
	if err != nil {
		return info, err
	}
	if !fi.Mode().IsRegular() || fi.Size() != info.Bytes {
		return info, fmt.Errorf("installed binary is missing or changed")
	}
	return info, nil
}

func writePluginBinaryJSON(dir, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".metadata-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = replacePluginBlobFile(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncPluginBlobDirectory(dir)
}

func (s *pluginBinaryStore) Select(owner, id, version string) (pluginBinaryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return pluginBinaryStatus{}, fmt.Errorf("binary store is closed")
	}
	dir, err := s.directory(owner, id)
	if err != nil {
		return pluginBinaryStatus{}, err
	}
	if err = s.selectLocked(dir, version); err != nil {
		return pluginBinaryStatus{}, err
	}
	return s.statusLocked(owner, id)
}

func (s *pluginBinaryStore) selectLocked(dir, version string) error {
	info, err := readPluginBinaryVersion(dir, version)
	if err != nil {
		return err
	}
	f, err := os.Open(info.Path)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	_ = f.Close()
	if err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != info.BinarySHA256 {
		return fmt.Errorf("installed binary checksum mismatch")
	}
	selection, err := readPluginBinarySelection(dir)
	if err != nil {
		return err
	}
	if selection.Version == version {
		return nil
	}
	return writePluginBinaryJSON(dir, "selected.json", pluginBinarySelection{Version: version, Previous: selection.Version})
}

func (s *pluginBinaryStore) Remove(owner, id, version string) (pluginBinaryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return pluginBinaryStatus{}, fmt.Errorf("binary store is closed")
	}
	dir, err := s.directory(owner, id)
	if err != nil {
		return pluginBinaryStatus{}, err
	}
	status, err := s.statusLocked(owner, id)
	if err != nil {
		return status, err
	}
	if status.Install != nil && (status.Install.State == "resolving" || status.Install.State == "downloading" || status.Install.State == "verifying") {
		return status, fmt.Errorf("binary installation is in progress")
	}
	if version == status.Version {
		return status, fmt.Errorf("cannot remove the selected binary")
	}
	info, err := readPluginBinaryVersion(dir, version)
	if err != nil {
		return status, err
	}
	if s.registry != nil && s.registry.binaryInUse(info.Path) {
		return status, fmt.Errorf("binary is still referenced by a managed process; reapply or stop its WAN first")
	}
	if version == status.Previous {
		if err = writePluginBinaryJSON(dir, "selected.json", pluginBinarySelection{Version: status.Version}); err != nil {
			return status, err
		}
	}
	if err = os.RemoveAll(filepath.Dir(info.Path)); err != nil {
		return status, err
	}
	return s.statusLocked(owner, id)
}

func (s *pluginBinaryStore) Install(owner string, req pluginBinaryRequest) (pluginBinaryStatus, error) {
	if err := validatePluginBinaryRequest(req); err != nil {
		return pluginBinaryStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return pluginBinaryStatus{}, fmt.Errorf("binary store is closed")
	}
	status, err := s.statusLocked(owner, req.ID)
	if err != nil {
		return status, err
	}
	active := 0
	for key, job := range s.jobs {
		if job.progress.State == "ready" || job.progress.State == "failed" {
			continue
		}
		active++
		if strings.HasPrefix(key, owner+"/") {
			return status, fmt.Errorf("a binary installation is already in progress for this plugin")
		}
	}
	if active >= 4 {
		return status, fmt.Errorf("binary installation concurrency limit reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	job := &pluginBinaryJob{request: req, progress: pluginBinaryProgress{State: "resolving", Version: req.Version}, cancel: cancel, done: make(chan struct{})}
	s.jobs[owner+"/"+req.ID] = job
	go s.install(ctx, owner, job)
	progress := job.progress
	status.Install = &progress
	return status, nil
}

func (s *pluginBinaryStore) progress(owner string, job *pluginBinaryJob, update func(*pluginBinaryProgress)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	update(&job.progress)
}

func (s *pluginBinaryStore) get(ctx context.Context, raw string) (*http.Response, error) {
	if err := validatePluginBinaryURL(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Veer-plugin-binaries")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("binary source request failed")
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		return nil, fmt.Errorf("binary source returned HTTP %d", res.StatusCode)
	}
	return res, nil
}

func (s *pluginBinaryStore) resolve(ctx context.Context, req pluginBinaryRequest) (pluginBinaryRequest, error) {
	if req.ReleaseURL == "" {
		req.SHA256 = strings.ToLower(req.SHA256)
		return req, nil
	}
	res, err := s.get(ctx, req.ReleaseURL)
	if err != nil {
		return req, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 2<<20+1))
	if err != nil || len(data) > 2<<20 {
		return req, fmt.Errorf("release metadata exceeds 2 MiB or is unreadable")
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err = json.Unmarshal(data, &release); err != nil || !validPluginBinaryVersion(release.Tag) || release.Draft || (strings.HasSuffix(req.ReleaseURL, "/latest") && release.Prerelease) {
		return req, fmt.Errorf("invalid stable release metadata")
	}
	expand := func(text string) string {
		return strings.NewReplacer("{tag}", release.Tag, "{version}", strings.TrimPrefix(release.Tag, "v")).Replace(text)
	}
	name := expand(req.Asset)
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		digest := strings.TrimPrefix(asset.Digest, "sha256:")
		if req.SHA256 != "" {
			digest = req.SHA256
		}
		if d, err := normalizePluginBlobDigest(digest); err != nil || d == "" {
			return req, fmt.Errorf("release asset has no SHA256; supply its verified SHA256 explicitly")
		}
		if err := validatePluginBinaryURL(asset.URL); err != nil {
			return req, err
		}
		req.Version, req.URL, req.SHA256, req.ArchivePath = release.Tag, asset.URL, strings.ToLower(digest), expand(req.ArchivePath)
		return req, nil
	}
	return req, fmt.Errorf("release has no asset for this architecture: %s", name)
}

type pluginBinaryDownloadWriter struct {
	writer   io.Writer
	progress func(int64)
	bytes    int64
}

func (w *pluginBinaryDownloadWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.bytes += int64(n)
	w.progress(w.bytes)
	return n, err
}

func (s *pluginBinaryStore) install(ctx context.Context, owner string, job *pluginBinaryJob) {
	defer close(job.done)
	defer job.cancel()
	err := s.installArtifact(ctx, owner, job)
	s.progress(owner, job, func(p *pluginBinaryProgress) {
		if err != nil {
			p.State = "failed"
			p.Error = err.Error()
		} else {
			p.State = "ready"
		}
	})
}

func (s *pluginBinaryStore) installArtifact(ctx context.Context, owner string, job *pluginBinaryJob) error {
	req, err := s.resolve(ctx, job.request)
	if err != nil {
		return err
	}
	s.mu.Lock()
	status, statusErr := s.statusLocked(owner, req.ID)
	s.mu.Unlock()
	if statusErr != nil {
		return statusErr
	}
	known := false
	for _, v := range status.Versions {
		if v.Version == req.Version {
			known = true
		}
	}
	if !known && len(status.Versions) >= pluginBinaryMaxVersions {
		return fmt.Errorf("keep at most %d binary versions; remove an unused version first", pluginBinaryMaxVersions)
	}
	s.progress(owner, job, func(p *pluginBinaryProgress) { p.State = "downloading"; p.Version = req.Version })
	stage, err := os.MkdirTemp(filepath.Join(s.root, ".staging"), fmt.Sprintf("%d-", os.Getpid()))
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	archive, err := os.OpenFile(filepath.Join(stage, "download"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer archive.Close()
	res, err := s.get(ctx, req.URL)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.ContentLength > pluginBinaryMaxArchive {
		return fmt.Errorf("binary archive exceeds 256 MiB")
	}
	s.progress(owner, job, func(p *pluginBinaryProgress) { p.TotalBytes = max(0, res.ContentLength) })
	hash := sha256.New()
	last := time.Time{}
	writer := &pluginBinaryDownloadWriter{writer: io.MultiWriter(archive, hash), progress: func(n int64) {
		if time.Since(last) >= 250*time.Millisecond {
			last = time.Now()
			s.progress(owner, job, func(p *pluginBinaryProgress) { p.DownloadedBytes = n })
		}
	}}
	n, err := io.Copy(writer, io.LimitReader(res.Body, pluginBinaryMaxArchive+1))
	if err != nil {
		return fmt.Errorf("binary download interrupted")
	}
	if n > pluginBinaryMaxArchive {
		return fmt.Errorf("binary archive exceeds 256 MiB")
	}
	if hex.EncodeToString(hash.Sum(nil)) != req.SHA256 {
		return fmt.Errorf("binary archive SHA256 mismatch")
	}
	s.progress(owner, job, func(p *pluginBinaryProgress) { p.State = "verifying"; p.DownloadedBytes = n })
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	payload := filepath.Join(stage, "payload")
	if err = os.Mkdir(payload, 0700); err != nil {
		return err
	}
	binary := filepath.Join(payload, req.Executable)
	info, err := extractPluginBinary(ctx, archive, binary, req)
	if err != nil {
		return err
	}
	if len(req.CheckArgs) > 0 {
		result, err := runPluginExec(pluginExecRequest{Command: binary, Args: req.CheckArgs}, 10*time.Second, ctx.Done())
		if err != nil || result.ExitCode != 0 || result.TimedOut || result.Cancelled || result.Truncated {
			return fmt.Errorf("binary cannot run on this host; version check failed")
		}
	}
	info.Version, info.Executable, info.SHA256, info.InstalledAt = req.Version, req.Executable, req.SHA256, time.Now().UTC().Format(time.RFC3339Nano)
	if err = writePluginBinaryJSON(payload, "manifest.json", info); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx.Err() != nil {
		return fmt.Errorf("binary installation cancelled")
	}
	dir, err := s.directory(owner, req.ID)
	if err != nil {
		return err
	}
	if old, err := readPluginBinaryVersion(dir, req.Version); err == nil {
		if old.SHA256 != req.SHA256 || old.BinarySHA256 != info.BinarySHA256 || old.Executable != req.Executable {
			return fmt.Errorf("this version is already installed with a different binary")
		}
		return s.selectLocked(dir, req.Version)
	} else if !os.IsNotExist(err) {
		return err
	}
	status, err = s.statusLocked(owner, req.ID)
	if err != nil {
		return err
	}
	if len(status.Versions) >= pluginBinaryMaxVersions {
		return fmt.Errorf("binary version limit reached")
	}
	var bytes int64
	ownerRoot := filepath.Join(s.root, owner)
	if err = filepath.WalkDir(ownerRoot, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link in binary storage")
		}
		if !d.IsDir() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			bytes += fi.Size()
		}
		return nil
	}); err != nil {
		return err
	}
	if bytes+info.Bytes > pluginBinaryPluginQuota {
		return fmt.Errorf("plugin binary storage exceeds 1 GiB")
	}
	if err = os.Rename(payload, filepath.Join(dir, req.Version)); err != nil {
		return err
	}
	if err = syncPluginBlobDirectory(dir); err != nil {
		return err
	}
	return s.selectLocked(dir, req.Version)
}

func extractPluginBinary(ctx context.Context, archive io.Reader, target string, req pluginBinaryRequest) (pluginBinaryInfo, error) {
	var info pluginBinaryInfo
	reader := archive
	if req.Format != "raw" {
		gz, err := gzip.NewReader(archive)
		if err != nil {
			return info, err
		}
		defer gz.Close()
		reader = gz
	}
	if req.Format == "tar.gz" {
		if req.ArchivePath == "" || path.Clean(req.ArchivePath) != req.ArchivePath || strings.HasPrefix(req.ArchivePath, "/") || strings.Contains(req.ArchivePath, "\\") || strings.HasPrefix(req.ArchivePath, "../") {
			return info, fmt.Errorf("invalid executable archive path")
		}
		tr := tar.NewReader(io.LimitReader(reader, pluginBinaryMaxFile+8<<20))
		found := false
		for entries := 0; entries < 1024; entries++ {
			if ctx.Err() != nil {
				return info, ctx.Err()
			}
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return info, err
			}
			if header.Name != req.ArchivePath {
				continue
			}
			if header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > pluginBinaryMaxFile {
				return info, fmt.Errorf("archive executable must be a regular file of at most 256 MiB")
			}
			reader = tr
			found = true
			break
		}
		if !found {
			return info, fmt.Errorf("executable not found in archive")
		}
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0700)
	if err != nil {
		return info, err
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(reader, pluginBinaryMaxFile+1))
	if err != nil {
		return info, err
	}
	if n <= 0 || n > pluginBinaryMaxFile {
		return info, fmt.Errorf("executable exceeds size limit")
	}
	if ctx.Err() != nil {
		return info, ctx.Err()
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return info, err
	}
	elfFile, err := elf.NewFile(f)
	if err != nil {
		return info, fmt.Errorf("core must be a Linux ELF executable")
	}
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64, "arm": elf.EM_ARM, "386": elf.EM_386, "mips": elf.EM_MIPS, "mipsle": elf.EM_MIPS, "mips64": elf.EM_MIPS, "mips64le": elf.EM_MIPS, "riscv64": elf.EM_RISCV, "ppc64le": elf.EM_PPC64, "s390x": elf.EM_S390, "loong64": elf.EM_LOONGARCH}
	if machine, ok := machines[runtime.GOARCH]; !ok || elfFile.Machine != machine || (elfFile.Type != elf.ET_EXEC && elfFile.Type != elf.ET_DYN) {
		return info, fmt.Errorf("core executable architecture does not match this host")
	}
	class := elf.ELFCLASS64
	if runtime.GOARCH == "386" || runtime.GOARCH == "arm" || runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" {
		class = elf.ELFCLASS32
	}
	data := elf.ELFDATA2LSB
	if runtime.GOARCH == "mips" || runtime.GOARCH == "mips64" || runtime.GOARCH == "s390x" {
		data = elf.ELFDATA2MSB
	}
	if elfFile.Class != class || elfFile.Data != data {
		return info, fmt.Errorf("core executable word size or byte order does not match this host")
	}
	if err = f.Sync(); err != nil {
		return info, err
	}
	info.Bytes, info.BinarySHA256 = n, hex.EncodeToString(hash.Sum(nil))
	return info, nil
}

func (s *pluginBinaryStore) cancelOwner(owner string, closeStore bool) {
	s.mu.Lock()
	if closeStore {
		s.closed = true
	}
	var jobs []*pluginBinaryJob
	for key, job := range s.jobs {
		if closeStore || strings.HasPrefix(key, owner+"/") {
			job.cancel()
			jobs = append(jobs, job)
		}
	}
	s.mu.Unlock()
	for _, job := range jobs {
		<-job.done
	}
}

func (h *pluginControlHost) managedBinaryStore(api string) *pluginBinaryStore {
	r := h.managedProcessRegistry(api)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		h.throwf("%s: process registry is closed", api)
	}
	if r.binaries == nil {
		store, err := newPluginBinaryStore(h.cfg, r)
		if err != nil {
			h.throwf("%s: %v", api, err)
		}
		r.binaries = store
	}
	return r.binaries
}

func (h *pluginControlHost) processBinaryInstall(call goja.FunctionCall) goja.Value {
	s := h.managedBinaryStore("process.binaryInstall")
	data, err := json.Marshal(h.requiredObjectArg(call, 0, "request").Export())
	if err != nil || len(data) > 8192 {
		h.throwf("invalid binary request")
	}
	var req pluginBinaryRequest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&req); err != nil {
		h.throwf("invalid binary request")
	}
	status, err := s.Install(h.plugin.ID, req)
	if err != nil {
		h.throwf("process.binaryInstall: %v", err)
	}
	recordPluginAudit(h.db, h.plugin.ID, "process.binaryInstall", "control", "started", map[string]any{"id": req.ID, "version": req.Version})
	return h.vm.ToValue(status.value())
}

func (h *pluginControlHost) processBinaryStatus(call goja.FunctionCall) goja.Value {
	s := h.managedBinaryStore("process.binaryStatus")
	status, err := s.Status(h.plugin.ID, h.processIDArg(call))
	if err != nil {
		h.throwf("process.binaryStatus: %v", err)
	}
	return h.vm.ToValue(status.value())
}

func (h *pluginControlHost) processBinarySelect(call goja.FunctionCall) goja.Value {
	s := h.managedBinaryStore("process.binarySelect")
	obj := h.requiredObjectArg(call, 0, "request")
	id, version := h.requiredStringObjectField(obj, "id"), h.requiredStringObjectField(obj, "version")
	status, err := s.Select(h.plugin.ID, id, version)
	if err != nil {
		h.throwf("process.binarySelect: %v", err)
	}
	recordPluginAudit(h.db, h.plugin.ID, "process.binarySelect", "control", "success", map[string]any{"id": id, "version": version})
	return h.vm.ToValue(status.value())
}

func (h *pluginControlHost) processBinaryRemove(call goja.FunctionCall) goja.Value {
	s := h.managedBinaryStore("process.binaryRemove")
	obj := h.requiredObjectArg(call, 0, "request")
	id, version := h.requiredStringObjectField(obj, "id"), h.requiredStringObjectField(obj, "version")
	status, err := s.Remove(h.plugin.ID, id, version)
	if err != nil {
		h.throwf("process.binaryRemove: %v", err)
	}
	recordPluginAudit(h.db, h.plugin.ID, "process.binaryRemove", "control", "success", map[string]any{"id": id, "version": version})
	return h.vm.ToValue(status.value())
}
