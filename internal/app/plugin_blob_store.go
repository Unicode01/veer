package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	pluginBlobFormatVersion       = 1
	pluginBlobHeaderBytes         = 4096
	pluginBlobMaxChunkBytes       = 1 << 20
	pluginBlobMaxUploadsPerPlugin = 8
	pluginBlobMaxUploadsGlobal    = 64
	pluginBlobMaxListEntries      = 1000
	pluginBlobDirectoryName       = "blobs"
	pluginBlobUploadDirectoryName = "blob-uploads"
	pluginBlobFileSuffix          = ".blob"
	pluginBlobUploadSuffix        = ".upload"
)

var pluginBlobMagic = [8]byte{'V', 'E', 'E', 'R', 'B', 'L', 'B', '1'}

type pluginBlobHeader struct {
	FormatVersion int    `json:"format_version"`
	Key           string `json:"key"`
	Bytes         int64  `json:"bytes"`
	SHA256        string `json:"sha256"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type pluginBlobInfo struct {
	Key       string `json:"key"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type pluginBlobReadResult struct {
	Info   pluginBlobInfo
	Offset int64
	Data   []byte
	EOF    bool
}

type pluginBlobUploadInfo struct {
	UploadID       string `json:"upload_id"`
	Key            string `json:"key"`
	Bytes          int64  `json:"bytes"`
	ExpectedBytes  int64  `json:"expected_bytes,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type pluginBlobUsage struct {
	Objects int
	Bytes   int64
}

type pluginBlobUpload struct {
	pluginID       string
	generation     string
	id             string
	key            string
	path           string
	file           *os.File
	hash           hash.Hash
	size           int64
	expectedBytes  int64
	expectedSHA256 string
	createdAt      time.Time
}

type pluginBlobStore struct {
	mu         sync.Mutex
	stateRoot  string
	blobRoot   string
	uploadRoot string
	limits     PluginResourceLimits
	uploads    map[string]*pluginBlobUpload
	usage      map[string]pluginBlobUsage
	global     pluginBlobUsage
	closed     bool
}

func newPluginBlobStore(cfg *Config) (*pluginBlobStore, error) {
	pluginsDir := normalizePluginsDir("")
	if cfg != nil {
		pluginsDir = normalizePluginsDir(cfg.PluginsDir)
	}
	absPlugins, err := filepath.Abs(pluginsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve plugins directory: %w", err)
	}
	if err := ensurePluginPackageDirectory(absPlugins, 0o700); err != nil {
		return nil, fmt.Errorf("prepare plugins directory: %w", err)
	}
	realPlugins, err := filepath.EvalSymlinks(absPlugins)
	if err != nil {
		return nil, fmt.Errorf("resolve plugins directory: %w", err)
	}
	if realPlugins != absPlugins {
		return nil, fmt.Errorf("plugin blob storage requires plugins_dir itself not to be a symbolic link")
	}
	stateRoot := realPlugins + pluginPackageStateSuffix
	blobRoot := filepath.Join(stateRoot, pluginBlobDirectoryName)
	uploadRoot := filepath.Join(stateRoot, pluginBlobUploadDirectoryName)
	for _, dir := range []string{stateRoot, blobRoot} {
		if err := ensurePluginPackageDirectory(dir, 0o700); err != nil {
			return nil, fmt.Errorf("prepare plugin blob storage: %w", err)
		}
	}
	if err := removePluginPackageManagedPath(stateRoot, uploadRoot); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("clean stale plugin blob uploads: %w", err)
	}
	if err := ensurePluginPackageDirectory(uploadRoot, 0o700); err != nil {
		return nil, fmt.Errorf("prepare plugin blob uploads: %w", err)
	}
	store := &pluginBlobStore{
		stateRoot: stateRoot, blobRoot: blobRoot, uploadRoot: uploadRoot,
		limits: pluginResourceLimitsFromConfig(cfg), uploads: make(map[string]*pluginBlobUpload), usage: make(map[string]pluginBlobUsage),
	}
	if err := store.scanUsageLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *pluginBlobStore) Begin(pluginID, generation, key string, expectedBytes int64, expectedSHA256 string) (pluginBlobUploadInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireOpenLocked(); err != nil {
		return pluginBlobUploadInfo{}, err
	}
	pluginID, generation, key, err := normalizePluginBlobOwner(pluginID, generation, key)
	if err != nil {
		return pluginBlobUploadInfo{}, err
	}
	expectedSHA256, err = normalizePluginBlobDigest(expectedSHA256)
	if err != nil {
		return pluginBlobUploadInfo{}, err
	}
	if expectedBytes < 0 || expectedBytes > s.limits.BlobObjectBytes {
		return pluginBlobUploadInfo{}, fmt.Errorf("expected_bytes must be between 0 and %d", s.limits.BlobObjectBytes)
	}
	pluginUploads, uploadBytes := s.activeUploadUsageLocked(pluginID)
	if pluginUploads >= pluginBlobMaxUploadsPerPlugin || len(s.uploads) >= pluginBlobMaxUploadsGlobal {
		return pluginBlobUploadInfo{}, fmt.Errorf("plugin blob upload limit reached")
	}
	if uploadBytes > s.limits.PluginBlobBytes || s.activeUploadBytesLocked() > s.limits.GlobalBlobBytes {
		return pluginBlobUploadInfo{}, fmt.Errorf("plugin blob temporary quota is exhausted")
	}
	pluginUploadRoot := filepath.Join(s.uploadRoot, pluginID)
	if err := ensurePluginPackageDirectory(pluginUploadRoot, 0o700); err != nil {
		return pluginBlobUploadInfo{}, err
	}
	uploadID, err := newPluginBlobUploadID()
	if err != nil {
		return pluginBlobUploadInfo{}, err
	}
	path := filepath.Join(pluginUploadRoot, uploadID+pluginBlobUploadSuffix)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) // #nosec G304 -- path is built from validated identifiers below a private root.
	if err != nil {
		return pluginBlobUploadInfo{}, err
	}
	if _, err := file.Write(make([]byte, pluginBlobHeaderBytes)); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return pluginBlobUploadInfo{}, err
	}
	upload := &pluginBlobUpload{
		pluginID: pluginID, generation: generation, id: uploadID, key: key, path: path, file: file, hash: sha256.New(),
		expectedBytes: expectedBytes, expectedSHA256: expectedSHA256, createdAt: time.Now().UTC(),
	}
	s.uploads[uploadID] = upload
	return upload.info(), nil
}

func (s *pluginBlobStore) Write(pluginID, generation, uploadID string, offset int64, data []byte) (pluginBlobUploadInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upload, err := s.uploadLocked(pluginID, generation, uploadID)
	if err != nil {
		return pluginBlobUploadInfo{}, err
	}
	if offset != upload.size {
		return pluginBlobUploadInfo{}, fmt.Errorf("blob upload offset %d does not match next offset %d", offset, upload.size)
	}
	if len(data) < 1 || len(data) > pluginBlobMaxChunkBytes {
		return pluginBlobUploadInfo{}, fmt.Errorf("blob upload chunk must be between 1 and %d bytes", pluginBlobMaxChunkBytes)
	}
	nextSize := upload.size + int64(len(data))
	if nextSize > s.limits.BlobObjectBytes {
		return pluginBlobUploadInfo{}, fmt.Errorf("blob exceeds per-object limit %d", s.limits.BlobObjectBytes)
	}
	if upload.expectedBytes > 0 && nextSize > upload.expectedBytes {
		return pluginBlobUploadInfo{}, fmt.Errorf("blob exceeds expected_bytes %d", upload.expectedBytes)
	}
	_, pluginTempBytes := s.activeUploadUsageLocked(upload.pluginID)
	globalTempBytes := s.activeUploadBytesLocked()
	if pluginTempBytes+int64(len(data)) > s.limits.PluginBlobBytes || globalTempBytes+int64(len(data)) > s.limits.GlobalBlobBytes {
		return pluginBlobUploadInfo{}, fmt.Errorf("plugin blob temporary quota exceeded")
	}
	n, err := upload.file.Write(data)
	if err != nil || n != len(data) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return pluginBlobUploadInfo{}, err
	}
	if _, err := upload.hash.Write(data); err != nil {
		return pluginBlobUploadInfo{}, err
	}
	upload.size = nextSize
	return upload.info(), nil
}

func (s *pluginBlobStore) Commit(pluginID, generation, uploadID string) (pluginBlobInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upload, err := s.uploadLocked(pluginID, generation, uploadID)
	if err != nil {
		return pluginBlobInfo{}, err
	}
	if upload.expectedBytes > 0 && upload.size != upload.expectedBytes {
		return pluginBlobInfo{}, fmt.Errorf("blob size %d does not match expected_bytes %d", upload.size, upload.expectedBytes)
	}
	digest := hex.EncodeToString(upload.hash.Sum(nil))
	if upload.expectedSHA256 != "" && digest != upload.expectedSHA256 {
		return pluginBlobInfo{}, fmt.Errorf("blob sha256 %s does not match expected %s", digest, upload.expectedSHA256)
	}
	targetDir := filepath.Join(s.blobRoot, upload.pluginID)
	if err := ensurePluginPackageDirectory(targetDir, 0o700); err != nil {
		return pluginBlobInfo{}, err
	}
	target := filepath.Join(targetDir, upload.key+pluginBlobFileSuffix)
	createdAt := upload.createdAt
	oldSize := int64(0)
	oldExists := false
	if old, statErr := s.statPathLocked(upload.pluginID, upload.key, target); statErr == nil {
		oldExists = true
		oldSize = old.Bytes
		if parsed, parseErr := time.Parse(time.RFC3339Nano, old.CreatedAt); parseErr == nil {
			createdAt = parsed
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return pluginBlobInfo{}, statErr
	}
	usage := s.usage[upload.pluginID]
	nextObjects := usage.Objects
	if !oldExists {
		nextObjects++
	}
	nextBytes := usage.Bytes - oldSize + upload.size
	globalBytes := s.global.Bytes - oldSize + upload.size
	if nextObjects > s.limits.BlobObjectsPerPlugin || nextBytes > s.limits.PluginBlobBytes || globalBytes > s.limits.GlobalBlobBytes {
		return pluginBlobInfo{}, fmt.Errorf("plugin blob committed quota exceeded")
	}
	now := time.Now().UTC()
	header := pluginBlobHeader{
		FormatVersion: pluginBlobFormatVersion, Key: upload.key, Bytes: upload.size, SHA256: digest,
		CreatedAt: createdAt.UTC().Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
	}
	headerBytes, err := encodePluginBlobHeader(header)
	if err != nil {
		return pluginBlobInfo{}, err
	}
	if _, err := upload.file.WriteAt(headerBytes, 0); err != nil {
		return pluginBlobInfo{}, err
	}
	if err := upload.file.Sync(); err != nil {
		return pluginBlobInfo{}, err
	}
	if err := upload.file.Close(); err != nil {
		upload.file = nil
		delete(s.uploads, upload.id)
		_ = os.Remove(upload.path)
		return pluginBlobInfo{}, err
	}
	upload.file = nil
	if err := replacePluginBlobFile(upload.path, target); err != nil {
		delete(s.uploads, upload.id)
		_ = os.Remove(upload.path)
		return pluginBlobInfo{}, err
	}
	delete(s.uploads, upload.id)
	s.usage[upload.pluginID] = pluginBlobUsage{Objects: nextObjects, Bytes: nextBytes}
	s.global.Objects += nextObjects - usage.Objects
	s.global.Bytes = globalBytes
	info := pluginBlobInfoFromHeader(header)
	if err := syncPluginBlobDirectory(targetDir); err != nil {
		return info, fmt.Errorf("blob committed but directory sync failed: %w", err)
	}
	return info, nil
}

func (s *pluginBlobStore) Put(pluginID, generation, key string, data []byte, expectedSHA256 string) (info pluginBlobInfo, err error) {
	if len(data) > pluginBlobMaxChunkBytes {
		return pluginBlobInfo{}, fmt.Errorf("blob.put payload exceeds %d bytes; use begin/write/commit", pluginBlobMaxChunkBytes)
	}
	upload, err := s.Begin(pluginID, generation, key, int64(len(data)), expectedSHA256)
	if err != nil {
		return pluginBlobInfo{}, err
	}
	defer func() {
		if err != nil {
			_, _ = s.Abort(pluginID, generation, upload.UploadID)
		}
	}()
	if len(data) > 0 {
		if _, err = s.Write(pluginID, generation, upload.UploadID, 0, data); err != nil {
			return pluginBlobInfo{}, err
		}
	}
	return s.Commit(pluginID, generation, upload.UploadID)
}

func (s *pluginBlobStore) Abort(pluginID, generation, uploadID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upload, err := s.uploadLocked(pluginID, generation, uploadID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.abortUploadLocked(upload)
	return true, nil
}

func (s *pluginBlobStore) Read(pluginID, key string, offset int64, maxBytes int) (pluginBlobReadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pluginID, _, key, err := normalizePluginBlobOwner(pluginID, "read", key)
	if err != nil {
		return pluginBlobReadResult{}, err
	}
	if offset < 0 {
		return pluginBlobReadResult{}, fmt.Errorf("offset must be non-negative")
	}
	if maxBytes == 0 {
		maxBytes = 64 << 10
	}
	if maxBytes < 1 || maxBytes > pluginBlobMaxChunkBytes {
		return pluginBlobReadResult{}, fmt.Errorf("max_bytes must be between 1 and %d", pluginBlobMaxChunkBytes)
	}
	path := filepath.Join(s.blobRoot, pluginID, key+pluginBlobFileSuffix)
	file, header, err := openPluginBlobFile(path, key, s.limits.BlobObjectBytes)
	if err != nil {
		return pluginBlobReadResult{}, err
	}
	defer file.Close()
	if offset > header.Bytes {
		return pluginBlobReadResult{}, fmt.Errorf("offset %d exceeds blob size %d", offset, header.Bytes)
	}
	remaining := header.Bytes - offset
	readBytes := int64(maxBytes)
	if readBytes > remaining {
		readBytes = remaining
	}
	data := make([]byte, int(readBytes))
	if readBytes > 0 {
		if _, err := file.ReadAt(data, pluginBlobHeaderBytes+offset); err != nil {
			return pluginBlobReadResult{}, err
		}
	}
	return pluginBlobReadResult{Info: pluginBlobInfoFromHeader(header), Offset: offset, Data: data, EOF: offset+readBytes >= header.Bytes}, nil
}

func (s *pluginBlobStore) Stat(pluginID, key string) (pluginBlobInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pluginID, _, key, err := normalizePluginBlobOwner(pluginID, "stat", key)
	if err != nil {
		return pluginBlobInfo{}, err
	}
	return s.statPathLocked(pluginID, key, filepath.Join(s.blobRoot, pluginID, key+pluginBlobFileSuffix))
}

func (s *pluginBlobStore) List(pluginID, after string, limit int) ([]pluginBlobInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pluginID, _, _, err := normalizePluginBlobOwner(pluginID, "list", "placeholder")
	if err != nil {
		return nil, err
	}
	if after != "" {
		after, err = pluginPathToken(after)
		if err != nil {
			return nil, fmt.Errorf("after: %w", err)
		}
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > pluginBlobMaxListEntries {
		return nil, fmt.Errorf("limit must be between 1 and %d", pluginBlobMaxListEntries)
	}
	dir := filepath.Join(s.blobRoot, pluginID)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []pluginBlobInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), pluginBlobFileSuffix) {
			continue
		}
		key := strings.TrimSuffix(entry.Name(), pluginBlobFileSuffix)
		if !pluginTokenPattern.MatchString(key) || key <= after {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]pluginBlobInfo, 0, len(keys))
	for _, key := range keys {
		info, err := s.statPathLocked(pluginID, key, filepath.Join(dir, key+pluginBlobFileSuffix))
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

func (s *pluginBlobStore) Delete(pluginID, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pluginID, _, key, err := normalizePluginBlobOwner(pluginID, "delete", key)
	if err != nil {
		return false, err
	}
	path := filepath.Join(s.blobRoot, pluginID, key+pluginBlobFileSuffix)
	info, err := s.statPathLocked(pluginID, key, path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	usage := s.usage[pluginID]
	usage.Objects--
	usage.Bytes -= info.Bytes
	if usage.Objects <= 0 {
		delete(s.usage, pluginID)
	} else {
		s.usage[pluginID] = usage
	}
	s.global.Objects--
	s.global.Bytes -= info.Bytes
	if err := syncPluginBlobDirectory(filepath.Dir(path)); err != nil {
		return true, fmt.Errorf("blob deleted but directory sync failed: %w", err)
	}
	return true, nil
}

func (s *pluginBlobStore) Verify(pluginID, key string) (pluginBlobInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pluginID, _, key, err := normalizePluginBlobOwner(pluginID, "verify", key)
	if err != nil {
		return pluginBlobInfo{}, err
	}
	path := filepath.Join(s.blobRoot, pluginID, key+pluginBlobFileSuffix)
	file, header, err := openPluginBlobFile(path, key, s.limits.BlobObjectBytes)
	if err != nil {
		return pluginBlobInfo{}, err
	}
	defer file.Close()
	if _, err := file.Seek(pluginBlobHeaderBytes, io.SeekStart); err != nil {
		return pluginBlobInfo{}, err
	}
	h := sha256.New()
	written, err := io.Copy(h, io.LimitReader(file, header.Bytes+1))
	if err != nil {
		return pluginBlobInfo{}, err
	}
	if written != header.Bytes || hex.EncodeToString(h.Sum(nil)) != header.SHA256 {
		return pluginBlobInfo{}, fmt.Errorf("blob %s failed sha256 verification", key)
	}
	return pluginBlobInfoFromHeader(header), nil
}

func (s *pluginBlobStore) AbortGeneration(pluginID, generation string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, upload := range s.uploads {
		if upload.pluginID == pluginID && upload.generation == generation {
			s.abortUploadLocked(upload)
			count++
		}
	}
	return count
}

func (s *pluginBlobStore) AbortPlugin(pluginID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, upload := range s.uploads {
		if upload.pluginID == pluginID {
			s.abortUploadLocked(upload)
			count++
		}
	}
	return count
}

func (s *pluginBlobStore) PurgePlugin(pluginID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, upload := range s.uploads {
		if upload.pluginID == pluginID {
			s.abortUploadLocked(upload)
		}
	}
	usage := s.usage[pluginID]
	if err := removePluginPackageManagedPath(s.blobRoot, filepath.Join(s.blobRoot, pluginID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := removePluginPackageManagedPath(s.uploadRoot, filepath.Join(s.uploadRoot, pluginID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(s.usage, pluginID)
	s.global.Objects -= usage.Objects
	s.global.Bytes -= usage.Bytes
	return nil
}

func (s *pluginBlobStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, upload := range s.uploads {
		s.abortUploadLocked(upload)
	}
	return nil
}

func (s *pluginBlobStore) requireOpenLocked() error {
	if s == nil || s.closed {
		return errPluginRuntimeTargetNotLoaded
	}
	return nil
}

func (s *pluginBlobStore) uploadLocked(pluginID, generation, uploadID string) (*pluginBlobUpload, error) {
	if err := s.requireOpenLocked(); err != nil {
		return nil, err
	}
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	generation = strings.TrimSpace(generation)
	uploadID = strings.TrimSpace(strings.ToLower(uploadID))
	upload := s.uploads[uploadID]
	if upload == nil || upload.pluginID != pluginID || upload.generation != generation {
		return nil, os.ErrNotExist
	}
	return upload, nil
}

func (s *pluginBlobStore) abortUploadLocked(upload *pluginBlobUpload) {
	if upload == nil {
		return
	}
	delete(s.uploads, upload.id)
	if upload.file != nil {
		_ = upload.file.Close()
		upload.file = nil
	}
	_ = os.Remove(upload.path)
}

func (s *pluginBlobStore) activeUploadUsageLocked(pluginID string) (int, int64) {
	count := 0
	var bytes int64
	for _, upload := range s.uploads {
		if upload.pluginID == pluginID {
			count++
			bytes += upload.size
		}
	}
	return count, bytes
}

func (s *pluginBlobStore) activeUploadBytesLocked() int64 {
	var bytes int64
	for _, upload := range s.uploads {
		bytes += upload.size
	}
	return bytes
}

func (s *pluginBlobStore) scanUsageLocked() error {
	entries, err := os.ReadDir(s.blobRoot)
	if err != nil {
		return err
	}
	for _, pluginEntry := range entries {
		if !pluginEntry.IsDir() || !pluginIDPattern.MatchString(pluginEntry.Name()) || reservedBuiltinPluginID(pluginEntry.Name()) {
			return fmt.Errorf("plugin blob root contains invalid entry %s", pluginEntry.Name())
		}
		pluginID := pluginEntry.Name()
		files, err := os.ReadDir(filepath.Join(s.blobRoot, pluginID))
		if err != nil {
			return err
		}
		usage := pluginBlobUsage{}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), pluginBlobFileSuffix) {
				return fmt.Errorf("plugin blob directory contains invalid entry %s/%s", pluginID, file.Name())
			}
			key := strings.TrimSuffix(file.Name(), pluginBlobFileSuffix)
			info, err := s.statPathLocked(pluginID, key, filepath.Join(s.blobRoot, pluginID, file.Name()))
			if err != nil {
				return err
			}
			usage.Objects++
			usage.Bytes += info.Bytes
		}
		if usage.Objects > s.limits.BlobObjectsPerPlugin || usage.Bytes > s.limits.PluginBlobBytes {
			return fmt.Errorf("plugin %s blob usage exceeds configured quota", pluginID)
		}
		s.usage[pluginID] = usage
		s.global.Objects += usage.Objects
		s.global.Bytes += usage.Bytes
	}
	if s.global.Bytes > s.limits.GlobalBlobBytes {
		return fmt.Errorf("global plugin blob usage exceeds configured quota")
	}
	return nil
}

func (s *pluginBlobStore) statPathLocked(_ string, key, path string) (pluginBlobInfo, error) {
	file, header, err := openPluginBlobFile(path, key, s.limits.BlobObjectBytes)
	if err != nil {
		return pluginBlobInfo{}, err
	}
	if err := file.Close(); err != nil {
		return pluginBlobInfo{}, err
	}
	return pluginBlobInfoFromHeader(header), nil
}

func (upload *pluginBlobUpload) info() pluginBlobUploadInfo {
	return pluginBlobUploadInfo{
		UploadID: upload.id, Key: upload.key, Bytes: upload.size, ExpectedBytes: upload.expectedBytes,
		ExpectedSHA256: upload.expectedSHA256, CreatedAt: upload.createdAt.Format(time.RFC3339Nano),
	}
}

func normalizePluginBlobOwner(pluginID, generation, key string) (string, string, string, error) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	generation = strings.TrimSpace(generation)
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) || generation == "" {
		return "", "", "", fmt.Errorf("plugin blob owner is invalid")
	}
	key, err := pluginPathToken(key)
	if err != nil {
		return "", "", "", fmt.Errorf("blob key: %w", err)
	}
	return pluginID, generation, key, nil
}

func normalizePluginBlobDigest(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "", nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("sha256 must be 64 lowercase hexadecimal characters")
	}
	return value, nil
}

func newPluginBlobUploadID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "upload_" + hex.EncodeToString(raw[:]), nil
}

func encodePluginBlobHeader(header pluginBlobHeader) ([]byte, error) {
	data, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	if len(data) > pluginBlobHeaderBytes-12 {
		return nil, fmt.Errorf("plugin blob header is too large")
	}
	out := make([]byte, pluginBlobHeaderBytes)
	copy(out[:8], pluginBlobMagic[:])
	binary.BigEndian.PutUint32(out[8:12], uint32(len(data)))
	copy(out[12:], data)
	return out, nil
}

func openPluginBlobFile(path, expectedKey string, maxBytes int64) (*os.File, pluginBlobHeader, error) {
	info, err := os.Lstat(path) // #nosec G703 -- path is below a private root and uses validated tokens.
	if err != nil {
		return nil, pluginBlobHeader{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < pluginBlobHeaderBytes {
		return nil, pluginBlobHeader{}, fmt.Errorf("plugin blob %s is not a regular blob file", expectedKey)
	}
	file, err := os.Open(path) // #nosec G304 -- path was lstat'd below a private root.
	if err != nil {
		return nil, pluginBlobHeader{}, err
	}
	headerBytes := make([]byte, pluginBlobHeaderBytes)
	if _, err := io.ReadFull(file, headerBytes); err != nil {
		_ = file.Close()
		return nil, pluginBlobHeader{}, err
	}
	header, err := decodePluginBlobHeader(headerBytes, expectedKey, maxBytes, info.Size())
	if err != nil {
		_ = file.Close()
		return nil, pluginBlobHeader{}, err
	}
	return file, header, nil
}

func decodePluginBlobHeader(headerBytes []byte, expectedKey string, maxBytes, fileBytes int64) (pluginBlobHeader, error) {
	if len(headerBytes) != pluginBlobHeaderBytes {
		return pluginBlobHeader{}, fmt.Errorf("plugin blob %s has an invalid header size", expectedKey)
	}
	if string(headerBytes[:8]) != string(pluginBlobMagic[:]) {
		return pluginBlobHeader{}, fmt.Errorf("plugin blob %s has an invalid header", expectedKey)
	}
	headerLength := int(binary.BigEndian.Uint32(headerBytes[8:12]))
	if headerLength < 2 || headerLength > pluginBlobHeaderBytes-12 {
		return pluginBlobHeader{}, fmt.Errorf("plugin blob %s has an invalid header length", expectedKey)
	}
	var header pluginBlobHeader
	decoder := json.NewDecoder(strings.NewReader(string(headerBytes[12 : 12+headerLength])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil {
		return pluginBlobHeader{}, fmt.Errorf("decode plugin blob %s header: %w", expectedKey, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return pluginBlobHeader{}, fmt.Errorf("plugin blob %s header contains trailing JSON values", expectedKey)
		}
		return pluginBlobHeader{}, fmt.Errorf("decode trailing plugin blob %s header content: %w", expectedKey, err)
	}
	digest, digestErr := normalizePluginBlobDigest(header.SHA256)
	createdAt, createdErr := time.Parse(time.RFC3339Nano, header.CreatedAt)
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, header.UpdatedAt)
	if header.FormatVersion != pluginBlobFormatVersion || header.Key != expectedKey || header.Bytes < 0 || header.Bytes > maxBytes || digestErr != nil || digest == "" || createdErr != nil || updatedErr != nil || updatedAt.Before(createdAt) || fileBytes != pluginBlobHeaderBytes+header.Bytes {
		return pluginBlobHeader{}, fmt.Errorf("plugin blob %s metadata is invalid", expectedKey)
	}
	return header, nil
}

func pluginBlobInfoFromHeader(header pluginBlobHeader) pluginBlobInfo {
	return pluginBlobInfo{Key: header.Key, Bytes: header.Bytes, SHA256: header.SHA256, CreatedAt: header.CreatedAt, UpdatedAt: header.UpdatedAt}
}

func purgePluginBlobData(stateRoot, pluginID string) error {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return fmt.Errorf("plugin id is invalid")
	}
	for _, root := range []string{filepath.Join(stateRoot, pluginBlobDirectoryName), filepath.Join(stateRoot, pluginBlobUploadDirectoryName)} {
		if err := removePluginPackageManagedPath(root, filepath.Join(root, pluginID)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func purgePluginBlobDataForRuntime(pm *ProcessManager, stateRoot, pluginID string) error {
	if pm != nil {
		pm.mu.Lock()
		runtime, _ := pm.pluginControlRuntime.(*gojaPluginControlRuntime)
		pm.mu.Unlock()
		if runtime != nil {
			if store := runtime.currentPluginBlobStore(); store != nil {
				return store.PurgePlugin(pluginID)
			}
		}
	}
	return purgePluginBlobData(stateRoot, pluginID)
}
