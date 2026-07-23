package app

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	pluginStateBackupFormatVersion = 1
	pluginStateBackupMaxEntries    = 32768
	pluginStateBackupMaxFileBytes  = int64(2 << 30)
	pluginStateBackupMaxTotalBytes = int64(16 << 30)
	pluginStateBackupAttempts      = 3
	pluginStateBackupManifestPath  = "backup.json"
)

type pluginStateBackupManifest struct {
	FormatVersion  int                     `json:"format_version"`
	CreatedAt      string                  `json:"created_at"`
	RuntimeVersion string                  `json:"runtime_version"`
	Files          []pluginStateBackupFile `json:"files"`
}

type pluginStateBackupFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type pluginStateBackupResult struct {
	Archive       string `json:"archive"`
	ArchiveSHA256 string `json:"archive_sha256"`
	Bytes         int64  `json:"bytes"`
	Files         int    `json:"files"`
	CreatedAt     string `json:"created_at"`
}

type pluginStateBackupSource struct {
	diskPath    string
	archivePath string
	size        int64
	digest      string
}

func runPluginStateBackupCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin backup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("database", "forward.db", "Veer SQLite database path")
	pluginsDir := flags.String("plugins-dir", defaultPluginsDir, "managed plugins directory")
	output := flags.String("output", "", "output backup .tar.gz path")
	force := flags.Bool("force", false, "replace an existing regular output file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*output) == "" {
		return fmt.Errorf("plugin backup requires --output and no positional arguments")
	}
	dbPath, err := filepath.Abs(strings.TrimSpace(*databasePath))
	if err != nil {
		return err
	}
	pluginRoot, err := filepath.Abs(normalizePluginsDir(*pluginsDir))
	if err != nil {
		return err
	}
	target, err := filepath.Abs(strings.TrimSpace(*output))
	if err != nil {
		return err
	}
	result, err := createPluginStateBackup(dbPath, pluginRoot, target, *force)
	if err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, result)
}

func createPluginStateBackup(databasePath, pluginsRoot, output string, force bool) (pluginStateBackupResult, error) {
	if err := validatePluginStateBackupInputs(databasePath, pluginsRoot, output, force); err != nil {
		return pluginStateBackupResult{}, err
	}
	db, err := initDB(databasePath)
	if err != nil {
		return pluginStateBackupResult{}, fmt.Errorf("open backup database: %w", err)
	}
	defer db.Close()
	workDir, err := os.MkdirTemp(filepath.Dir(output), ".veer-plugin-backup-*")
	if err != nil {
		return pluginStateBackupResult{}, err
	}
	defer os.RemoveAll(workDir)

	var lastErr error
	for attempt := 0; attempt < pluginStateBackupAttempts; attempt++ {
		before, err := pluginStateBackupLiveFingerprint(pluginsRoot, databasePath+pluginSecretKeyFileSuffix)
		if err != nil {
			return pluginStateBackupResult{}, err
		}
		snapshotPath := filepath.Join(workDir, fmt.Sprintf("database-%d.db", attempt))
		if err := vacuumPluginStateBackupDatabase(db, snapshotPath); err != nil {
			return pluginStateBackupResult{}, err
		}
		keySnapshot := ""
		keyPath := databasePath + pluginSecretKeyFileSuffix
		if exists, err := boundedRegularFileExists(keyPath, pluginSecretKeyringMaxBytes); err != nil {
			return pluginStateBackupResult{}, err
		} else if exists {
			keySnapshot = filepath.Join(workDir, fmt.Sprintf("secrets-%d.key", attempt))
			if err := copyPluginStateBackupFile(keyPath, keySnapshot, pluginSecretKeyringMaxBytes); err != nil {
				return pluginStateBackupResult{}, err
			}
		}
		sources, err := collectPluginStateBackupSources(snapshotPath, keySnapshot, pluginsRoot)
		if err != nil {
			return pluginStateBackupResult{}, err
		}
		createdAt := time.Now().UTC()
		archiveTemp := filepath.Join(workDir, fmt.Sprintf("backup-%d.tar.gz", attempt))
		manifest, err := writePluginStateBackupArchive(archiveTemp, sources, createdAt)
		if err != nil {
			return pluginStateBackupResult{}, err
		}
		after, err := pluginStateBackupLiveFingerprint(pluginsRoot, keyPath)
		if err != nil {
			return pluginStateBackupResult{}, err
		}
		if before != after {
			lastErr = fmt.Errorf("plugin state changed while creating backup")
			continue
		}
		if err := installPluginStateBackupOutput(archiveTemp, output, force); err != nil {
			return pluginStateBackupResult{}, err
		}
		digest, err := sha256File(output)
		if err != nil {
			return pluginStateBackupResult{}, err
		}
		info, err := os.Stat(output)
		if err != nil {
			return pluginStateBackupResult{}, err
		}
		return pluginStateBackupResult{
			Archive: output, ArchiveSHA256: digest, Bytes: info.Size(), Files: len(manifest.Files), CreatedAt: manifest.CreatedAt,
		}, nil
	}
	return pluginStateBackupResult{}, lastErr
}

func validatePluginStateBackupInputs(databasePath, pluginsRoot, output string, force bool) error {
	for label, value := range map[string]string{"database": databasePath, "plugins directory": pluginsRoot, "output": output} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s path is required", label)
		}
	}
	info, err := os.Lstat(databasePath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("backup database must be a regular file")
	}
	if existing, err := os.Lstat(output); err == nil {
		if !force || existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return fmt.Errorf("backup output already exists")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, root := range []string{pluginsRoot, pluginsRoot + pluginPackageStateSuffix} {
		if root == output || pathWithinRoot(root, output) {
			return fmt.Errorf("backup output must be outside managed plugin directories")
		}
	}
	return nil
}

func vacuumPluginStateBackupDatabase(db *sql.DB, destination string) error {
	if db == nil {
		return fmt.Errorf("backup database is unavailable")
	}
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		return err
	}
	quoted := "'" + strings.ReplaceAll(destination, "'", "''") + "'"
	if _, err := db.Exec("VACUUM INTO " + quoted); err != nil {
		return fmt.Errorf("snapshot plugin database: %w", err)
	}
	return os.Chmod(destination, 0o600)
}

func pluginStateBackupLiveFingerprint(pluginsRoot, keyPath string) (string, error) {
	parts := make([]string, 0, 3)
	for _, item := range []struct {
		root string
		skip func(string, os.DirEntry) bool
	}{{root: pluginsRoot}, {root: pluginsRoot + pluginPackageStateSuffix, skip: pluginStateBackupSkipVolatile}} {
		fingerprint, err := buildPluginDirectoryFingerprintWithSkip(item.root, item.skip)
		if err != nil {
			return "", err
		}
		parts = append(parts, fingerprint)
	}
	if exists, err := boundedRegularFileExists(keyPath, pluginSecretKeyringMaxBytes); err != nil {
		return "", err
	} else if exists {
		digest, err := sha256File(keyPath)
		if err != nil {
			return "", err
		}
		parts = append(parts, digest)
	} else {
		parts = append(parts, "no-keyring")
	}
	hash := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(hash[:]), nil
}

func boundedRegularFileExists(path string, maxBytes int64) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return false, fmt.Errorf("%s is not a bounded regular file", path)
	}
	return true, nil
}

func copyPluginStateBackupFile(source, destination string, maxBytes int64) error {
	input, err := os.Open(source) // #nosec G304 -- CLI paths are checked before use.
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- destination is a private temporary path.
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, maxBytes+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if written > maxBytes {
		return fmt.Errorf("backup source exceeds %d bytes", maxBytes)
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func collectPluginStateBackupSources(databaseSnapshot, keySnapshot, pluginsRoot string) ([]pluginStateBackupSource, error) {
	sources := make([]pluginStateBackupSource, 0)
	if err := addPluginStateBackupFile(&sources, databaseSnapshot, "database/forward.db"); err != nil {
		return nil, err
	}
	if keySnapshot != "" {
		if err := addPluginStateBackupFile(&sources, keySnapshot, "database/forward.db"+pluginSecretKeyFileSuffix); err != nil {
			return nil, err
		}
	}
	for _, root := range []struct {
		disk string
		name string
	}{{pluginsRoot, "plugins"}, {pluginsRoot + pluginPackageStateSuffix, "state"}} {
		info, err := os.Lstat(root.disk)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("backup root %s must be a regular directory", root.disk)
		}
		if err := filepath.WalkDir(root.disk, func(filePath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if filePath == root.disk {
				return nil
			}
			rel, err := filepath.Rel(root.disk, filePath)
			if err != nil {
				return err
			}
			if root.name == "state" && pluginStateBackupSkipVolatile(filepath.ToSlash(rel), entry) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("backup source contains symbolic link %s", filePath)
			}
			if entry.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("backup source contains unsupported file %s", filePath)
			}
			return addPluginStateBackupFile(&sources, filePath, root.name+"/"+filepath.ToSlash(rel))
		}); err != nil {
			return nil, err
		}
	}
	if len(sources) > pluginStateBackupMaxEntries {
		return nil, fmt.Errorf("plugin backup contains more than %d files", pluginStateBackupMaxEntries)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].archivePath < sources[j].archivePath })
	var total int64
	for _, source := range sources {
		if total > pluginStateBackupMaxTotalBytes-source.size {
			return nil, fmt.Errorf("plugin backup exceeds %d bytes", pluginStateBackupMaxTotalBytes)
		}
		total += source.size
	}
	return sources, nil
}

func pluginStateBackupSkipVolatile(rel string, _ os.DirEntry) bool {
	rel = filepath.ToSlash(rel)
	return rel == pluginBlobUploadDirectoryName || strings.HasPrefix(rel, pluginBlobUploadDirectoryName+"/")
}

func addPluginStateBackupFile(sources *[]pluginStateBackupSource, diskPath, archivePath string) error {
	archivePath, err := normalizePluginPackageEntryName(archivePath)
	if err != nil || archivePath == "" {
		return fmt.Errorf("invalid backup path %q", archivePath)
	}
	info, err := os.Lstat(diskPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > pluginStateBackupMaxFileBytes {
		return fmt.Errorf("backup file %s is invalid or exceeds %d bytes", diskPath, pluginStateBackupMaxFileBytes)
	}
	digest, err := sha256File(diskPath)
	if err != nil {
		return err
	}
	*sources = append(*sources, pluginStateBackupSource{diskPath: diskPath, archivePath: archivePath, size: info.Size(), digest: digest})
	return nil
}

func writePluginStateBackupArchive(destination string, sources []pluginStateBackupSource, createdAt time.Time) (pluginStateBackupManifest, error) {
	manifest := pluginStateBackupManifest{
		FormatVersion: pluginStateBackupFormatVersion,
		CreatedAt:     createdAt.UTC().Format(time.RFC3339Nano), RuntimeVersion: pluginRuntimeVersion,
		Files: make([]pluginStateBackupFile, 0, len(sources)),
	}
	for _, source := range sources {
		manifest.Files = append(manifest.Files, pluginStateBackupFile{Path: source.archivePath, SHA256: source.digest, Bytes: source.size})
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return pluginStateBackupManifest{}, err
	}
	manifestData = append(manifestData, '\n')
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- destination is a private temporary path.
	if err != nil {
		return pluginStateBackupManifest{}, err
	}
	gzipWriter := gzip.NewWriter(file)
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	writeEntry := func(name string, size int64, reader io.Reader) error {
		header := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: size, ModTime: time.Unix(0, 0).UTC(), Uid: 0, Gid: 0}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		written, err := io.CopyN(tarWriter, reader, size)
		if err != nil || written != size {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
		return nil
	}
	writeErr := writeEntry(pluginStateBackupManifestPath, int64(len(manifestData)), strings.NewReader(string(manifestData)))
	for _, source := range sources {
		if writeErr != nil {
			break
		}
		input, err := os.Open(source.diskPath) // #nosec G304 -- source was collected from validated roots.
		if err != nil {
			writeErr = err
			break
		}
		hash := sha256.New()
		writeErr = writeEntry(source.archivePath, source.size, io.TeeReader(input, hash))
		closeErr := input.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
		if writeErr == nil && hex.EncodeToString(hash.Sum(nil)) != source.digest {
			writeErr = fmt.Errorf("backup source %s changed while reading", source.archivePath)
		}
	}
	tarErr := tarWriter.Close()
	gzipErr := gzipWriter.Close()
	syncErr := file.Sync()
	closeErr := file.Close()
	for _, err := range []error{writeErr, tarErr, gzipErr, syncErr, closeErr} {
		if err != nil {
			_ = os.Remove(destination)
			return pluginStateBackupManifest{}, err
		}
	}
	return manifest, nil
}

func installPluginStateBackupOutput(source, output string, force bool) error {
	if err := os.MkdirAll(filepath.Dir(output), 0o750); err != nil {
		return err
	}
	if existing, err := os.Lstat(output); err == nil {
		if !force || existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return fmt.Errorf("backup output already exists")
		}
		if err := os.Remove(output); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(source, output); err != nil {
		return err
	}
	return os.Chmod(output, 0o600)
}
