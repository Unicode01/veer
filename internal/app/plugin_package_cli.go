package app

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	pluginPackageSignatureFileVersion = 1
	pluginPackageCLIKeyMaxBytes       = 64 << 10
)

type pluginPackageSignatureFile struct {
	Version       int    `json:"version"`
	SignerID      string `json:"signer_id"`
	ArchiveSHA256 string `json:"archive_sha256"`
	Signature     string `json:"signature"`
	CreatedAt     string `json:"created_at"`
}

type pluginPackageCLIArchiveInfo struct {
	PluginID      string `json:"plugin_id"`
	Version       string `json:"version"`
	Archive       string `json:"archive"`
	ArchiveSHA256 string `json:"archive_sha256"`
	Bytes         int64  `json:"bytes"`
}

func runPluginPackageCLI(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "plugin" {
		return false, nil
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) < 2 {
		writePluginPackageCLIUsage(stderr)
		return true, fmt.Errorf("plugin subcommand is required")
	}
	var err error
	switch args[1] {
	case "init":
		err = runPluginInitCLI(args[2:], stdout, stderr)
	case "lint":
		err = runPluginLintCLI(args[2:], stdout, stderr, false)
	case "test":
		err = runPluginLintCLI(args[2:], stdout, stderr, true)
	case "contract":
		err = runPluginContractCLI(args[2:], stdout, stderr)
	case "build":
		err = runPluginBuildCLI(args[2:], stdout, stderr)
	case "pack":
		err = runPluginPackagePackCLI(args[2:], stdout, stderr)
	case "backup":
		err = runPluginStateBackupCLI(args[2:], stdout, stderr)
	case "restore":
		err = runPluginStateRestoreCLI(args[2:], stdout, stderr)
	case "keygen":
		err = runPluginPackageKeygenCLI(args[2:], stdout, stderr)
	case "sign":
		err = runPluginPackageSignCLI(args[2:], stdout, stderr)
	case "verify":
		err = runPluginPackageVerifyCLI(args[2:], stdout, stderr)
	case "repository":
		err = runPluginRepositoryCLI(args[2:], stdout, stderr)
	case "help", "-h", "--help":
		writePluginPackageCLIUsage(stdout)
	default:
		writePluginPackageCLIUsage(stderr)
		err = fmt.Errorf("unknown plugin subcommand %q", args[1])
	}
	return true, err
}

func writePluginPackageCLIUsage(w io.Writer) {
	fmt.Fprintln(w, "Veer plugin tools:")
	fmt.Fprintln(w, "  veer plugin init --id ID [--name NAME] [--kind control|pipeline] [--directory DIR]")
	fmt.Fprintln(w, "  veer plugin lint --source DIR")
	fmt.Fprintln(w, "  veer plugin test --source DIR")
	fmt.Fprintln(w, "  veer plugin contract [--check FILE | --output FILE | --types-output FILE] [--force]")
	fmt.Fprintln(w, "  veer plugin build --source DIR [--architectures amd64,arm64,arm] [--output-dir build]")
	fmt.Fprintln(w, "  veer plugin pack --source DIR [--output FILE]")
	fmt.Fprintln(w, "  veer plugin backup --database FILE --plugins-dir DIR --output FILE")
	fmt.Fprintln(w, "  veer plugin restore (--archive FILE | --status | --retry | --cancel) [--database FILE] [--plugins-dir DIR]")
	fmt.Fprintln(w, "  veer plugin keygen --private-key FILE --public-key FILE")
	fmt.Fprintln(w, "  veer plugin sign --archive FILE --private-key FILE [--signature FILE]")
	fmt.Fprintln(w, "  veer plugin verify --archive FILE --signature FILE --public-key FILE")
	fmt.Fprintln(w, "  veer plugin repository init|add|revoke|publish|rotate-key|status [options]")
}

func runPluginPackagePackCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin pack", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "plugin source directory")
	output := flags.String("output", "", "output .tar.gz path")
	force := flags.Bool("force", false, "replace an existing regular output file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*source) == "" {
		return fmt.Errorf("plugin pack requires --source and no positional arguments")
	}
	plugin, err := validatePluginPackageSource(*source)
	if err != nil {
		return err
	}
	target := strings.TrimSpace(*output)
	if target == "" {
		target = plugin.ID + "-" + plugin.Version + ".tar.gz"
	}
	info, err := packPluginDirectory(plugin, target, *force)
	if err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, info)
}

func runPluginPackageKeygenCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	privatePath := flags.String("private-key", "", "new PKCS#8 private key path")
	publicPath := flags.String("public-key", "", "new base64 public key path")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*privatePath) == "" || strings.TrimSpace(*publicPath) == "" {
		return fmt.Errorf("plugin keygen requires --private-key and --public-key")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicData := []byte(base64.StdEncoding.EncodeToString(publicKey) + "\n")
	if err := writePluginCLIFileExclusive(*privatePath, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writePluginCLIFileExclusive(*publicPath, publicData, 0o644); err != nil {
		_ = os.Remove(*privatePath)
		return fmt.Errorf("write public key: %w", err)
	}
	return writePluginPackageCLIJSON(stdout, map[string]any{
		"signer_id": pluginTrustKeyID(publicKey), "public_key": strings.TrimSpace(string(publicData)),
		"private_key_file": *privatePath, "public_key_file": *publicPath,
	})
}

func runPluginPackageSignCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	archivePath := flags.String("archive", "", "plugin .tar.gz archive")
	privatePath := flags.String("private-key", "", "Ed25519 private key path")
	signaturePath := flags.String("signature", "", "signature sidecar path")
	force := flags.Bool("force", false, "replace an existing regular signature file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*archivePath) == "" || strings.TrimSpace(*privatePath) == "" {
		return fmt.Errorf("plugin sign requires --archive and --private-key")
	}
	archive, err := inspectPluginPackageArchive(*archivePath)
	if err != nil {
		return err
	}
	privateKey, err := loadPluginPackagePrivateKey(*privatePath)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	digestBytes, _ := hex.DecodeString(archive.ArchiveSHA256)
	signature := ed25519.Sign(privateKey, append([]byte(pluginPackageSignatureDomain), digestBytes...))
	sidecar := pluginPackageSignatureFile{
		Version: pluginPackageSignatureFileVersion, SignerID: pluginTrustKeyID(publicKey), ArchiveSHA256: archive.ArchiveSHA256,
		Signature: base64.StdEncoding.EncodeToString(signature), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	target := strings.TrimSpace(*signaturePath)
	if target == "" {
		target = *archivePath + ".sig"
	}
	if err := writePluginPackageCLIJSONFile(target, sidecar, *force, 0o644); err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, map[string]any{
		"plugin_id": archive.PluginID, "version": archive.Version, "archive_sha256": archive.ArchiveSHA256,
		"signer_id": sidecar.SignerID, "public_key": base64.StdEncoding.EncodeToString(publicKey), "signature_file": target,
	})
}

func runPluginPackageVerifyCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	archivePath := flags.String("archive", "", "plugin .tar.gz archive")
	signaturePath := flags.String("signature", "", "signature sidecar path")
	publicPath := flags.String("public-key", "", "trusted Ed25519 public key path")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*archivePath) == "" || strings.TrimSpace(*signaturePath) == "" || strings.TrimSpace(*publicPath) == "" {
		return fmt.Errorf("plugin verify requires --archive, --signature, and --public-key")
	}
	archive, err := inspectPluginPackageArchive(*archivePath)
	if err != nil {
		return err
	}
	var sidecar pluginPackageSignatureFile
	if err := readPluginPackageCLIJSONFile(*signaturePath, &sidecar); err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	if sidecar.Version != pluginPackageSignatureFileVersion || sidecar.ArchiveSHA256 != archive.ArchiveSHA256 {
		return fmt.Errorf("plugin package signature metadata does not match the archive")
	}
	publicKey, err := loadPluginPackagePublicKey(*publicPath)
	if err != nil {
		return err
	}
	if pluginTrustKeyID(publicKey) != sidecar.SignerID {
		return fmt.Errorf("plugin package signer id does not match the trusted public key")
	}
	signature, err := decodePluginPackageSignature(sidecar.Signature)
	if err != nil {
		return err
	}
	digestBytes, _ := hex.DecodeString(archive.ArchiveSHA256)
	if !ed25519.Verify(publicKey, append([]byte(pluginPackageSignatureDomain), digestBytes...), signature) {
		return fmt.Errorf("plugin package signature verification failed")
	}
	return writePluginPackageCLIJSON(stdout, map[string]any{
		"verified": true, "plugin_id": archive.PluginID, "version": archive.Version,
		"archive_sha256": archive.ArchiveSHA256, "signer_id": sidecar.SignerID,
	})
}

func validatePluginPackageSource(source string) (LoadedPlugin, error) {
	absSource, err := filepath.Abs(source)
	if err != nil {
		return LoadedPlugin{}, err
	}
	info, err := os.Lstat(absSource)
	if err != nil {
		return LoadedPlugin{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return LoadedPlugin{}, fmt.Errorf("plugin source must be a regular directory")
	}
	plugin, err := loadPluginFromDir(absSource, filepath.Base(absSource))
	if err != nil {
		return LoadedPlugin{}, err
	}
	if plugin.Status != pluginStatusActive {
		return LoadedPlugin{}, fmt.Errorf("plugin source is invalid: %s", plugin.Error)
	}
	isolation := false
	plugin, err = registerPluginPackageCandidate(plugin, &Config{
		PluginsIsolationSetting: &isolation,
		PluginsMinSandboxLevel:  pluginSandboxLevelNone,
	})
	if err != nil {
		return LoadedPlugin{}, err
	}
	return plugin, nil
}

type pluginPackagePackEntry struct {
	path string
	rel  string
	info os.FileInfo
}

func packPluginDirectory(plugin LoadedPlugin, output string, force bool) (pluginPackageCLIArchiveInfo, error) {
	absSource, err := filepath.Abs(plugin.rootDir)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	if pathWithinRoot(absSource, absOutput) {
		return pluginPackageCLIArchiveInfo{}, fmt.Errorf("plugin package output must be outside the source directory")
	}
	entries := make([]pluginPackagePackEntry, 0)
	var totalBytes int64
	err = filepath.Walk(absSource, func(current string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("plugin source contains symbolic link %s", current)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("plugin source contains unsupported file %s", current)
		}
		rel, err := filepath.Rel(absSource, current)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if len(entries)+2 > pluginPackageMaxEntries {
			return fmt.Errorf("plugin package contains more than %d entries", pluginPackageMaxEntries)
		}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || info.Size() > pluginPackageMaxEntryBytes {
				return fmt.Errorf("plugin source entry %s exceeds %d bytes", filepath.ToSlash(rel), pluginPackageMaxEntryBytes)
			}
			if totalBytes > pluginPackageMaxExtractedBytes-info.Size() {
				return fmt.Errorf("plugin source exceeds %d bytes", pluginPackageMaxExtractedBytes)
			}
			totalBytes += info.Size()
		}
		entries = append(entries, pluginPackagePackEntry{path: current, rel: filepath.ToSlash(rel), info: info})
		return nil
	})
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	if err := os.MkdirAll(filepath.Dir(absOutput), 0o755); err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	temp, err := os.CreateTemp(filepath.Dir(absOutput), ".veer-plugin-package-*")
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	hash := sha256.New()
	gzipWriter := gzip.NewWriter(io.MultiWriter(temp, hash))
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writePluginPackageTarHeader(tarWriter, plugin.ID+"/", true, 0); err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	for _, entry := range entries {
		name := path.Join(plugin.ID, entry.rel)
		if entry.info.IsDir() {
			if err := writePluginPackageTarHeader(tarWriter, name+"/", true, 0); err != nil {
				return pluginPackageCLIArchiveInfo{}, err
			}
			continue
		}
		if err := writePluginPackageTarHeader(tarWriter, name, false, entry.info.Size()); err != nil {
			return pluginPackageCLIArchiveInfo{}, err
		}
		file, err := os.Open(entry.path) // #nosec G304 -- entry is from the validated source walk.
		if err != nil {
			return pluginPackageCLIArchiveInfo{}, err
		}
		written, copyErr := io.CopyN(tarWriter, file, entry.info.Size())
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != entry.info.Size() {
			if copyErr != nil {
				return pluginPackageCLIArchiveInfo{}, copyErr
			}
			if closeErr != nil {
				return pluginPackageCLIArchiveInfo{}, closeErr
			}
			return pluginPackageCLIArchiveInfo{}, fmt.Errorf("plugin source entry %s changed while packing", entry.rel)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	if err := gzipWriter.Close(); err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	if err := temp.Sync(); err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	if err := temp.Close(); err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	info, err := os.Stat(tempPath)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	if info.Size() <= 0 || info.Size() > pluginPackageMaxArchiveBytes {
		return pluginPackageCLIArchiveInfo{}, fmt.Errorf("plugin package archive exceeds %d bytes", pluginPackageMaxArchiveBytes)
	}
	inspected, err := inspectPluginPackageArchive(tempPath)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, fmt.Errorf("verify packed plugin: %w", err)
	}
	if inspected.PluginID != plugin.ID || inspected.Version != plugin.Version {
		return pluginPackageCLIArchiveInfo{}, fmt.Errorf("packed plugin identity changed during validation")
	}
	if existing, err := os.Lstat(absOutput); err == nil {
		if !force || existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return pluginPackageCLIArchiveInfo{}, fmt.Errorf("plugin package output already exists")
		}
		if err := os.Remove(absOutput); err != nil {
			return pluginPackageCLIArchiveInfo{}, err
		}
	} else if !os.IsNotExist(err) {
		return pluginPackageCLIArchiveInfo{}, err
	}
	if err := os.Rename(tempPath, absOutput); err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	cleanup = false
	return pluginPackageCLIArchiveInfo{
		PluginID: plugin.ID, Version: plugin.Version, Archive: absOutput,
		ArchiveSHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: info.Size(),
	}, nil
}

func writePluginPackageTarHeader(writer *tar.Writer, name string, directory bool, size int64) error {
	header := &tar.Header{
		Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg,
		ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{}, Format: tar.FormatPAX,
	}
	if directory {
		header.Mode = 0o755
		header.Size = 0
		header.Typeflag = tar.TypeDir
	}
	return writer.WriteHeader(header)
}

func inspectPluginPackageArchive(archivePath string) (pluginPackageCLIArchiveInfo, error) {
	absArchive, data, info, err := readPluginCLIRegularFile(archivePath, pluginPackageMaxArchiveBytes)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	digest := sha256.Sum256(data)
	tempRoot, err := os.MkdirTemp("", "veer-plugin-verify-*")
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	defer os.RemoveAll(tempRoot)
	pluginRoot, err := extractPluginPackageArchive(absArchive, tempRoot)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	plugin, err := validatePluginPackageSource(pluginRoot)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, err
	}
	if filepath.Base(pluginRoot) != plugin.ID {
		return pluginPackageCLIArchiveInfo{}, fmt.Errorf("plugin package directory %q does not match manifest id %q", filepath.Base(pluginRoot), plugin.ID)
	}
	return pluginPackageCLIArchiveInfo{
		PluginID: plugin.ID, Version: plugin.Version, Archive: absArchive,
		ArchiveSHA256: hex.EncodeToString(digest[:]), Bytes: info.Size(),
	}, nil
}

func loadPluginPackagePrivateKey(path string) (ed25519.PrivateKey, error) {
	_, data, info, err := readPluginCLIRegularFile(path, pluginPackageCLIKeyMaxBytes)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("Ed25519 private key permissions must not grant group or other access")
	}
	if block, _ := pem.Decode(data); block != nil {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse Ed25519 private key: %w", err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	}
	raw, err := decodePluginPackageKeyData(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode Ed25519 private key: %w", err)
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Ed25519 private key must be a %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
	derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if !ed25519.PrivateKey(raw).Equal(derived) {
		return nil, fmt.Errorf("Ed25519 private key failed integrity validation")
	}
	return derived, nil
}

func loadPluginPackagePublicKey(path string) (ed25519.PublicKey, error) {
	_, data, _, err := readPluginCLIRegularFile(path, pluginPackageCLIKeyMaxBytes)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse Ed25519 public key: %w", err)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not Ed25519")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	}
	return decodePluginTrustPublicKey(strings.TrimSpace(string(data)))
}

func decodePluginPackageKeyData(value string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	if raw, err := hex.DecodeString(value); err == nil {
		return raw, nil
	}
	return nil, fmt.Errorf("key must be PKCS#8 PEM, base64, or hexadecimal")
}

func readPluginCLIRegularFile(path string, maxBytes int64) (string, []byte, os.FileInfo, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", nil, nil, err
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return "", nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return "", nil, nil, fmt.Errorf("path must be a non-empty regular file no larger than %d bytes", maxBytes)
	}
	data, err := os.ReadFile(absPath) // #nosec G304 -- the bounded path was checked with Lstat.
	if err != nil {
		return "", nil, nil, err
	}
	if int64(len(data)) != info.Size() {
		return "", nil, nil, fmt.Errorf("file changed while reading")
	}
	return absPath, data, info, nil
}

func writePluginCLIFileExclusive(path string, data []byte, mode os.FileMode) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(absPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304 -- caller supplied CLI output.
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(absPath)
		if writeErr != nil {
			return writeErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return os.Chmod(absPath, mode)
}

func writePluginPackageCLIJSONFile(path string, value any, force bool, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if existing, err := os.Lstat(absPath); err == nil {
		if !force || existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return fmt.Errorf("output file already exists")
		}
		if err := os.Remove(absPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return writePluginCLIFileExclusive(absPath, data, mode)
}

func readPluginPackageCLIJSONFile(path string, target any) error {
	_, data, _, err := readPluginCLIRegularFile(path, 1<<20)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("metadata contains trailing JSON")
	}
	return nil
}

func writePluginPackageCLIJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
