package app

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const pluginPackageTarTypeLegacyRegular byte = 0

func writeBoundedPluginPackageFile(reader io.Reader, destination string, maxBytes int64, label string) (string, int64, error) {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- destination is a private manager staging path.
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, maxBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", written, copyErr
	}
	if closeErr != nil {
		return "", written, closeErr
	}
	if written == 0 {
		return "", 0, fmt.Errorf("%s is empty", label)
	}
	if written > maxBytes {
		return "", written, fmt.Errorf("%s exceeds %d bytes", label, maxBytes)
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func extractPluginPackageArchive(archivePath, destination string) (string, error) {
	archive, err := os.Open(archivePath) // #nosec G304 -- archivePath is a manager-owned staging path.
	if err != nil {
		return "", err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return "", fmt.Errorf("open gzip stream: %w", err)
	}
	defer gzipReader.Close()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return "", err
	}
	absDestination, err := filepath.Abs(destination)
	if err != nil {
		return "", err
	}

	reader := tar.NewReader(gzipReader)
	seen := make(map[string]struct{})
	topLevels := make(map[string]struct{})
	entryCount := 0
	var extractedBytes int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry: %w", err)
		}
		entryCount++
		if entryCount > pluginPackageMaxEntries {
			return "", fmt.Errorf("plugin package contains more than %d entries", pluginPackageMaxEntries)
		}
		name, err := normalizePluginPackageEntryName(header.Name)
		if err != nil {
			return "", err
		}
		if name == "" {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			return "", fmt.Errorf("plugin package contains duplicate entry %q", name)
		}
		seen[name] = struct{}{}
		topLevel := strings.SplitN(name, "/", 2)[0]
		topLevels[topLevel] = struct{}{}
		if len(topLevels) > 1 {
			return "", fmt.Errorf("plugin package must contain exactly one top-level plugin directory")
		}

		target := filepath.Join(absDestination, filepath.FromSlash(name))
		if !pathWithinRoot(absDestination, target) || target == absDestination {
			return "", fmt.Errorf("plugin package entry %q escapes extraction root", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return "", fmt.Errorf("create directory %q: %w", name, err)
			}
		case tar.TypeReg, pluginPackageTarTypeLegacyRegular:
			if header.Size < 0 || header.Size > pluginPackageMaxEntryBytes {
				return "", fmt.Errorf("plugin package entry %q exceeds %d bytes", name, pluginPackageMaxEntryBytes)
			}
			if extractedBytes > pluginPackageMaxExtractedBytes-header.Size {
				return "", fmt.Errorf("plugin package extracted content exceeds %d bytes", pluginPackageMaxExtractedBytes)
			}
			extractedBytes += header.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return "", err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- target is bounded to the private extraction directory.
			if err != nil {
				return "", fmt.Errorf("create entry %q: %w", name, err)
			}
			written, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return "", fmt.Errorf("extract entry %q after %d bytes: %w", name, written, copyErr)
			}
			if closeErr != nil {
				return "", fmt.Errorf("close entry %q: %w", name, closeErr)
			}
		default:
			return "", fmt.Errorf("plugin package entry %q uses unsupported tar type %d", name, header.Typeflag)
		}
	}
	if entryCount == 0 || len(topLevels) != 1 {
		return "", fmt.Errorf("plugin package must contain exactly one top-level plugin directory")
	}
	var topLevel string
	for value := range topLevels {
		topLevel = value
	}
	pluginRoot := filepath.Join(absDestination, filepath.FromSlash(topLevel))
	info, err := os.Stat(pluginRoot)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("plugin package top-level entry %q is not a directory", topLevel)
	}
	return pluginRoot, nil
}

func normalizePluginPackageEntryName(value string) (string, error) {
	if strings.Contains(value, "\x00") || strings.Contains(value, "\\") {
		return "", fmt.Errorf("plugin package entry %q contains invalid characters", value)
	}
	value = strings.TrimPrefix(value, "./")
	value = strings.TrimSuffix(value, "/")
	if value == "" || value == "." {
		return "", nil
	}
	if strings.HasPrefix(value, "/") || path.IsAbs(value) {
		return "", fmt.Errorf("plugin package entry %q is absolute", value)
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != value {
		return "", fmt.Errorf("plugin package entry %q is not a canonical relative path", value)
	}
	for _, component := range strings.Split(clean, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return "", fmt.Errorf("plugin package entry %q has an invalid path component", value)
		}
	}
	return clean, nil
}

func copyPluginDirectoryStrict(source, destination string) error {
	absSource, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	realSource, err := filepath.EvalSymlinks(absSource)
	if err != nil {
		return err
	}
	info, err := os.Lstat(realSource)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("plugin source is not a regular directory")
	}
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("plugin copy destination already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(realSource, func(sourcePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(realSource, sourcePath)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(destination, rel)
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("plugin path %s is a symbolic link", filepath.ToSlash(rel))
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("plugin path %s has unsupported mode %s", filepath.ToSlash(rel), entryInfo.Mode())
		}
		if entryInfo.Size() > pluginPackageMaxEntryBytes {
			return fmt.Errorf("plugin path %s exceeds %d bytes", filepath.ToSlash(rel), pluginPackageMaxEntryBytes)
		}
		return copyPluginPackageFile(sourcePath, target)
	})
}

func copyPluginPackageFile(source, destination string) error {
	input, err := os.Open(source) // #nosec G304 -- source is from a symlink-free bounded plugin walk.
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- destination is a manager-owned private path.
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, io.LimitReader(input, pluginPackageMaxEntryBytes+1))
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func removePluginPackageManagedPath(root, target string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if absTarget == absRoot || !pathWithinRoot(absRoot, absTarget) {
		return fmt.Errorf("refuse to remove path outside plugin package state root")
	}
	return os.RemoveAll(absTarget)
}
