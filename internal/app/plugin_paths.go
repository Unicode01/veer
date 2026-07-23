package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var errPluginPathEscapesRoot = errors.New("path escapes plugin root")

func normalizePluginRelativePath(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		return "", nil
	}
	nativePath := filepath.FromSlash(value)
	if strings.HasPrefix(value, "/") || path.IsAbs(value) || filepath.IsAbs(nativePath) || filepath.VolumeName(nativePath) != "" {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	clean := path.Clean(value)
	if clean == "." {
		return "", nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path traversal is not allowed")
	}
	return clean, nil
}

func pathWithinRoot(root, target string) bool {
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	cleanTarget, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func readPluginRootedRegularFile(rootDir, relativePath string, maxBytes int64) ([]byte, os.FileInfo, error) {
	relativePath, err := normalizePluginRelativePath(relativePath)
	if err != nil {
		return nil, nil, err
	}
	if relativePath == "" {
		return nil, nil, fmt.Errorf("path is required")
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	file, err := root.Open(filepath.FromSlash(relativePath))
	if err != nil {
		return nil, nil, normalizePluginRootOpenError(err)
	}
	defer file.Close()
	return readBoundedRegularFile(file, maxBytes)
}

func readBoundedRegularFileAtPath(filePath string, maxBytes int64, allowSymlink bool) ([]byte, os.FileInfo, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(absPath))
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	name := filepath.Base(absPath)
	var expectedInfo os.FileInfo
	if !allowSymlink {
		info, err := root.Lstat(name)
		if err != nil {
			return nil, nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, info, fmt.Errorf("path is a symbolic link")
		}
		expectedInfo = info
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, normalizePluginRootOpenError(err)
	}
	defer file.Close()
	if expectedInfo != nil {
		openedInfo, err := file.Stat()
		if err != nil {
			return nil, nil, err
		}
		if !os.SameFile(expectedInfo, openedInfo) {
			return nil, openedInfo, fmt.Errorf("path changed while opening")
		}
	}
	return readBoundedRegularFile(file, maxBytes)
}

func readBoundedRegularFile(file *os.File, maxBytes int64) ([]byte, os.FileInfo, error) {
	if file == nil {
		return nil, nil, fmt.Errorf("file is unavailable")
	}
	if maxBytes < 0 {
		return nil, nil, fmt.Errorf("file size limit is invalid")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		if info.IsDir() {
			return nil, info, fmt.Errorf("path is a directory")
		}
		return nil, info, fmt.Errorf("path is not a regular file")
	}
	if info.Size() > maxBytes {
		return nil, info, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, info, err
	}
	if int64(len(data)) > maxBytes {
		return nil, info, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, info, nil
}

func normalizePluginRootOpenError(err error) error {
	for current := err; current != nil; current = errors.Unwrap(current) {
		if current.Error() == "path escapes from parent" {
			return fmt.Errorf("%w: %v", errPluginPathEscapesRoot, err)
		}
	}
	return err
}

func pluginPathEscapesRoot(err error) bool {
	return errors.Is(err, errPluginPathEscapesRoot)
}
