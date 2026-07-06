package app

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

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
