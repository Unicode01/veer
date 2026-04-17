//go:build linux

package hotrestart

import (
	"os"
	"strings"
)

func ShouldPreserveOnClose(markerPath string) bool {
	if strings.TrimSpace(markerPath) == "" {
		return false
	}
	_, err := os.Stat(markerPath)
	return err == nil
}
