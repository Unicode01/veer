//go:build linux

package app

import (
	"os"
	"strings"
)

func shouldPreserveUserspaceWorkersOnClose() bool {
	markerPath := kernelHotRestartMarkerPath()
	if strings.TrimSpace(markerPath) == "" {
		return false
	}
	_, err := os.Stat(markerPath)
	return err == nil
}
