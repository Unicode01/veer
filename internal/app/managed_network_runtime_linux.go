//go:build linux

package app

import (
	"os"
	"strings"

	"github.com/Unicode01/veer/internal/hotrestart"
	"github.com/Unicode01/veer/internal/managednet"
)

func newManagedNetworkRuntime() managedNetworkRuntime {
	return newManagedIPv4NetworkRuntime(managednet.NewLinuxNetOps())
}

func managedNetworkPreserveStateOnClose() bool {
	markerPath := kernelHotRestartMarkerPath()
	if strings.TrimSpace(markerPath) == "" {
		return false
	}
	_, err := os.Stat(markerPath)
	return err == nil
}

func userspaceWorkerPreserveOnClose() bool {
	return hotrestart.ShouldPreserveOnClose(kernelHotRestartMarkerPath())
}
