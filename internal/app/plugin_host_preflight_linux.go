//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	pluginRawL2ProbeOnce   sync.Once
	pluginRawL2ProbeStatus PluginHostFeatureStatus
	pluginHostLookPath     = exec.LookPath
)

func pluginRawL2FeatureStatus() PluginHostFeatureStatus {
	pluginRawL2ProbeOnce.Do(func() {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			pluginRawL2ProbeStatus = PluginHostFeatureStatus{Reason: "raw L2 socket unavailable: " + err.Error()}
			return
		}
		_ = unix.Close(fd)
		pluginRawL2ProbeStatus = PluginHostFeatureStatus{Available: true}
	})
	return pluginRawL2ProbeStatus
}

func pluginNetOffloadFeatureStatus() PluginHostFeatureStatus {
	if _, err := pluginHostLookPath("ethtool"); err != nil {
		return PluginHostFeatureStatus{Reason: "network offload control unavailable: ethtool not found"}
	}
	return PluginHostFeatureStatus{Available: true}
}

func pluginNetworkNamespaceFeatureStatus() PluginHostFeatureStatus {
	if err := pluginRequireEffectiveCapabilities(unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN); err != nil {
		return PluginHostFeatureStatus{Reason: "network namespace provider unavailable: " + err.Error()}
	}
	fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return PluginHostFeatureStatus{Reason: "network namespace provider unavailable: " + err.Error()}
	}
	_ = unix.Close(fd)
	path := pluginControlNamedNetNSDir
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() {
			return PluginHostFeatureStatus{Reason: "network namespace provider unavailable: /run/netns is not a directory"}
		}
	} else if errors.Is(err, os.ErrNotExist) {
		path = "/run"
	} else {
		return PluginHostFeatureStatus{Reason: "network namespace provider unavailable: " + err.Error()}
	}
	if err := unix.Access(path, unix.W_OK|unix.X_OK); err != nil {
		return PluginHostFeatureStatus{Reason: "network namespace provider unavailable: " + err.Error()}
	}
	return PluginHostFeatureStatus{Available: true}
}

func pluginTunTapFeatureStatus() PluginHostFeatureStatus {
	if err := pluginRequireEffectiveCapabilities(unix.CAP_NET_ADMIN); err != nil {
		return PluginHostFeatureStatus{Reason: "TUN/TAP provider unavailable: " + err.Error()}
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return PluginHostFeatureStatus{Reason: "TUN/TAP provider unavailable: " + err.Error()}
	}
	_ = unix.Close(fd)
	return PluginHostFeatureStatus{Available: true}
}

func pluginRequireEffectiveCapabilities(capabilities ...int) error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	for _, capability := range capabilities {
		word := capability / 32
		bit := uint(capability % 32)
		if word < 0 || word >= len(data) || data[word].Effective&(uint32(1)<<bit) == 0 {
			return fmt.Errorf("effective capability %d is missing", capability)
		}
	}
	return nil
}
