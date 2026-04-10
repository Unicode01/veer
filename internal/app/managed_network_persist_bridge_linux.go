//go:build linux

package app

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

func persistManagedNetworkBridge(item ManagedNetwork) (managedNetworkPersistBridgeResult, error) {
	item = normalizeManagedNetwork(item)
	bridgeName := strings.TrimSpace(item.Bridge)
	if bridgeName == "" {
		return managedNetworkPersistBridgeResult{}, managedNetworkPersistBridgeIssue{Field: "bridge", Message: "bridge name is required"}
	}
	if item.BridgeMode != managedNetworkBridgeModeCreate {
		return managedNetworkPersistBridgeResult{}, managedNetworkPersistBridgeIssue{Field: "bridge_mode", Message: "managed network bridge persistence requires create mode"}
	}

	link, err := netlink.LinkByName(bridgeName)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			return managedNetworkPersistBridgeResult{}, managedNetworkPersistBridgeIssue{Field: "bridge", Message: fmt.Sprintf("bridge %q is unavailable on this host", bridgeName)}
		}
		return managedNetworkPersistBridgeResult{}, fmt.Errorf("load bridge %q: %w", bridgeName, err)
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return managedNetworkPersistBridgeResult{}, managedNetworkPersistBridgeIssue{Field: "bridge", Message: fmt.Sprintf("bridge %q is unavailable on this host", bridgeName)}
	}
	if !strings.EqualFold(strings.TrimSpace(link.Type()), "bridge") {
		return managedNetworkPersistBridgeResult{}, managedNetworkPersistBridgeIssue{Field: "bridge", Message: fmt.Sprintf("bridge %q is not a linux bridge", bridgeName)}
	}

	hw, err := ensureManagedNetworkBridgeHardwareAddr(link)
	if err != nil {
		return managedNetworkPersistBridgeResult{}, err
	}

	content, mode, existed, err := readManagedNetworkInterfacesFile(managedNetworkHostInterfacesConfigPath)
	if err != nil {
		return managedNetworkPersistBridgeResult{}, err
	}
	if managedNetworkInterfacesFileDefinesInterface(content, bridgeName) {
		return managedNetworkPersistBridgeResult{
			Status:         "already_present",
			Bridge:         bridgeName,
			InterfacesPath: managedNetworkHostInterfacesConfigPath,
			Message:        fmt.Sprintf("bridge %q is already defined in host network config", bridgeName),
		}, nil
	}

	for _, sourcedPath := range managedNetworkInterfacesDirectivePaths(managedNetworkHostInterfacesConfigPath, content) {
		sourcedContent, readErr := os.ReadFile(sourcedPath)
		if readErr != nil {
			return managedNetworkPersistBridgeResult{}, fmt.Errorf("read sourced host network config %q: %w", sourcedPath, readErr)
		}
		if managedNetworkInterfacesFileDefinesInterface(string(sourcedContent), bridgeName) {
			return managedNetworkPersistBridgeResult{}, managedNetworkPersistBridgeIssue{
				Field:   "bridge",
				Message: fmt.Sprintf("host network sourced config %q already defines interface %q", sourcedPath, bridgeName),
			}
		}
	}

	updatedContent, _, err := appendManagedNetworkBridgeBlock(content, managedNetworkPersistedBridgeSpec{
		Name:            bridgeName,
		BridgeMTU:       item.BridgeMTU,
		BridgeVLANAware: item.BridgeVLANAware,
		HardwareAddr:    hw,
	})
	if err != nil {
		return managedNetworkPersistBridgeResult{}, err
	}

	backupPath, err := writeManagedNetworkInterfacesFile(managedNetworkHostInterfacesConfigPath, []byte(updatedContent), mode, existed)
	if err != nil {
		return managedNetworkPersistBridgeResult{}, err
	}
	return managedNetworkPersistBridgeResult{
		Status:         "persisted",
		Bridge:         bridgeName,
		InterfacesPath: managedNetworkHostInterfacesConfigPath,
		BackupPath:     backupPath,
		Message:        fmt.Sprintf("bridge %q was written to host network config", bridgeName),
	}, nil
}

func ensureManagedNetworkBridgeHardwareAddr(link netlink.Link) (net.HardwareAddr, error) {
	if link == nil || link.Attrs() == nil {
		return nil, fmt.Errorf("bridge is unavailable")
	}
	if isValidHardwareAddr(link.Attrs().HardwareAddr) {
		return append(net.HardwareAddr(nil), link.Attrs().HardwareAddr...), nil
	}

	hw, err := generateManagedNetworkBridgeHardwareAddr()
	if err != nil {
		return nil, fmt.Errorf("generate hardware address for bridge %q: %w", link.Attrs().Name, err)
	}
	if err := netlink.LinkSetHardwareAddr(link, hw); err != nil {
		return nil, fmt.Errorf("set hardware address for bridge %q: %w", link.Attrs().Name, err)
	}

	refreshed, err := netlink.LinkByName(link.Attrs().Name)
	if err == nil && refreshed != nil && refreshed.Attrs() != nil && isValidHardwareAddr(refreshed.Attrs().HardwareAddr) {
		return append(net.HardwareAddr(nil), refreshed.Attrs().HardwareAddr...), nil
	}
	return append(net.HardwareAddr(nil), hw...), nil
}

func generateManagedNetworkBridgeHardwareAddr() (net.HardwareAddr, error) {
	hw := make(net.HardwareAddr, 6)
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := rand.Read(hw); err != nil {
			return nil, err
		}
		hw[0] &^= 0x01
		hw[0] |= 0x02
		if isValidHardwareAddr(hw) {
			return append(net.HardwareAddr(nil), hw...), nil
		}
	}
	return nil, fmt.Errorf("could not generate a usable ethernet address")
}

func readManagedNetworkInterfacesFile(path string) (string, fs.FileMode, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0o644, false, nil
		}
		return "", 0, false, fmt.Errorf("stat host network config %q: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, false, fmt.Errorf("read host network config %q: %w", path, err)
	}
	return string(data), info.Mode().Perm(), true, nil
}

func writeManagedNetworkInterfacesFile(path string, content []byte, mode fs.FileMode, existed bool) (string, error) {
	if mode == 0 {
		mode = 0o644
	}
	backupPath := ""
	if existed {
		current, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read host network config %q: %w", path, err)
		}
		backupPath = managedNetworkInterfacesBackupPath(path)
		if err := os.WriteFile(backupPath, current, mode); err != nil {
			return "", fmt.Errorf("write host network backup %q: %w", backupPath, err)
		}
	}
	if err := writeManagedNetworkInterfacesFileAtomic(path, content, mode); err != nil {
		return backupPath, err
	}
	return backupPath, nil
}

func managedNetworkInterfacesBackupPath(path string) string {
	return path + ".forward.bak." + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
}

func writeManagedNetworkInterfacesFileAtomic(path string, content []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".forward-*")
	if err != nil {
		return fmt.Errorf("create temp host network config in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temp host network config mode: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp host network config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp host network config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp host network config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace host network config %q: %w", path, err)
	}
	cleanup = false
	return nil
}
