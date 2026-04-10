package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const managedNetworkHostInterfacesConfigPath = "/etc/network/interfaces"

var persistManagedNetworkBridgeForTests func(ManagedNetwork) (managedNetworkPersistBridgeResult, error)

type managedNetworkPersistBridgeResult struct {
	Status         string `json:"status"`
	Bridge         string `json:"bridge"`
	InterfacesPath string `json:"interfaces_path,omitempty"`
	BackupPath     string `json:"backup_path,omitempty"`
	Message        string `json:"message,omitempty"`
}

type managedNetworkPersistBridgeIssue struct {
	Field   string
	Message string
}

func (e managedNetworkPersistBridgeIssue) Error() string {
	return strings.TrimSpace(e.Message)
}

type managedNetworkPersistedBridgeSpec struct {
	Name            string
	BridgeMTU       int
	BridgeVLANAware bool
	HardwareAddr    net.HardwareAddr
}

func persistManagedNetworkBridgeWithHook(item ManagedNetwork) (managedNetworkPersistBridgeResult, error) {
	if persistManagedNetworkBridgeForTests != nil {
		return persistManagedNetworkBridgeForTests(item)
	}
	return persistManagedNetworkBridge(item)
}

func buildManagedNetworkPersistedBridgeBlock(spec managedNetworkPersistedBridgeSpec) (string, error) {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		return "", managedNetworkPersistBridgeIssue{Field: "bridge", Message: "bridge name is required"}
	}
	if !managedNetworkPersistBridgeHasHardwareAddr(spec.HardwareAddr) {
		return "", managedNetworkPersistBridgeIssue{Field: "bridge", Message: fmt.Sprintf("bridge %q has no usable ethernet address", name)}
	}

	lines := []string{
		fmt.Sprintf("# BEGIN forward managed bridge %s", name),
		fmt.Sprintf("auto %s", name),
		fmt.Sprintf("iface %s inet manual", name),
		"\tbridge-ports none",
		"\tbridge-stp off",
		"\tbridge-fd 0",
		fmt.Sprintf("\thwaddress ether %s", strings.ToLower(spec.HardwareAddr.String())),
	}
	if spec.BridgeMTU > 0 {
		lines = append(lines, fmt.Sprintf("\tmtu %d", spec.BridgeMTU))
	}
	if spec.BridgeVLANAware {
		lines = append(lines, "\tbridge-vlan-aware yes")
	}
	lines = append(lines, fmt.Sprintf("# END forward managed bridge %s", name))
	return strings.Join(lines, "\n") + "\n", nil
}

func managedNetworkPersistBridgeHasHardwareAddr(hw net.HardwareAddr) bool {
	if len(hw) < 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if hw[i] != 0 {
			return true
		}
	}
	return false
}

func managedNetworkInterfacesFileDefinesInterface(content string, interfaceName string) bool {
	target := strings.TrimSpace(interfaceName)
	if target == "" {
		return false
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 && fields[0] == "iface" && fields[1] == target {
			return true
		}
	}
	return false
}

func managedNetworkInterfacesDirectivePaths(basePath string, content string) []string {
	baseDir := filepath.Dir(basePath)
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "source":
			for _, pattern := range fields[1:] {
				p := pattern
				if !filepath.IsAbs(p) {
					p = filepath.Join(baseDir, p)
				}
				matches, err := filepath.Glob(p)
				if err != nil {
					continue
				}
				sort.Strings(matches)
				for _, match := range matches {
					if info, err := os.Stat(match); err == nil && !info.IsDir() {
						if _, ok := seen[match]; ok {
							continue
						}
						seen[match] = struct{}{}
						out = append(out, match)
					}
				}
			}
		case "source-directory":
			for _, dirText := range fields[1:] {
				dir := dirText
				if !filepath.IsAbs(dir) {
					dir = filepath.Join(baseDir, dir)
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				names := make([]string, 0, len(entries))
				for _, entry := range entries {
					if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
						continue
					}
					names = append(names, entry.Name())
				}
				sort.Strings(names)
				for _, name := range names {
					path := filepath.Join(dir, name)
					if _, ok := seen[path]; ok {
						continue
					}
					seen[path] = struct{}{}
					out = append(out, path)
				}
			}
		}
	}
	return out
}

func appendManagedNetworkBridgeBlock(content string, spec managedNetworkPersistedBridgeSpec) (string, bool, error) {
	block, err := buildManagedNetworkPersistedBridgeBlock(spec)
	if err != nil {
		return "", false, err
	}
	if managedNetworkInterfacesFileDefinesInterface(content, spec.Name) {
		return content, true, nil
	}

	trimmed := strings.TrimRight(content, "\n")
	if trimmed == "" {
		return block, false, nil
	}
	return trimmed + "\n\n" + block, false, nil
}
