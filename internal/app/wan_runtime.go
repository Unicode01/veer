package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	wanProfileTypeExisting = "existing"
	wanProfileTypeStatic   = "static"
	wanProfileTypeDHCP     = "dhcp"
	wanProfileTypePPPoE    = "pppoe"

	wanDNSModeAuto   = "auto"
	wanDNSModeManual = "manual"
	wanDNSModeIgnore = "ignore"

	wanPlatformOpenWrt      = "openwrt"
	wanPlatformGenericLinux = "linux"
	wanPlatformUnsupported  = "unsupported"
)

const wanCommandTimeout = 8 * time.Second

var (
	execLookPathForWANRuntime       = exec.LookPath
	execCommandContextForWANRuntime = exec.CommandContext
)

type wanRuntimeCommandResult struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

func normalizeWANProfile(item WANProfile) WANProfile {
	item.Name = strings.TrimSpace(item.Name)
	item.Type = normalizeWANProfileType(item.Type)
	item.ParentInterface = strings.TrimSpace(item.ParentInterface)
	item.RuntimeInterface = strings.TrimSpace(item.RuntimeInterface)
	item.IPv4CIDR = strings.TrimSpace(item.IPv4CIDR)
	item.IPv4Gateway = strings.TrimSpace(item.IPv4Gateway)
	item.Username = strings.TrimSpace(item.Username)
	item.DNSMode = normalizeWANDNSMode(item.DNSMode)
	item.DNSServers = strings.TrimSpace(item.DNSServers)
	item.Remark = strings.TrimSpace(item.Remark)
	if item.MTU < 0 {
		item.MTU = 0
	}
	if item.MRU < 0 {
		item.MRU = 0
	}
	if item.Metric < 0 {
		item.Metric = 0
	}
	return item
}

func normalizeWANProfileType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", wanProfileTypeExisting:
		return wanProfileTypeExisting
	case wanProfileTypeStatic:
		return wanProfileTypeStatic
	case wanProfileTypeDHCP:
		return wanProfileTypeDHCP
	case wanProfileTypePPPoE:
		return wanProfileTypePPPoE
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func isValidWANProfileType(value string) bool {
	switch normalizeWANProfileType(value) {
	case wanProfileTypeExisting, wanProfileTypeStatic, wanProfileTypeDHCP, wanProfileTypePPPoE:
		return true
	default:
		return false
	}
}

func normalizeWANDNSMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", wanDNSModeAuto:
		return wanDNSModeAuto
	case wanDNSModeManual:
		return wanDNSModeManual
	case wanDNSModeIgnore:
		return wanDNSModeIgnore
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func isValidWANDNSMode(value string) bool {
	switch normalizeWANDNSMode(value) {
	case wanDNSModeAuto, wanDNSModeManual, wanDNSModeIgnore:
		return true
	default:
		return false
	}
}

func maskWANProfilePassword(item WANProfile) WANProfile {
	item.PasswordSet = strings.TrimSpace(item.Password) != ""
	item.Password = ""
	return item
}

func maskWANProfileStatuses(items []WANProfileStatus) []WANProfileStatus {
	for i := range items {
		items[i].WANProfile = maskWANProfilePassword(items[i].WANProfile)
	}
	return items
}

func validateWANProfile(item WANProfile, scope string, requireID bool) (WANProfile, []ruleValidationIssue) {
	item = normalizeWANProfile(item)
	if requireID && item.ID <= 0 {
		return item, singleValidationIssue(scope, item.ID, "id", "is required")
	}
	if !requireID && item.ID != 0 {
		return item, singleValidationIssue(scope, 0, "id", "must be omitted when creating a wan profile")
	}
	if item.Name == "" {
		return item, singleValidationIssue(scope, item.ID, "name", "is required")
	}
	if !isValidWANProfileType(item.Type) {
		return item, singleValidationIssue(scope, item.ID, "type", "must be one of existing, static, dhcp, pppoe")
	}
	if !isValidWANDNSMode(item.DNSMode) {
		return item, singleValidationIssue(scope, item.ID, "dns_mode", "must be one of auto, manual, ignore")
	}
	if item.MTU < 0 || item.MTU > 65535 {
		return item, singleValidationIssue(scope, item.ID, "mtu", "mtu must be between 0 and 65535")
	}
	if item.MRU < 0 || item.MRU > 65535 {
		return item, singleValidationIssue(scope, item.ID, "mru", "mru must be between 0 and 65535")
	}
	if item.Metric < 0 || item.Metric > 2147483647 {
		return item, singleValidationIssue(scope, item.ID, "metric", "metric must be between 0 and 2147483647")
	}
	if item.Type != wanProfileTypeExisting && strings.TrimSpace(item.ParentInterface) == "" {
		return item, singleValidationIssue(scope, item.ID, "parent_interface", "is required")
	}
	if item.Type == wanProfileTypeExisting && strings.TrimSpace(item.RuntimeInterface) == "" {
		return item, singleValidationIssue(scope, item.ID, "runtime_interface", "is required")
	}
	if item.Type == wanProfileTypeStatic {
		if strings.TrimSpace(item.IPv4CIDR) == "" {
			return item, singleValidationIssue(scope, item.ID, "ipv4_cidr", "is required")
		}
		if _, _, err := net.ParseCIDR(item.IPv4CIDR); err != nil {
			return item, singleValidationIssue(scope, item.ID, "ipv4_cidr", "must be a valid IPv4 CIDR")
		}
		ip, network, _ := net.ParseCIDR(item.IPv4CIDR)
		prefixLen, bits := network.Mask.Size()
		if ip == nil || ip.To4() == nil || network == nil || bits != 32 {
			return item, singleValidationIssue(scope, item.ID, "ipv4_cidr", "must be a valid IPv4 CIDR")
		}
		item.IPv4CIDR = ip.String() + "/" + strconv.Itoa(prefixLen)
		if strings.TrimSpace(item.IPv4Gateway) != "" {
			gateway := net.ParseIP(item.IPv4Gateway)
			if gateway == nil || gateway.To4() == nil {
				return item, singleValidationIssue(scope, item.ID, "ipv4_gateway", "must be a valid IPv4 address")
			}
			item.IPv4Gateway = gateway.String()
		}
	} else {
		item.IPv4CIDR = ""
		item.IPv4Gateway = ""
	}
	if item.Type == wanProfileTypePPPoE && strings.TrimSpace(item.Username) == "" {
		return item, singleValidationIssue(scope, item.ID, "username", "is required")
	}
	if item.DNSMode == wanDNSModeManual && strings.TrimSpace(item.DNSServers) == "" {
		return item, singleValidationIssue(scope, item.ID, "dns_servers", "is required when dns_mode is manual")
	}
	if strings.TrimSpace(item.DNSServers) != "" {
		for _, entry := range splitWANCSV(item.DNSServers) {
			if net.ParseIP(entry) == nil {
				return item, singleValidationIssue(scope, item.ID, "dns_servers", "must contain valid IP addresses")
			}
		}
		item.DNSServers = strings.Join(splitWANCSV(item.DNSServers), ",")
	}
	return item, nil
}

func splitWANCSV(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		text := strings.TrimSpace(field)
		if text == "" {
			continue
		}
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	return out
}

func prepareWANProfileCreate(raw WANProfile) (WANProfile, []ruleValidationIssue) {
	item, issues := validateWANProfile(raw, "create", false)
	if len(issues) > 0 {
		return item, issues
	}
	item.Enabled = true
	return item, nil
}

func prepareWANProfileUpdate(db sqlRuleStore, raw WANProfile) (WANProfile, []ruleValidationIssue, error) {
	item, issues := validateWANProfile(raw, "update", true)
	if len(issues) > 0 {
		return item, issues, nil
	}
	current, err := dbGetWANProfile(db, item.ID)
	if err != nil {
		return item, singleValidationIssue("update", item.ID, "id", "wan profile not found"), err
	}
	if strings.TrimSpace(item.Password) == "" {
		item.Password = current.Password
	}
	item.Enabled = current.Enabled
	return item, nil, nil
}

func prepareWANProfileToggle(db sqlRuleStore, id int64) (WANProfile, []ruleValidationIssue, error) {
	item, err := dbGetWANProfile(db, id)
	if err != nil {
		return WANProfile{}, singleValidationIssue("toggle", id, "id", "wan profile not found"), err
	}
	item.Enabled = !item.Enabled
	return *item, nil, nil
}

type wanProfileRuntimeSnapshot struct {
	Platform    string
	Supported   bool
	Reason      string
	byID        map[int64]WANProfileStatus
	byInterface map[string]HostNetworkInterface
}

func newWANProfileRuntimeSnapshot(profiles []WANProfile) wanProfileRuntimeSnapshot {
	platform, supported, reason := detectWANRuntimePlatform()
	snapshot := wanProfileRuntimeSnapshot{
		Platform:    platform,
		Supported:   supported,
		Reason:      reason,
		byID:        make(map[int64]WANProfileStatus, len(profiles)),
		byInterface: make(map[string]HostNetworkInterface),
	}

	ifaces, err := loadCurrentHostNetworkInterfaces()
	if err == nil {
		for _, iface := range ifaces {
			name := strings.TrimSpace(iface.Name)
			if name != "" {
				snapshot.byInterface[name] = iface
			}
		}
	}

	for _, profile := range profiles {
		status := buildWANProfileStatus(profile, snapshot, err)
		snapshot.byID[profile.ID] = status
	}
	return snapshot
}

func detectWANRuntimePlatform() (string, bool, string) {
	if runtime.GOOS != "linux" {
		return wanPlatformUnsupported, false, "wan management requires linux"
	}
	if commandExists("uci") && commandExists("ubus") {
		return wanPlatformOpenWrt, true, ""
	}
	if commandExists("ip") {
		return wanPlatformGenericLinux, true, ""
	}
	return wanPlatformUnsupported, false, "required system tools are missing"
}

func commandExists(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	_, err := execLookPathForWANRuntime(name)
	return err == nil
}

func buildWANProfileStatuses(profiles []WANProfile) []WANProfileStatus {
	if len(profiles) == 0 {
		return []WANProfileStatus{}
	}
	snapshot := newWANProfileRuntimeSnapshot(profiles)
	items := make([]WANProfileStatus, 0, len(profiles))
	for _, profile := range profiles {
		if status, ok := snapshot.byID[profile.ID]; ok {
			items = append(items, status)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return maskWANProfileStatuses(items)
}

func buildWANProfileStatus(profile WANProfile, snapshot wanProfileRuntimeSnapshot, inventoryErr error) WANProfileStatus {
	profile = normalizeWANProfile(profile)
	status := WANProfileStatus{
		WANProfile: profile,
		Platform:   snapshot.Platform,
		Supported:  snapshot.Supported,
	}
	if !snapshot.Supported {
		status.Status = "unsupported"
		status.SupportedReason = snapshot.Reason
		return status
	}
	if !profile.Enabled {
		status.Status = "disabled"
		return status
	}
	if inventoryErr != nil {
		status.Status = "unknown"
		status.LastError = inventoryErr.Error()
		return status
	}
	status.EffectiveInterface = resolveWANProfileRuntimeInterface(profile)
	if status.EffectiveInterface == "" {
		status.Status = "error"
		status.LastError = "runtime interface is unresolved"
		return status
	}
	iface, ok := snapshot.byInterface[status.EffectiveInterface]
	if !ok {
		status.Status = "error"
		status.LastError = fmt.Sprintf("runtime interface %q not found", status.EffectiveInterface)
		return status
	}

	for _, addr := range iface.Addresses {
		switch addr.Family {
		case "ipv4":
			status.IPv4Addresses = append(status.IPv4Addresses, addr.CIDR)
		case "ipv6":
			status.IPv6Addresses = append(status.IPv6Addresses, addr.CIDR)
		}
	}
	status.DefaultIPv4Route = iface.DefaultIPv4Route
	status.DefaultIPv6Route = iface.DefaultIPv6Route
	if len(status.IPv4Addresses) == 0 && len(status.IPv6Addresses) == 0 {
		status.Status = "up"
		return status
	}
	status.Status = "running"
	return status
}

func resolveWANProfileRuntimeInterface(profile WANProfile) string {
	profile = normalizeWANProfile(profile)
	if profile.RuntimeInterface != "" {
		return profile.RuntimeInterface
	}
	switch profile.Type {
	case wanProfileTypeExisting:
		return strings.TrimSpace(profile.RuntimeInterface)
	case wanProfileTypePPPoE:
		if strings.TrimSpace(profile.Name) != "" {
			return "pppoe-" + sanitizeOpenWrtInterfaceName(profile.Name)
		}
	case wanProfileTypeDHCP, wanProfileTypeStatic:
		return strings.TrimSpace(profile.ParentInterface)
	}
	return strings.TrimSpace(profile.ParentInterface)
}

func resolveWANProfileIDToInterface(db sqlRuleStore, id int64) (string, error) {
	if id <= 0 {
		return "", nil
	}
	profile, err := dbGetWANProfile(db, id)
	if err != nil {
		return "", err
	}
	if !profile.Enabled {
		return "", fmt.Errorf("wan profile #%d is disabled", id)
	}
	iface := resolveWANProfileRuntimeInterface(*profile)
	if strings.TrimSpace(iface) == "" {
		return "", fmt.Errorf("wan profile #%d runtime interface is unresolved", id)
	}
	return iface, nil
}

func resolveWANProfilesForEgressNATs(db sqlRuleStore, items []EgressNAT) ([]EgressNAT, map[int64]string) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]EgressNAT, len(items))
	copy(out, items)
	warnings := make(map[int64]string)
	cache := make(map[int64]string)
	for i := range out {
		id := out[i].WANProfileID
		if id <= 0 {
			continue
		}
		iface, ok := cache[id]
		if !ok {
			resolved, err := resolveWANProfileIDToInterface(db, id)
			if err != nil {
				warnings[out[i].ID] = err.Error()
				continue
			}
			iface = resolved
			cache[id] = iface
		}
		out[i].OutInterface = iface
	}
	return out, warnings
}

func resolveWANProfilesForManagedNetworks(db sqlRuleStore, items []ManagedNetwork) ([]ManagedNetwork, map[int64]string) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]ManagedNetwork, len(items))
	copy(out, items)
	warnings := make(map[int64]string)
	cache := make(map[int64]string)
	for i := range out {
		id := out[i].WANProfileID
		if id <= 0 {
			continue
		}
		iface, ok := cache[id]
		if !ok {
			resolved, err := resolveWANProfileIDToInterface(db, id)
			if err != nil {
				warnings[out[i].ID] = err.Error()
				continue
			}
			iface = resolved
			cache[id] = iface
		}
		out[i].UplinkInterface = iface
	}
	return out, warnings
}

func wanProfileRuntimeWarningText(warnings map[int64]string) string {
	if len(warnings) == 0 {
		return ""
	}
	ids := make([]int64, 0, len(warnings))
	for id := range warnings {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("#%d: %s", id, warnings[id]))
	}
	return strings.Join(parts, "; ")
}

func applyWANProfileConfig(profile WANProfile) (wanRuntimeCommandResult, error) {
	profile = normalizeWANProfile(profile)
	platform, supported, reason := detectWANRuntimePlatform()
	if !supported {
		return wanRuntimeCommandResult{Error: reason}, fmt.Errorf("%s", reason)
	}
	switch platform {
	case wanPlatformOpenWrt:
		return applyWANProfileOpenWrt(profile)
	case wanPlatformGenericLinux:
		return applyWANProfileLinux(profile)
	default:
		return wanRuntimeCommandResult{Error: "unsupported platform"}, fmt.Errorf("unsupported platform")
	}
}

func reconnectWANProfile(profile WANProfile) (wanRuntimeCommandResult, error) {
	profile = normalizeWANProfile(profile)
	platform, supported, reason := detectWANRuntimePlatform()
	if !supported {
		return wanRuntimeCommandResult{Error: reason}, fmt.Errorf("%s", reason)
	}
	name := wanRuntimeConfigName(profile)
	switch platform {
	case wanPlatformOpenWrt:
		down, _ := runWANCommand("ifdown", name)
		up, err := runWANCommand("ifup", name)
		out := strings.TrimSpace(strings.Join([]string{down.Output, up.Output}, "\n"))
		if err != nil {
			return wanRuntimeCommandResult{Output: out, Error: up.Error}, err
		}
		return wanRuntimeCommandResult{Output: out}, nil
	case wanPlatformGenericLinux:
		iface := resolveWANProfileRuntimeInterface(profile)
		if iface == "" {
			return wanRuntimeCommandResult{Error: "runtime interface is unresolved"}, fmt.Errorf("runtime interface is unresolved")
		}
		down, _ := runWANCommand("ip", "link", "set", "dev", iface, "down")
		up, err := runWANCommand("ip", "link", "set", "dev", iface, "up")
		out := strings.TrimSpace(strings.Join([]string{down.Output, up.Output}, "\n"))
		if err != nil {
			return wanRuntimeCommandResult{Output: out, Error: up.Error}, err
		}
		return wanRuntimeCommandResult{Output: out}, nil
	default:
		return wanRuntimeCommandResult{Error: "unsupported platform"}, fmt.Errorf("unsupported platform")
	}
}

func applyWANProfileOpenWrt(profile WANProfile) (wanRuntimeCommandResult, error) {
	name := wanRuntimeConfigName(profile)
	if name == "" {
		return wanRuntimeCommandResult{Error: "wan profile name is required"}, fmt.Errorf("wan profile name is required")
	}

	commands := [][]string{
		{"uci", "set", "network." + name + "=interface"},
		optionalUCIDeleteCommand(name, "device"),
		optionalUCIDeleteCommand(name, "ipaddr"),
		optionalUCIDeleteCommand(name, "netmask"),
		optionalUCIDeleteCommand(name, "gateway"),
		optionalUCIDeleteCommand(name, "username"),
		optionalUCIDeleteCommand(name, "password"),
		optionalUCIDeleteCommand(name, "mtu"),
		optionalUCIDeleteCommand(name, "mru"),
		optionalUCIDeleteCommand(name, "metric"),
		optionalUCIDeleteCommand(name, "dns"),
	}
	switch profile.Type {
	case wanProfileTypeExisting:
		commands = append(commands,
			[]string{"uci", "set", "network." + name + ".proto=none"},
			[]string{"uci", "set", "network." + name + ".device=" + profile.RuntimeInterface},
		)
	case wanProfileTypeStatic:
		ipaddr, netmask, err := staticWANIPv4Parts(profile.IPv4CIDR)
		if err != nil {
			return wanRuntimeCommandResult{Error: err.Error()}, err
		}
		commands = append(commands,
			[]string{"uci", "set", "network." + name + ".proto=static"},
			[]string{"uci", "set", "network." + name + ".device=" + profile.ParentInterface},
			[]string{"uci", "set", "network." + name + ".ipaddr=" + ipaddr},
			[]string{"uci", "set", "network." + name + ".netmask=" + netmask},
		)
		if profile.IPv4Gateway != "" {
			commands = append(commands, []string{"uci", "set", "network." + name + ".gateway=" + profile.IPv4Gateway})
		}
	case wanProfileTypeDHCP:
		commands = append(commands,
			[]string{"uci", "set", "network." + name + ".proto=dhcp"},
			[]string{"uci", "set", "network." + name + ".device=" + profile.ParentInterface},
		)
	case wanProfileTypePPPoE:
		commands = append(commands,
			[]string{"uci", "set", "network." + name + ".proto=pppoe"},
			[]string{"uci", "set", "network." + name + ".device=" + profile.ParentInterface},
			[]string{"uci", "set", "network." + name + ".username=" + profile.Username},
			[]string{"uci", "set", "network." + name + ".password=" + profile.Password},
		)
	default:
		return wanRuntimeCommandResult{Error: "unsupported wan type"}, fmt.Errorf("unsupported wan type")
	}
	if profile.MTU > 0 {
		commands = append(commands, []string{"uci", "set", "network." + name + ".mtu=" + strconv.Itoa(profile.MTU)})
	}
	if profile.MRU > 0 && profile.Type == wanProfileTypePPPoE {
		commands = append(commands, []string{"uci", "set", "network." + name + ".mru=" + strconv.Itoa(profile.MRU)})
	}
	if profile.DefaultRoute {
		commands = append(commands, []string{"uci", "set", "network." + name + ".defaultroute=1"})
	} else {
		commands = append(commands, []string{"uci", "set", "network." + name + ".defaultroute=0"})
	}
	if profile.Metric > 0 {
		commands = append(commands, []string{"uci", "set", "network." + name + ".metric=" + strconv.Itoa(profile.Metric)})
	}
	switch profile.DNSMode {
	case wanDNSModeIgnore:
		commands = append(commands, []string{"uci", "set", "network." + name + ".peerdns=0"})
	case wanDNSModeManual:
		commands = append(commands, []string{"uci", "set", "network." + name + ".peerdns=0"})
		commands = append(commands, optionalUCIDeleteCommand(name, "dns"))
		for _, dns := range splitWANCSV(profile.DNSServers) {
			commands = append(commands, []string{"uci", "add_list", "network." + name + ".dns=" + dns})
		}
	default:
		commands = append(commands, []string{"uci", "set", "network." + name + ".peerdns=1"})
	}
	commands = append(commands, []string{"uci", "commit", "network"})
	if profile.Enabled {
		commands = append(commands, []string{"ifup", name})
	} else {
		commands = append(commands, []string{"ifdown", name})
	}

	return runWANCommands(commands)
}

func applyWANProfileLinux(profile WANProfile) (wanRuntimeCommandResult, error) {
	switch profile.Type {
	case wanProfileTypeExisting:
		return wanRuntimeCommandResult{}, nil
	case wanProfileTypeDHCP:
		if commandExists("dhclient") {
			return runWANCommand("dhclient", "-v", profile.ParentInterface)
		}
		return wanRuntimeCommandResult{Error: "dhclient is missing"}, fmt.Errorf("dhclient is missing")
	case wanProfileTypePPPoE:
		if commandExists("pon") && strings.TrimSpace(profile.Name) != "" {
			return runWANCommand("pon", sanitizeOpenWrtInterfaceName(profile.Name))
		}
		return wanRuntimeCommandResult{Error: "generic linux PPPoE apply requires pon/pppd profile setup"}, fmt.Errorf("generic linux PPPoE apply requires pon/pppd profile setup")
	case wanProfileTypeStatic:
		return wanRuntimeCommandResult{Error: "static wan apply is not implemented for generic linux"}, fmt.Errorf("static wan apply is not implemented for generic linux")
	default:
		return wanRuntimeCommandResult{Error: "unsupported wan type"}, fmt.Errorf("unsupported wan type")
	}
}

func optionalUCIDeleteCommand(configName string, option string) []string {
	return []string{"uci", "-q", "delete", "network." + configName + "." + option}
}

func isOptionalUCIDeleteCommand(command []string) bool {
	return len(command) >= 4 && command[0] == "uci" && command[1] == "-q" && command[2] == "delete"
}

func runWANCommands(commands [][]string) (wanRuntimeCommandResult, error) {
	var outputs []string
	for _, command := range commands {
		if len(command) == 0 {
			continue
		}
		result, err := runWANCommand(command[0], command[1:]...)
		if strings.TrimSpace(result.Output) != "" {
			outputs = append(outputs, result.Output)
		}
		if err != nil {
			if isOptionalUCIDeleteCommand(command) {
				continue
			}
			result.Output = strings.TrimSpace(strings.Join(outputs, "\n"))
			return result, err
		}
	}
	return wanRuntimeCommandResult{Output: strings.TrimSpace(strings.Join(outputs, "\n"))}, nil
}

func staticWANIPv4Parts(cidr string) (string, string, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ip == nil || ip.To4() == nil || network == nil {
		return "", "", fmt.Errorf("static wan ipv4_cidr is invalid")
	}
	maskIP := net.IP(network.Mask)
	if len(maskIP) != net.IPv4len {
		return "", "", fmt.Errorf("static wan ipv4_cidr is invalid")
	}
	return ip.String(), maskIP.String(), nil
}

func runWANCommand(name string, args ...string) (wanRuntimeCommandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wanCommandTimeout)
	defer cancel()
	cmd := execCommandContextForWANRuntime(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return wanRuntimeCommandResult{Output: text, Error: err.Error()}, err
	}
	return wanRuntimeCommandResult{Output: text}, nil
}

func wanRuntimeConfigName(profile WANProfile) string {
	name := sanitizeOpenWrtInterfaceName(profile.Name)
	if name != "" {
		return name
	}
	if profile.ID > 0 {
		return "wan" + strconv.FormatInt(profile.ID, 10)
	}
	return ""
}

func sanitizeOpenWrtInterfaceName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '_' || r == '-':
			builder.WriteRune('_')
		default:
			builder.WriteRune('_')
		}
	}
	return strings.Trim(builder.String(), "_")
}

func wanCommandJSON(result wanRuntimeCommandResult) map[string]string {
	out := map[string]string{"status": "ok"}
	if strings.TrimSpace(result.Output) != "" {
		out["output"] = strings.TrimSpace(result.Output)
	}
	if strings.TrimSpace(result.Error) != "" {
		out["error"] = strings.TrimSpace(result.Error)
	}
	return out
}

func parseWANStatusJSON(value string) map[string]interface{} {
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return nil
	}
	return out
}

func isWANProfileNotFound(err error) bool {
	return err != nil && (errors.Is(err, errWANProfileNotFound) || strings.Contains(err.Error(), "wan profile not found"))
}

var errWANProfileNotFound = errors.New("wan profile not found")
