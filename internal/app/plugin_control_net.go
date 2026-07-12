package app

import (
	"fmt"
	"net"
	"strings"

	"github.com/dop251/goja"
)

const linuxInterfaceNameMaxBytes = 15

type pluginControlNetAdmin interface {
	LinkGet(name string) (pluginControlNetLinkInfo, error)
	LinkList() ([]pluginControlNetLinkInfo, error)
	LinkEnsureBridge(req pluginControlNetBridgeRequest) (pluginControlNetLinkInfo, error)
	LinkEnsureVeth(req pluginControlNetVethRequest) (pluginControlNetVethResult, error)
	LinkEnsureDummy(req pluginControlNetDummyRequest) (pluginControlNetDummyResult, error)
	LinkEnsureMacvlan(req pluginControlNetMacvlanRequest) (pluginControlNetMacvlanResult, error)
	LinkDelete(name string) error
	LinkSetMaster(req pluginControlNetMasterRequest) (pluginControlNetLinkInfo, error)
	LinkClearMaster(name string) (pluginControlNetLinkInfo, error)
	LinkSetUp(name string, up bool) error
	LinkSetMTU(name string, mtu int) error
	LinkSetARP(name string, enabled bool) (pluginControlNetLinkInfo, error)
	LinkSetPromiscuous(name string, enabled bool) (pluginControlNetLinkInfo, error)
	LinkGetOffloads(name string) (map[string]bool, error)
	LinkSetOffloads(req pluginControlNetOffloadRequest) error
	LinkSetGSO(req pluginControlNetGSORequest) (pluginControlNetLinkInfo, error)
	AddrReplace(req pluginControlNetAddrRequest) error
	AddrDelete(req pluginControlNetAddrRequest) error
	RouteReplace(req pluginControlNetRouteRequest) error
	RouteDelete(req pluginControlNetRouteRequest) error
}

type pluginControlNetLinkInfo struct {
	Name          string
	IfIndex       int
	Kind          string
	Parent        string
	MTU           int
	MAC           string
	Up            bool
	ARP           bool
	OperState     string
	Addresses     []string
	PeerName      string
	PeerIfIndex   int
	MasterName    string
	MasterIfIndex int
	Promiscuous   bool
	GSOMaxSize    int
	GSOMaxSegs    int
	Statistics    *pluginControlNetLinkStatistics
}

type pluginControlNetLinkStatistics struct {
	RXPackets uint64
	TXPackets uint64
	RXBytes   uint64
	TXBytes   uint64
	RXErrors  uint64
	TXErrors  uint64
	RXDropped uint64
	TXDropped uint64
}

type pluginControlNetVethRequest struct {
	Host string
	Peer string
	MTU  int
	Up   bool
}

type pluginControlNetVethResult struct {
	Host    pluginControlNetLinkInfo
	Peer    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetDummyRequest struct {
	Name string
	MTU  int
	Up   bool
}

type pluginControlNetDummyResult struct {
	Link    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetMacvlanRequest struct {
	Name   string
	Parent string
	Mode   string
	MAC    string
	MTU    int
	Up     bool
}

type pluginControlNetMacvlanResult struct {
	Link    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetBridgeRequest struct {
	Name string
	MTU  int
	Up   bool
}

type pluginControlNetMasterRequest struct {
	Link   string
	Master string
	Up     bool
}

type pluginControlNetAddrRequest struct {
	Interface string
	CIDR      string
}

type pluginControlNetRouteRequest struct {
	Dst     string
	Gateway string
	Dev     string
	Src     string
	Table   int
	Metric  int
	Scope   int
}

type pluginControlNetOffloadRequest struct {
	Interface string
	Features  map[string]bool
}

type pluginControlNetGSORequest struct {
	Interface string
	MaxSize   int
	MaxSegs   int
}

func (h *pluginControlHost) netAdminOrThrow(operation string) pluginControlNetAdmin {
	h.requirePermission("net.admin")
	if h.netAdmin == nil {
		h.throwf("%s: net.admin controller is unavailable", operation)
	}
	return h.netAdmin
}

func (h *pluginControlHost) requireNetAccess(operation string, interfaceName string, api string) {
	if !pluginControlHasNetAccess(h.plugin, operation, interfaceName) {
		h.throwf("%s: net_access operation %s on interface %s is not declared", api, operation, interfaceName)
	}
}

func (h *pluginControlHost) requireAnyNetAccess(operation string, api string) {
	if !pluginControlHasAnyNetAccess(h.plugin, operation) {
		h.throwf("%s: net_access operation %s is not declared", api, operation)
	}
}

func (h *pluginControlHost) netLinkGet(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.get")
	name := h.requiredNetStringArg(call, 0, "name")
	h.requireNetAccess("link.read", name, "net.link.get")
	info, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.get: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkList(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.list")
	h.requireAnyNetAccess("link.read", "net.link.list")
	infos, err := admin.LinkList()
	if err != nil {
		h.throwf("net.link.list: %v", err)
	}
	out := make([]map[string]any, 0, len(infos))
	for _, info := range infos {
		if !pluginControlHasNetAccess(h.plugin, "link.read", info.Name) {
			continue
		}
		out = append(out, pluginControlNetLinkInfoMap(info))
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) netLinkEnsureVeth(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.ensureVeth")
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetVethRequest{
		Host: h.firstStringObjectField(obj, "host", "host_name", "name"),
		Peer: h.firstStringObjectField(obj, "peer", "peer_name"),
		MTU:  h.optionalIntObjectField(obj, 0, "mtu"),
		Up:   true,
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Host, "host"); err != nil {
		h.throwf("net.link.ensureVeth: %v", err)
	}
	if err := validatePluginControlInterfaceName(req.Peer, "peer"); err != nil {
		h.throwf("net.link.ensureVeth: %v", err)
	}
	if req.Host == req.Peer {
		h.throwf("net.link.ensureVeth: host and peer must be different")
	}
	if req.MTU != 0 && (req.MTU < 576 || req.MTU > 65535) {
		h.throwf("net.link.ensureVeth: mtu must be between 576 and 65535")
	}
	h.requireNetAccess("link.create", req.Host, "net.link.ensureVeth")
	h.requireNetAccess("link.create", req.Peer, "net.link.ensureVeth")
	result, err := admin.LinkEnsureVeth(req)
	if err != nil {
		h.throwf("net.link.ensureVeth: %v", err)
	}
	return h.vm.ToValue(map[string]any{
		"host":    pluginControlNetLinkInfoMap(result.Host),
		"peer":    pluginControlNetLinkInfoMap(result.Peer),
		"created": result.Created,
	})
}

func (h *pluginControlHost) netLinkEnsureDummy(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.ensureDummy")
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetDummyRequest{
		Name: h.firstStringObjectField(obj, "name", "interface", "link"),
		MTU:  h.optionalIntObjectField(obj, 0, "mtu"),
		Up:   true,
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Name, "name"); err != nil {
		h.throwf("net.link.ensureDummy: %v", err)
	}
	if req.MTU != 0 && (req.MTU < 576 || req.MTU > 65535) {
		h.throwf("net.link.ensureDummy: mtu must be between 576 and 65535")
	}
	h.requireNetAccess("link.create", req.Name, "net.link.ensureDummy")
	result, err := admin.LinkEnsureDummy(req)
	if err != nil {
		h.throwf("net.link.ensureDummy: %v", err)
	}
	return h.vm.ToValue(map[string]any{
		"link":    pluginControlNetLinkInfoMap(result.Link),
		"created": result.Created,
	})
}

func (h *pluginControlHost) netLinkEnsureMacvlan(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.ensureMacvlan")
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetMacvlanRequest{
		Name:   h.firstStringObjectField(obj, "name", "interface", "link"),
		Parent: h.firstStringObjectField(obj, "parent", "parent_interface", "physical_interface"),
		Mode:   strings.ToLower(h.firstStringObjectField(obj, "mode")),
		MAC:    h.firstStringObjectField(obj, "mac", "mac_address", "address"),
		MTU:    h.optionalIntObjectField(obj, 0, "mtu"),
		Up:     true,
	}
	if req.Mode == "" {
		req.Mode = "bridge"
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Name, "name"); err != nil {
		h.throwf("net.link.ensureMacvlan: %v", err)
	}
	if err := validatePluginControlInterfaceName(req.Parent, "parent"); err != nil {
		h.throwf("net.link.ensureMacvlan: %v", err)
	}
	if req.Name == req.Parent {
		h.throwf("net.link.ensureMacvlan: name and parent must be different")
	}
	switch req.Mode {
	case "bridge", "private", "vepa", "passthru":
	default:
		h.throwf("net.link.ensureMacvlan: mode must be bridge, private, vepa or passthru")
	}
	if req.MTU != 0 && (req.MTU < 576 || req.MTU > 65535) {
		h.throwf("net.link.ensureMacvlan: mtu must be between 576 and 65535")
	}
	if req.MAC != "" {
		normalized, err := normalizePluginControlUnicastMAC(req.MAC)
		if err != nil {
			h.throwf("net.link.ensureMacvlan: %v", err)
		}
		req.MAC = normalized
	}
	h.requireNetAccess("link.read", req.Parent, "net.link.ensureMacvlan")
	h.requireNetAccess("link.create", req.Name, "net.link.ensureMacvlan")
	result, err := admin.LinkEnsureMacvlan(req)
	if err != nil {
		h.throwf("net.link.ensureMacvlan: %v", err)
	}
	return h.vm.ToValue(map[string]any{
		"link":    pluginControlNetLinkInfoMap(result.Link),
		"created": result.Created,
	})
}

func normalizePluginControlUnicastMAC(value string) (string, error) {
	hardwareAddr, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(hardwareAddr) != 6 {
		return "", fmt.Errorf("mac must be a 6-byte address")
	}
	if hardwareAddr[0]&1 != 0 {
		return "", fmt.Errorf("mac must be a unicast address")
	}
	allZero := true
	for _, part := range hardwareAddr {
		if part != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", fmt.Errorf("mac must not be all zero")
	}
	return strings.ToLower(hardwareAddr.String()), nil
}

func (h *pluginControlHost) netLinkEnsureBridge(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.ensureBridge")
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetBridgeRequest{
		Name: h.firstStringObjectField(obj, "name", "bridge", "interface"),
		MTU:  h.optionalIntObjectField(obj, 0, "mtu"),
		Up:   true,
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Name, "name"); err != nil {
		h.throwf("net.link.ensureBridge: %v", err)
	}
	if req.MTU != 0 && (req.MTU < 576 || req.MTU > 65535) {
		h.throwf("net.link.ensureBridge: mtu must be between 576 and 65535")
	}
	h.requireNetAccess("link.create", req.Name, "net.link.ensureBridge")
	info, err := admin.LinkEnsureBridge(req)
	if err != nil {
		h.throwf("net.link.ensureBridge: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkDelete(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.delete")
	name := h.requiredNetStringArg(call, 0, "name")
	h.requireNetAccess("link.delete", name, "net.link.delete")
	if err := admin.LinkDelete(name); err != nil {
		h.throwf("net.link.delete: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkSetMaster(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.setMaster")
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetMasterRequest{
		Link:   h.firstStringObjectField(obj, "link", "interface", "dev", "name"),
		Master: h.firstStringObjectField(obj, "master", "bridge"),
		Up:     true,
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Link, "link"); err != nil {
		h.throwf("net.link.setMaster: %v", err)
	}
	if err := validatePluginControlInterfaceName(req.Master, "master"); err != nil {
		h.throwf("net.link.setMaster: %v", err)
	}
	if req.Link == req.Master {
		h.throwf("net.link.setMaster: link and master must be different")
	}
	h.requireNetAccess("link.master", req.Link, "net.link.setMaster")
	h.requireNetAccess("link.master", req.Master, "net.link.setMaster")
	info, err := admin.LinkSetMaster(req)
	if err != nil {
		h.throwf("net.link.setMaster: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkClearMaster(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.clearMaster")
	name := h.requiredNetStringArg(call, 0, "name")
	h.requireNetAccess("link.master", name, "net.link.clearMaster")
	info, err := admin.LinkClearMaster(name)
	if err != nil {
		h.throwf("net.link.clearMaster: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkSetUp(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.setUp")
	name := h.requiredNetStringArg(call, 0, "name")
	up := true
	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		up = call.Arguments[1].ToBoolean()
	}
	h.requireNetAccess("link.state", name, "net.link.setUp")
	if err := admin.LinkSetUp(name, up); err != nil {
		h.throwf("net.link.setUp: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkSetMTU(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.setMTU")
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setMTU: mtu is required")
	}
	mtu := int(call.Arguments[1].ToInteger())
	if mtu < 576 || mtu > 65535 {
		h.throwf("net.link.setMTU: mtu must be between 576 and 65535")
	}
	h.requireNetAccess("link.state", name, "net.link.setMTU")
	if err := admin.LinkSetMTU(name, mtu); err != nil {
		h.throwf("net.link.setMTU: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkSetARP(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.setARP")
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setARP: enabled is required")
	}
	enabled := call.Arguments[1].ToBoolean()
	h.requireNetAccess("link.state", name, "net.link.setARP")
	info, err := admin.LinkSetARP(name, enabled)
	if err != nil {
		h.throwf("net.link.setARP: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkSetPromiscuous(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.setPromiscuous")
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setPromiscuous: enabled is required")
	}
	enabled := call.Arguments[1].ToBoolean()
	h.requireNetAccess("link.state", name, "net.link.setPromiscuous")
	info, err := admin.LinkSetPromiscuous(name, enabled)
	if err != nil {
		h.throwf("net.link.setPromiscuous: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkSetOffloads(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.setOffloads")
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setOffloads: features are required")
	}
	obj := call.Arguments[1].ToObject(h.vm)
	features := make(map[string]bool)
	for _, key := range obj.Keys() {
		name := strings.TrimSpace(strings.ToLower(key))
		if !isAllowedPluginControlOffloadFeature(name) {
			h.throwf("net.link.setOffloads: unsupported feature %q", key)
		}
		features[name] = obj.Get(key).ToBoolean()
	}
	if len(features) == 0 {
		h.throwf("net.link.setOffloads: at least one feature is required")
	}
	h.requireNetAccess("link.offload", name, "net.link.setOffloads")
	if err := admin.LinkSetOffloads(pluginControlNetOffloadRequest{Interface: name, Features: features}); err != nil {
		h.throwf("net.link.setOffloads: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkGetOffloads(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.getOffloads")
	name := h.requiredNetStringArg(call, 0, "name")
	h.requireNetAccess("link.read", name, "net.link.getOffloads")
	features, err := admin.LinkGetOffloads(name)
	if err != nil {
		h.throwf("net.link.getOffloads: %v", err)
	}
	return h.vm.ToValue(features)
}

func (h *pluginControlHost) netLinkSetGSO(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.link.setGSO")
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setGSO: limits are required")
	}
	obj := call.Arguments[1].ToObject(h.vm)
	for _, key := range obj.Keys() {
		if key != "max_size" && key != "max_segs" {
			h.throwf("net.link.setGSO: unsupported limit %q", key)
		}
	}
	maxSize := int(obj.Get("max_size").ToInteger())
	maxSegs := int(obj.Get("max_segs").ToInteger())
	if maxSize < 576 || maxSize > 65536 {
		h.throwf("net.link.setGSO: max_size must be between 576 and 65536")
	}
	if maxSegs < 1 || maxSegs > 65535 {
		h.throwf("net.link.setGSO: max_segs must be between 1 and 65535")
	}
	h.requireNetAccess("link.offload", name, "net.link.setGSO")
	info, err := admin.LinkSetGSO(pluginControlNetGSORequest{Interface: name, MaxSize: maxSize, MaxSegs: maxSegs})
	if err != nil {
		h.throwf("net.link.setGSO: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func isAllowedPluginControlOffloadFeature(name string) bool {
	switch name {
	case "rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro":
		return true
	default:
		return false
	}
}

func parsePluginControlOffloadFeatures(output string) map[string]bool {
	aliases := map[string]string{
		"rx-checksumming":              "rx",
		"tx-checksumming":              "tx",
		"scatter-gather":               "sg",
		"tcp-segmentation-offload":     "tso",
		"udp-fragmentation-offload":    "ufo",
		"generic-segmentation-offload": "gso",
		"generic-receive-offload":      "gro",
		"large-receive-offload":        "lro",
	}
	out := make(map[string]bool, len(aliases))
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		feature, ok := aliases[strings.TrimSpace(strings.ToLower(parts[0]))]
		if !ok {
			continue
		}
		state := strings.Fields(strings.TrimSpace(strings.ToLower(parts[1])))
		if len(state) == 0 || (state[0] != "on" && state[0] != "off") {
			continue
		}
		out[feature] = state[0] == "on"
	}
	return out
}

func (h *pluginControlHost) netAddrReplace(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.addr.replace")
	req := h.netAddrRequest(call, "net.addr.replace")
	h.requireNetAccess("addr.write", req.Interface, "net.addr.replace")
	if err := admin.AddrReplace(req); err != nil {
		h.throwf("net.addr.replace: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netPrefixSubnet(call goja.FunctionCall) goja.Value {
	if h.upgradePhase {
		h.throwf("net.prefix.subnet is unavailable during plugin upgrade snapshot/restore")
	}
	obj := h.requiredObjectArg(call, 0, "request")
	prefixText := h.firstStringObjectField(obj, "prefix", "cidr", "parent_prefix")
	if prefixText == "" {
		h.throwf("net.prefix.subnet: prefix is required")
	}
	newLength := h.optionalIntObjectField(obj, -1, "new_length", "prefix_length", "length")
	if newLength < 0 || newLength > 128 {
		h.throwf("net.prefix.subnet: new_length must be between 0 and 128")
	}
	rawIndex := h.optionalIntObjectField(obj, 0, "index", "subnet_index")
	if rawIndex < 0 {
		h.throwf("net.prefix.subnet: index must not be negative")
	}
	_, parent, err := normalizeIPv6Prefix(prefixText)
	if err != nil {
		h.throwf("net.prefix.subnet: %v", err)
	}
	subnet, err := pluginIPv6SubnetByIndex(parent, newLength, uint64(rawIndex))
	if err != nil {
		h.throwf("net.prefix.subnet: %v", err)
	}
	return h.vm.ToValue(subnet.String())
}

func (h *pluginControlHost) netAddrDelete(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.addr.delete")
	req := h.netAddrRequest(call, "net.addr.delete")
	h.requireNetAccess("addr.write", req.Interface, "net.addr.delete")
	if err := admin.AddrDelete(req); err != nil {
		h.throwf("net.addr.delete: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netRouteReplace(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.route.replace")
	req := h.netRouteRequest(call, "net.route.replace")
	h.requireRouteNetAccess(req, "net.route.replace")
	if err := admin.RouteReplace(req); err != nil {
		h.throwf("net.route.replace: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netRouteDelete(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.route.delete")
	req := h.netRouteRequest(call, "net.route.delete")
	h.requireRouteNetAccess(req, "net.route.delete")
	if err := admin.RouteDelete(req); err != nil {
		h.throwf("net.route.delete: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) requireRouteNetAccess(req pluginControlNetRouteRequest, operation string) {
	if req.Dev == "" {
		h.throwf("%s: dev is required for route.write net_access", operation)
		return
	}
	h.requireNetAccess("route.write", req.Dev, operation)
}

func (h *pluginControlHost) netAddrRequest(call goja.FunctionCall, operation string) pluginControlNetAddrRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetAddrRequest{
		Interface: h.firstStringObjectField(obj, "interface", "dev", "link"),
		CIDR:      h.firstStringObjectField(obj, "cidr", "address", "addr"),
	}
	if err := validatePluginControlInterfaceName(req.Interface, "interface"); err != nil {
		h.throwf("%s: %v", operation, err)
	}
	if req.CIDR == "" || strings.Contains(req.CIDR, "\x00") || len(req.CIDR) > 128 {
		h.throwf("%s: cidr is required", operation)
	}
	return req
}

func (h *pluginControlHost) netRouteRequest(call goja.FunctionCall, operation string) pluginControlNetRouteRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetRouteRequest{
		Dst:     h.firstStringObjectField(obj, "dst", "destination", "cidr"),
		Gateway: h.firstStringObjectField(obj, "gateway", "gw"),
		Dev:     h.firstStringObjectField(obj, "dev", "interface", "link"),
		Src:     h.firstStringObjectField(obj, "src", "source"),
		Table:   h.optionalIntObjectField(obj, 0, "table"),
		Metric:  h.optionalIntObjectField(obj, 0, "metric"),
		Scope:   h.optionalIntObjectField(obj, 0, "scope"),
	}
	if req.Dst == "" {
		h.throwf("%s: dst is required", operation)
	}
	if req.Dev != "" {
		if err := validatePluginControlInterfaceName(req.Dev, "dev"); err != nil {
			h.throwf("%s: %v", operation, err)
		}
	}
	for _, item := range []struct {
		name  string
		value string
	}{
		{name: "dst", value: req.Dst},
		{name: "gateway", value: req.Gateway},
		{name: "src", value: req.Src},
	} {
		if strings.Contains(item.value, "\x00") || len(item.value) > 128 {
			h.throwf("%s: %s contains invalid characters", operation, item.name)
		}
	}
	if req.Table < 0 || req.Table > 0x7fffffff {
		h.throwf("%s: table out of range", operation)
	}
	if req.Metric < 0 || req.Metric > 0x7fffffff {
		h.throwf("%s: metric out of range", operation)
	}
	if req.Scope < 0 || req.Scope > 255 {
		h.throwf("%s: scope out of range", operation)
	}
	return req
}

func (h *pluginControlHost) requiredNetStringArg(call goja.FunctionCall, index int, name string) string {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s is required", name)
	}
	value := strings.TrimSpace(call.Arguments[index].String())
	if err := validatePluginControlInterfaceName(value, name); err != nil {
		h.throwf("%v", err)
	}
	return value
}

func (h *pluginControlHost) firstStringObjectField(obj *goja.Object, fields ...string) string {
	for _, field := range fields {
		value := h.optionalStringObjectField(obj, field)
		if value != "" {
			return value
		}
	}
	return ""
}

func (h *pluginControlHost) optionalIntObjectField(obj *goja.Object, fallback int, fields ...string) int {
	for _, field := range fields {
		value := h.objectField(obj, field)
		if goja.IsUndefined(value) || goja.IsNull(value) {
			continue
		}
		return int(value.ToInteger())
	}
	return fallback
}

func validatePluginControlInterfaceName(value string, field string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.Contains(value, "\x00") || strings.ContainsAny(value, "/\\ \t\r\n") || len(value) > linuxInterfaceNameMaxBytes {
		return fmt.Errorf("%s contains invalid characters or exceeds %d bytes", field, linuxInterfaceNameMaxBytes)
	}
	return nil
}

func pluginControlNetLinkInfoMap(info pluginControlNetLinkInfo) map[string]any {
	out := map[string]any{
		"name":           info.Name,
		"ifindex":        info.IfIndex,
		"kind":           info.Kind,
		"parent":         info.Parent,
		"mtu":            info.MTU,
		"mac":            info.MAC,
		"up":             info.Up,
		"arp":            info.ARP,
		"oper_state":     info.OperState,
		"addresses":      append([]string(nil), info.Addresses...),
		"peer_name":      info.PeerName,
		"peer_ifindex":   info.PeerIfIndex,
		"master_name":    info.MasterName,
		"master_ifindex": info.MasterIfIndex,
		"promiscuous":    info.Promiscuous,
		"gso_max_size":   info.GSOMaxSize,
		"gso_max_segs":   info.GSOMaxSegs,
	}
	if info.Statistics != nil {
		out["statistics"] = map[string]uint64{
			"rx_packets": info.Statistics.RXPackets,
			"tx_packets": info.Statistics.TXPackets,
			"rx_bytes":   info.Statistics.RXBytes,
			"tx_bytes":   info.Statistics.TXBytes,
			"rx_errors":  info.Statistics.RXErrors,
			"tx_errors":  info.Statistics.TXErrors,
			"rx_dropped": info.Statistics.RXDropped,
			"tx_dropped": info.Statistics.TXDropped,
		}
	}
	return out
}
