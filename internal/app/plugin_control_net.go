package app

import (
	"fmt"
	"strings"

	"github.com/dop251/goja"
)

const linuxInterfaceNameMaxBytes = 15

type pluginControlNetAdmin interface {
	LinkGet(name string) (pluginControlNetLinkInfo, error)
	LinkList() ([]pluginControlNetLinkInfo, error)
	LinkEnsureBridge(req pluginControlNetBridgeRequest) (pluginControlNetLinkInfo, error)
	LinkEnsureVeth(req pluginControlNetVethRequest) (pluginControlNetVethResult, error)
	LinkDelete(name string) error
	LinkSetMaster(req pluginControlNetMasterRequest) (pluginControlNetLinkInfo, error)
	LinkClearMaster(name string) (pluginControlNetLinkInfo, error)
	LinkSetUp(name string, up bool) error
	LinkSetMTU(name string, mtu int) error
	LinkSetOffloads(req pluginControlNetOffloadRequest) error
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
	OperState     string
	Addresses     []string
	PeerName      string
	PeerIfIndex   int
	MasterName    string
	MasterIfIndex int
}

type pluginControlNetVethRequest struct {
	Host string
	Peer string
	MTU  int
	Up   bool
}

type pluginControlNetVethResult struct {
	Host pluginControlNetLinkInfo
	Peer pluginControlNetLinkInfo
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
		"host": pluginControlNetLinkInfoMap(result.Host),
		"peer": pluginControlNetLinkInfoMap(result.Peer),
	})
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

func isAllowedPluginControlOffloadFeature(name string) bool {
	switch name {
	case "rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro":
		return true
	default:
		return false
	}
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
	return map[string]any{
		"name":           info.Name,
		"ifindex":        info.IfIndex,
		"kind":           info.Kind,
		"parent":         info.Parent,
		"mtu":            info.MTU,
		"mac":            info.MAC,
		"up":             info.Up,
		"oper_state":     info.OperState,
		"addresses":      append([]string(nil), info.Addresses...),
		"peer_name":      info.PeerName,
		"peer_ifindex":   info.PeerIfIndex,
		"master_name":    info.MasterName,
		"master_ifindex": info.MasterIfIndex,
	}
}
