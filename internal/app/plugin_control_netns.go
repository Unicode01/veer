package app

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dop251/goja"

	"github.com/Unicode01/veer/internal/store"
)

const (
	pluginControlTunTapMaxPacketBytes = 65535
	pluginControlTunTapMaxTimeout     = 15 * time.Second
)

type pluginControlNetworkProvider interface {
	NamespaceLookup(name string) (pluginControlNetNamespaceInfo, bool, error)
	NamespaceList() ([]pluginControlNetNamespaceInfo, error)
	NamespaceEnsure(req pluginControlNetNamespaceRequest) (pluginControlNetNamespaceResult, error)
	NamespaceDelete(name string, identity pluginControlNetNamespaceIdentity) error
	TunTapEnsure(owner string, req pluginControlNetTunTapRequest) (pluginControlNetTunTapResult, error)
	TunTapClose(owner string, req pluginControlNetTunTapCloseRequest) error
	TunTapRead(owner string, req pluginControlNetTunTapReadRequest) (pluginControlNetTunTapPacket, error)
	TunTapWrite(owner string, req pluginControlNetTunTapWriteRequest) (int, error)
	TunTapList(owner string) []pluginControlNetTunTapInfo
	TunTapCloseAll(owner string)
}

type pluginControlNetNamespaceIdentity struct {
	Device uint64 `json:"device,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
}

type pluginControlNetNamespaceInfo struct {
	Name     string                            `json:"name"`
	Identity pluginControlNetNamespaceIdentity `json:"identity"`
}

type pluginControlNetNamespaceRequest struct {
	Name       string
	LoopbackUp bool
}

type pluginControlNetNamespaceResult struct {
	Info    pluginControlNetNamespaceInfo
	Created bool
}

type pluginControlNetTunTapRequest struct {
	Name      string
	Namespace string
	Mode      string
	MTU       int
	Up        bool
}

type pluginControlNetTunTapCloseRequest struct {
	Name      string
	Namespace string
	IfIndex   int
}

type pluginControlNetTunTapReadRequest struct {
	Name      string
	Namespace string
	MaxBytes  int
	Timeout   time.Duration
}

type pluginControlNetTunTapWriteRequest struct {
	Name      string
	Namespace string
	Packet    []byte
}

type pluginControlNetTunTapPacket struct {
	Packet   []byte
	TimedOut bool
}

type pluginControlNetTunTapInfo struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Mode        string `json:"mode"`
	IfIndex     int    `json:"ifindex"`
	MTU         int    `json:"mtu"`
	Up          bool   `json:"up"`
	MAC         string `json:"mac,omitempty"`
	Reads       uint64 `json:"reads"`
	ReadBytes   uint64 `json:"read_bytes"`
	Writes      uint64 `json:"writes"`
	WriteBytes  uint64 `json:"write_bytes"`
	ReadErrors  uint64 `json:"read_errors"`
	WriteErrors uint64 `json:"write_errors"`
}

type pluginControlNetTunTapResult struct {
	Info    pluginControlNetTunTapInfo
	Created bool
}

type pluginOwnedNamespaceClaim struct {
	Name     string                            `json:"name"`
	Identity pluginControlNetNamespaceIdentity `json:"identity,omitempty"`
	Pending  bool                              `json:"pending,omitempty"`
	BootID   string                            `json:"boot_id,omitempty"`
}

type pluginOwnedTunTapClaim struct {
	Name              string                            `json:"name"`
	Namespace         string                            `json:"namespace"`
	Mode              string                            `json:"mode"`
	IfIndex           int                               `json:"ifindex,omitempty"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`
	Pending           bool                              `json:"pending,omitempty"`
	BootID            string                            `json:"boot_id,omitempty"`
}

func (h *pluginControlHost) networkProviderOrThrow(permission, operation string) pluginControlNetworkProvider {
	h.requirePermission(permission)
	provider, ok := h.netAdmin.(pluginControlNetworkProvider)
	if !ok || provider == nil {
		h.throwf("%s: network provider is unavailable on this platform", operation)
	}
	return provider
}

func (h *pluginControlHost) requireNamespaceAccess(namespace, api string) string {
	namespace = normalizePluginControlNamespace(namespace)
	if !pluginControlHasNamespaceAccess(h.plugin, namespace) {
		h.throwf("%s: namespace_access for %s is not declared", api, namespace)
	}
	return namespace
}

func validatePluginControlNamespaceName(value string, allowHost bool) (string, error) {
	value = normalizePluginControlNamespace(value)
	if value == "host" {
		if allowHost {
			return value, nil
		}
		return "", fmt.Errorf("host is reserved for the initial network namespace")
	}
	if len(value) == 0 || len(value) > 63 || value == "." || value == ".." || strings.ContainsAny(value, "/\\ \t\r\n*") {
		return "", fmt.Errorf("namespace must be 1 to 63 lowercase letters, digits, dots, underscores or hyphens")
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return "", fmt.Errorf("namespace must be 1 to 63 lowercase letters, digits, dots, underscores or hyphens")
	}
	return value, nil
}

func (h *pluginControlHost) requiredNamespaceStringArg(call goja.FunctionCall, index int, label string) string {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s is required", label)
	}
	value := strings.TrimSpace(call.Arguments[index].String())
	if value == "" || strings.Contains(value, "\x00") {
		h.throwf("%s is required", label)
	}
	return value
}

func pluginControlNamespaceIdentityEqual(left, right pluginControlNetNamespaceIdentity) bool {
	return left.Device == right.Device && left.Inode == right.Inode && left.Device != 0 && left.Inode != 0
}

func pluginControlNamespaceInfoMap(info pluginControlNetNamespaceInfo) map[string]any {
	return map[string]any{
		"name":     info.Name,
		"identity": fmt.Sprintf("%d:%d", info.Identity.Device, info.Identity.Inode),
	}
}

func pluginControlTunTapResourceKey(namespace, name string) string {
	return normalizePluginControlNamespace(namespace) + "/" + strings.TrimSpace(name)
}

func (h *pluginControlHost) netNamespaceGet(call goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.namespace", "net.namespace.get")
	name, err := validatePluginControlNamespaceName(h.requiredNamespaceStringArg(call, 0, "name"), false)
	if err != nil {
		h.throwf("net.namespace.get: %v", err)
	}
	h.requireNamespaceAccess(name, "net.namespace.get")
	info, present, err := provider.NamespaceLookup(name)
	if err != nil {
		h.throwf("net.namespace.get: %v", err)
	}
	if !present {
		return goja.Null()
	}
	return h.vm.ToValue(pluginControlNamespaceInfoMap(info))
}

func (h *pluginControlHost) netNamespaceList(goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.namespace", "net.namespace.list")
	items, err := provider.NamespaceList()
	if err != nil {
		h.throwf("net.namespace.list: %v", err)
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if pluginControlHasNamespaceAccess(h.plugin, item.Name) {
			out = append(out, pluginControlNamespaceInfoMap(item))
		}
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) netNamespaceEnsure(call goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.namespace", "net.namespace.ensure")
	obj := h.requiredObjectArg(call, 0, "request")
	name, err := validatePluginControlNamespaceName(h.firstStringObjectField(obj, "name", "namespace"), false)
	if err != nil {
		h.throwf("net.namespace.ensure: %v", err)
	}
	h.requireNamespaceAccess(name, "net.namespace.ensure")
	loopbackUp := true
	if raw := h.objectField(obj, "loopback_up"); goja.IsUndefined(raw) || goja.IsNull(raw) {
		if raw = h.objectField(obj, "loopbackUp"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
			loopbackUp = raw.ToBoolean()
		}
	} else {
		loopbackUp = raw.ToBoolean()
	}

	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeNamespace, name)
	if err != nil {
		h.throwf("net.namespace.ensure: inspect ownership: %v", err)
	}
	if owned != nil && owned.PluginID != h.plugin.ID {
		h.throwf("net.namespace.ensure: namespace %s is owned by plugin %s", name, owned.PluginID)
	}
	if existing, present, lookupErr := provider.NamespaceLookup(name); lookupErr != nil {
		h.throwf("net.namespace.ensure: inspect namespace: %v", lookupErr)
	} else if present && owned == nil {
		result := pluginControlNamespaceInfoMap(existing)
		result["created"] = false
		result["owned"] = false
		return h.vm.ToValue(result)
	} else if present && owned != nil {
		var claim pluginOwnedNamespaceClaim
		if jsonErr := json.Unmarshal([]byte(owned.MetadataJSON), &claim); jsonErr != nil {
			h.throwf("net.namespace.ensure: decode ownership: %v", jsonErr)
		}
		if !claim.Pending && !pluginControlNamespaceIdentityEqual(claim.Identity, existing.Identity) {
			h.throwf("net.namespace.ensure: namespace %s changed identity", name)
		}
		claim = pluginOwnedNamespaceClaim{Name: name, Identity: existing.Identity, BootID: pluginOwnershipBootID}
		if updateErr := updatePluginOwnedNetworkResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNamespace, name, claim); updateErr != nil {
			h.throwf("net.namespace.ensure: finalize ownership: %v", updateErr)
		}
		result := pluginControlNamespaceInfoMap(existing)
		result["created"] = false
		result["owned"] = true
		return h.vm.ToValue(result)
	}

	reserved := false
	if owned == nil {
		claim := pluginOwnedNamespaceClaim{Name: name, Pending: true, BootID: pluginOwnershipBootID}
		if err := addPluginOwnedNetworkResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNamespace, name, claim); err != nil {
			h.throwf("net.namespace.ensure: reserve ownership: %v", err)
		}
		reserved = true
	}
	result, err := provider.NamespaceEnsure(pluginControlNetNamespaceRequest{Name: name, LoopbackUp: loopbackUp})
	if err != nil {
		if reserved {
			_ = store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNamespace, name)
		}
		h.throwf("net.namespace.ensure: %v", err)
	}
	claim := pluginOwnedNamespaceClaim{Name: name, Identity: result.Info.Identity, BootID: pluginOwnershipBootID}
	if err := updatePluginOwnedNetworkResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNamespace, name, claim); err != nil {
		_ = provider.NamespaceDelete(name, result.Info.Identity)
		h.throwf("net.namespace.ensure: finalize ownership: %v", err)
	}
	value := pluginControlNamespaceInfoMap(result.Info)
	value["created"] = result.Created
	value["owned"] = true
	return h.vm.ToValue(value)
}

func (h *pluginControlHost) netNamespaceDelete(call goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.namespace", "net.namespace.delete")
	name, err := validatePluginControlNamespaceName(h.requiredNamespaceStringArg(call, 0, "name"), false)
	if err != nil {
		h.throwf("net.namespace.delete: %v", err)
	}
	h.requireNamespaceAccess(name, "net.namespace.delete")
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeNamespace, name)
	if err != nil {
		h.throwf("net.namespace.delete: inspect ownership: %v", err)
	}
	if owned == nil || owned.PluginID != h.plugin.ID {
		h.throwf("net.namespace.delete: only namespaces created and owned by this plugin may be deleted")
	}
	if dependent, err := pluginOwnedTunTapCountInNamespace(h.db, h.plugin.ID, name); err != nil {
		h.throwf("net.namespace.delete: inspect dependent devices: %v", err)
	} else if dependent > 0 {
		h.throwf("net.namespace.delete: close %d owned TUN/TAP device(s) in namespace %s first", dependent, name)
	}
	var claim pluginOwnedNamespaceClaim
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &claim); err != nil {
		h.throwf("net.namespace.delete: decode ownership: %v", err)
	}
	if err := provider.NamespaceDelete(name, claim.Identity); err != nil {
		h.throwf("net.namespace.delete: %v", err)
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNamespace, name); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("net.namespace.delete: clear ownership: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netNamespaceRelease(call goja.FunctionCall) goja.Value {
	h.networkProviderOrThrow("net.namespace", "net.namespace.release")
	name, err := validatePluginControlNamespaceName(h.requiredNamespaceStringArg(call, 0, "name"), false)
	if err != nil {
		h.throwf("net.namespace.release: %v", err)
	}
	h.requireNamespaceAccess(name, "net.namespace.release")
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeNamespace, name)
	if err != nil {
		h.throwf("net.namespace.release: inspect ownership: %v", err)
	}
	if owned == nil || owned.PluginID != h.plugin.ID {
		h.throwf("net.namespace.release: namespace is not owned by this plugin")
	}
	if dependent, err := pluginOwnedTunTapCountInNamespace(h.db, h.plugin.ID, name); err != nil {
		h.throwf("net.namespace.release: inspect dependent devices: %v", err)
	} else if dependent > 0 {
		h.throwf("net.namespace.release: close %d owned TUN/TAP device(s) in namespace %s first", dependent, name)
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNamespace, name); err != nil {
		h.throwf("net.namespace.release: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netNamespaceOwned(goja.FunctionCall) goja.Value {
	h.networkProviderOrThrow("net.namespace", "net.namespace.owned")
	return h.vm.ToValue(h.pluginOwnedNetworkResourceViews(pluginOwnedResourceTypeNamespace, "net.namespace.owned"))
}

func (h *pluginControlHost) netTunTapEnsure(call goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.tuntap", "net.tuntap.ensure")
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetTunTapRequest{
		Name:      strings.TrimSpace(h.firstStringObjectField(obj, "name", "interface", "link")),
		Namespace: normalizePluginControlNamespace(h.firstStringObjectField(obj, "namespace", "netns")),
		Mode:      strings.ToLower(strings.TrimSpace(h.firstStringObjectField(obj, "mode", "type"))),
		MTU:       h.optionalIntObjectField(obj, 0, "mtu"),
		Up:        true,
	}
	if req.Mode == "" {
		req.Mode = "tun"
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Name, "name"); err != nil {
		h.throwf("net.tuntap.ensure: %v", err)
	}
	var err error
	if req.Namespace, err = validatePluginControlNamespaceName(req.Namespace, true); err != nil {
		h.throwf("net.tuntap.ensure: %v", err)
	}
	if req.Mode != "tun" && req.Mode != "tap" {
		h.throwf("net.tuntap.ensure: mode must be tun or tap")
	}
	if req.MTU != 0 && (req.MTU < 576 || req.MTU > 65535) {
		h.throwf("net.tuntap.ensure: mtu must be between 576 and 65535")
	}
	h.requireNamespaceAccess(req.Namespace, "net.tuntap.ensure")
	h.requireNetAccess("tuntap", req.Name, "net.tuntap.ensure")
	key := pluginControlTunTapResourceKey(req.Namespace, req.Name)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeTunTap, key)
	if err != nil {
		h.throwf("net.tuntap.ensure: inspect ownership: %v", err)
	}
	if owned != nil && owned.PluginID != h.plugin.ID {
		h.throwf("net.tuntap.ensure: device %s is owned by plugin %s", key, owned.PluginID)
	}
	reserved := false
	if owned == nil {
		claim := pluginOwnedTunTapClaim{Name: req.Name, Namespace: req.Namespace, Mode: req.Mode, Pending: true, BootID: pluginOwnershipBootID}
		if err := addPluginOwnedNetworkResource(h.db, h.plugin.ID, pluginOwnedResourceTypeTunTap, key, claim); err != nil {
			h.throwf("net.tuntap.ensure: reserve ownership: %v", err)
		}
		reserved = true
	}
	result, err := provider.TunTapEnsure(h.plugin.ID, req)
	if err != nil {
		if reserved {
			_ = store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeTunTap, key)
		}
		h.throwf("net.tuntap.ensure: %v", err)
	}
	namespaceIdentity := pluginControlNetNamespaceIdentity{}
	if req.Namespace != "host" {
		if namespace, present, lookupErr := provider.NamespaceLookup(req.Namespace); lookupErr != nil || !present {
			_ = provider.TunTapClose(h.plugin.ID, pluginControlNetTunTapCloseRequest{Name: req.Name, Namespace: req.Namespace, IfIndex: result.Info.IfIndex})
			if lookupErr != nil {
				h.throwf("net.tuntap.ensure: resolve namespace identity: %v", lookupErr)
			}
			h.throwf("net.tuntap.ensure: namespace %s disappeared", req.Namespace)
		} else {
			namespaceIdentity = namespace.Identity
		}
	}
	claim := pluginOwnedTunTapClaim{
		Name: req.Name, Namespace: req.Namespace, Mode: req.Mode, IfIndex: result.Info.IfIndex,
		NamespaceIdentity: namespaceIdentity, BootID: pluginOwnershipBootID,
	}
	if err := updatePluginOwnedNetworkResource(h.db, h.plugin.ID, pluginOwnedResourceTypeTunTap, key, claim); err != nil {
		_ = provider.TunTapClose(h.plugin.ID, pluginControlNetTunTapCloseRequest{Name: req.Name, Namespace: req.Namespace, IfIndex: result.Info.IfIndex})
		h.throwf("net.tuntap.ensure: finalize ownership: %v", err)
	}
	return h.vm.ToValue(map[string]any{"device": result.Info, "created": result.Created})
}

func (h *pluginControlHost) netTunTapClose(call goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.tuntap", "net.tuntap.close")
	req, owned := h.requiredOwnedTunTap(call, "net.tuntap.close")
	if err := provider.TunTapClose(h.plugin.ID, pluginControlNetTunTapCloseRequest{Name: req.Name, Namespace: req.Namespace, IfIndex: req.IfIndex}); err != nil {
		h.throwf("net.tuntap.close: %v", err)
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeTunTap, owned.ResourceKey); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("net.tuntap.close: clear ownership: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netTunTapRead(call goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.tuntap", "net.tuntap.read")
	claim, _ := h.requiredOwnedTunTap(call, "net.tuntap.read")
	obj := h.requiredObjectArg(call, 0, "request")
	maxBytes := h.optionalIntObjectField(obj, pluginControlTunTapMaxPacketBytes, "max_bytes", "maxBytes")
	timeoutMS := h.optionalIntObjectField(obj, 0, "timeout_ms", "timeoutMs")
	if maxBytes < 1 || maxBytes > pluginControlTunTapMaxPacketBytes {
		h.throwf("net.tuntap.read: max_bytes must be between 1 and %d", pluginControlTunTapMaxPacketBytes)
	}
	if timeoutMS < 0 || time.Duration(timeoutMS)*time.Millisecond > pluginControlTunTapMaxTimeout {
		h.throwf("net.tuntap.read: timeout_ms must be between 0 and %d", pluginControlTunTapMaxTimeout.Milliseconds())
	}
	packet, err := provider.TunTapRead(h.plugin.ID, pluginControlNetTunTapReadRequest{
		Name: claim.Name, Namespace: claim.Namespace, MaxBytes: maxBytes, Timeout: time.Duration(timeoutMS) * time.Millisecond,
	})
	if err != nil {
		h.throwf("net.tuntap.read: %v", err)
	}
	return h.vm.ToValue(map[string]any{"data": hex.EncodeToString(packet.Packet), "bytes": len(packet.Packet), "timed_out": packet.TimedOut})
}

func (h *pluginControlHost) netTunTapWrite(call goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.tuntap", "net.tuntap.write")
	claim, _ := h.requiredOwnedTunTap(call, "net.tuntap.write")
	obj := h.requiredObjectArg(call, 0, "request")
	data := strings.TrimSpace(h.firstStringObjectField(obj, "data", "packet"))
	if data == "" || len(data)%2 != 0 || len(data) > pluginControlTunTapMaxPacketBytes*2 {
		h.throwf("net.tuntap.write: data must be non-empty even-length hex up to %d bytes", pluginControlTunTapMaxPacketBytes)
	}
	packet, err := hex.DecodeString(data)
	if err != nil {
		h.throwf("net.tuntap.write: data must be hexadecimal")
	}
	written, err := provider.TunTapWrite(h.plugin.ID, pluginControlNetTunTapWriteRequest{Name: claim.Name, Namespace: claim.Namespace, Packet: packet})
	if err != nil {
		h.throwf("net.tuntap.write: %v", err)
	}
	return h.vm.ToValue(map[string]any{"bytes": written})
}

func (h *pluginControlHost) netTunTapList(goja.FunctionCall) goja.Value {
	provider := h.networkProviderOrThrow("net.tuntap", "net.tuntap.list")
	return h.vm.ToValue(provider.TunTapList(h.plugin.ID))
}

func (h *pluginControlHost) netTunTapOwned(goja.FunctionCall) goja.Value {
	h.networkProviderOrThrow("net.tuntap", "net.tuntap.owned")
	return h.vm.ToValue(h.pluginOwnedNetworkResourceViews(pluginOwnedResourceTypeTunTap, "net.tuntap.owned"))
}

func (h *pluginControlHost) requiredOwnedTunTap(call goja.FunctionCall, api string) (pluginOwnedTunTapClaim, store.PluginOwnedResource) {
	obj := h.requiredObjectArg(call, 0, "request")
	name := strings.TrimSpace(h.firstStringObjectField(obj, "name", "interface", "link"))
	if err := validatePluginControlInterfaceName(name, "name"); err != nil {
		h.throwf("%s: %v", api, err)
	}
	namespace, err := validatePluginControlNamespaceName(h.firstStringObjectField(obj, "namespace", "netns"), true)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	h.requireNamespaceAccess(namespace, api)
	h.requireNetAccess("tuntap", name, api)
	key := pluginControlTunTapResourceKey(namespace, name)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeTunTap, key)
	if err != nil {
		h.throwf("%s: inspect ownership: %v", api, err)
	}
	if owned == nil || owned.PluginID != h.plugin.ID {
		h.throwf("%s: device %s is not owned by this plugin", api, key)
	}
	var claim pluginOwnedTunTapClaim
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &claim); err != nil {
		h.throwf("%s: decode ownership: %v", api, err)
	}
	if claim.Pending {
		h.throwf("%s: device ownership is pending reconciliation", api)
	}
	return claim, *owned
}

func addPluginOwnedNetworkResource(db store.RuleStore, pluginID, resourceType, resourceKey string, metadata any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: pluginID, ResourceType: resourceType, ResourceKey: resourceKey, MetadataJSON: string(raw),
	})
}

func updatePluginOwnedNetworkResource(db store.RuleStore, pluginID, resourceType, resourceKey string, metadata any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return store.UpdatePluginOwnedResource(db, pluginID, resourceType, resourceKey, string(raw))
}

func (h *pluginControlHost) pluginOwnedNetworkResourceViews(resourceType, api string) []map[string]any {
	items, err := store.GetPluginOwnedResources(h.db, h.plugin.ID)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	out := make([]map[string]any, 0)
	for _, item := range items {
		if item.ResourceType != resourceType {
			continue
		}
		var metadata map[string]any
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			h.throwf("%s: decode ownership: %v", api, err)
		}
		out = append(out, map[string]any{"key": item.ResourceKey, "metadata": metadata, "created_at": item.CreatedAt, "updated_at": item.UpdatedAt})
	}
	return out
}

func pluginOwnedTunTapCountInNamespace(db store.RuleStore, pluginID, namespace string) (int, error) {
	items, err := store.GetPluginOwnedResources(db, pluginID)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, item := range items {
		if item.ResourceType != pluginOwnedResourceTypeTunTap {
			continue
		}
		var claim pluginOwnedTunTapClaim
		if err := json.Unmarshal([]byte(item.MetadataJSON), &claim); err != nil {
			return 0, err
		}
		if claim.Namespace == namespace {
			count++
		}
	}
	return count, nil
}
