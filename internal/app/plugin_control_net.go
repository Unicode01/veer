package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/dop251/goja"

	"github.com/Unicode01/veer/internal/store"
)

const (
	linuxInterfaceNameMaxBytes       = 15
	pluginControlNetMaxRouteNexthops = 64
)

type pluginControlNetAdmin interface {
	LinkGet(name string) (pluginControlNetLinkInfo, error)
	LinkLookup(name string) (pluginControlNetLinkInfo, bool, error)
	LinkList() ([]pluginControlNetLinkInfo, error)
	LinkEnsureBridge(req pluginControlNetBridgeRequest) (pluginControlNetLinkInfo, error)
	LinkEnsureVeth(req pluginControlNetVethRequest) (pluginControlNetVethResult, error)
	LinkEnsureDummy(req pluginControlNetDummyRequest) (pluginControlNetDummyResult, error)
	LinkEnsureMacvlan(req pluginControlNetMacvlanRequest) (pluginControlNetMacvlanResult, error)
	LinkEnsureVLAN(req pluginControlNetVLANRequest) (pluginControlNetVLANResult, error)
	LinkEnsureVRF(req pluginControlNetVRFRequest) (pluginControlNetVRFResult, error)
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
	RouteSnapshot(req pluginControlNetRouteRequest) ([]pluginControlNetRouteState, error)
	RouteRestore(states []pluginControlNetRouteState) error
	RouteReplace(req pluginControlNetRouteRequest) error
	RouteDelete(req pluginControlNetRouteRequest) error
	RuleSnapshot(req pluginControlNetRuleRequest) ([]pluginControlNetRuleState, error)
	RuleRestore(states []pluginControlNetRuleState) error
	RuleReplace(req pluginControlNetRuleRequest) error
	RuleDelete(req pluginControlNetRuleRequest) error
	NeighSnapshot(req pluginControlNetNeighRequest) ([]pluginControlNetNeighState, error)
	NeighRestore(states []pluginControlNetNeighState) error
	NeighReplace(req pluginControlNetNeighRequest) error
	NeighDelete(req pluginControlNetNeighRequest) error
}

type pluginControlNetLinkInfo struct {
	Namespace     string
	Name          string
	Created       bool
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
	VLANID        int
	VLANProtocol  string
	VRFTable      uint32
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
	Namespace string
	Host      string
	Peer      string
	MTU       int
	Up        bool
}

type pluginControlNetVethResult struct {
	Host    pluginControlNetLinkInfo
	Peer    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetDummyRequest struct {
	Namespace string
	Name      string
	MTU       int
	Up        bool
}

type pluginControlNetDummyResult struct {
	Link    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetMacvlanRequest struct {
	Namespace string
	Name      string
	Parent    string
	Mode      string
	MAC       string
	MTU       int
	Up        bool
}

type pluginControlNetMacvlanResult struct {
	Link    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetVLANRequest struct {
	Namespace string
	Name      string
	Parent    string
	VLANID    int
	Protocol  string
	MTU       int
	Up        bool
}

type pluginControlNetVLANResult struct {
	Link    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetVRFRequest struct {
	Namespace string
	Name      string
	Table     uint32
	Up        bool
}

type pluginControlNetVRFResult struct {
	Link    pluginControlNetLinkInfo
	Created bool
}

type pluginControlNetBridgeRequest struct {
	Namespace string
	Name      string
	MTU       int
	Up        bool
}

type pluginControlNetMasterRequest struct {
	Namespace string
	Link      string
	Master    string
	Up        bool
}

type pluginControlNetAddrRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
}

type pluginControlNetRouteRequest struct {
	Namespace string                         `json:"namespace,omitempty"`
	Dst       string                         `json:"dst"`
	Gateway   string                         `json:"gateway,omitempty"`
	Dev       string                         `json:"dev,omitempty"`
	Src       string                         `json:"src,omitempty"`
	Table     int                            `json:"table,omitempty"`
	Metric    int                            `json:"metric,omitempty"`
	Scope     int                            `json:"scope,omitempty"`
	Nexthops  []pluginControlNetRouteNexthop `json:"nexthops,omitempty"`
}

type pluginControlNetRouteNexthop struct {
	Gateway string `json:"gateway,omitempty"`
	Dev     string `json:"dev"`
	Weight  int    `json:"weight,omitempty"`
	Onlink  bool   `json:"onlink,omitempty"`
}

type pluginControlNetRouteNexthopState struct {
	Gateway    string `json:"gateway,omitempty"`
	Dev        string `json:"dev"`
	DevIfIndex int    `json:"dev_ifindex,omitempty"`
	Weight     int    `json:"weight"`
	Onlink     bool   `json:"onlink,omitempty"`
	Flags      int    `json:"flags,omitempty"`
}

type pluginControlNetRouteState struct {
	Namespace        string                              `json:"namespace,omitempty"`
	Dst              string                              `json:"dst"`
	Gateway          string                              `json:"gateway,omitempty"`
	Dev              string                              `json:"dev,omitempty"`
	DevIfIndex       int                                 `json:"dev_ifindex,omitempty"`
	Src              string                              `json:"src,omitempty"`
	Table            int                                 `json:"table"`
	Metric           int                                 `json:"metric,omitempty"`
	Scope            int                                 `json:"scope,omitempty"`
	Protocol         int                                 `json:"protocol,omitempty"`
	Type             int                                 `json:"type,omitempty"`
	TOS              int                                 `json:"tos,omitempty"`
	Flags            int                                 `json:"flags,omitempty"`
	Realm            int                                 `json:"realm,omitempty"`
	MTU              int                                 `json:"mtu,omitempty"`
	MTULock          bool                                `json:"mtu_lock,omitempty"`
	Window           int                                 `json:"window,omitempty"`
	RTT              int                                 `json:"rtt,omitempty"`
	RTTVar           int                                 `json:"rtt_var,omitempty"`
	SSThresh         int                                 `json:"ssthresh,omitempty"`
	Cwnd             int                                 `json:"cwnd,omitempty"`
	AdvMSS           int                                 `json:"adv_mss,omitempty"`
	Reordering       int                                 `json:"reordering,omitempty"`
	Hoplimit         int                                 `json:"hoplimit,omitempty"`
	InitCwnd         int                                 `json:"init_cwnd,omitempty"`
	Features         int                                 `json:"features,omitempty"`
	RtoMin           int                                 `json:"rto_min,omitempty"`
	RtoMinLock       bool                                `json:"rto_min_lock,omitempty"`
	InitRwnd         int                                 `json:"init_rwnd,omitempty"`
	QuickACK         int                                 `json:"quick_ack,omitempty"`
	Congctl          string                              `json:"congctl,omitempty"`
	FastOpenNoCookie int                                 `json:"fast_open_no_cookie,omitempty"`
	Nexthops         []pluginControlNetRouteNexthopState `json:"nexthops,omitempty"`
}

type pluginControlNetRuleRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Family    string `json:"family"`
	Priority  int    `json:"priority"`
	Table     int    `json:"table"`
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst,omitempty"`
	Mark      uint32 `json:"mark,omitempty"`
	Mask      uint32 `json:"mask,omitempty"`
	HasMask   bool   `json:"has_mask,omitempty"`
	IIF       string `json:"iif,omitempty"`
	OIF       string `json:"oif,omitempty"`
	Invert    bool   `json:"invert,omitempty"`
}

type pluginControlNetRuleState struct {
	Request  pluginControlNetRuleRequest `json:"request"`
	Protocol uint8                       `json:"protocol,omitempty"`
	Type     uint8                       `json:"type,omitempty"`
}

type pluginControlNetNeighRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state,omitempty"`
	VLAN      int    `json:"vlan,omitempty"`
}

type pluginControlNetNeighState struct {
	Request     pluginControlNetNeighRequest `json:"request"`
	Family      int                          `json:"family"`
	LinkIfIndex int                          `json:"link_ifindex"`
	Flags       int                          `json:"flags,omitempty"`
	FlagsExt    int                          `json:"flags_ext,omitempty"`
	Type        int                          `json:"type,omitempty"`
}

type pluginControlNetOffloadRequest struct {
	Namespace string
	Interface string
	Features  map[string]bool
}

type pluginControlNetGSORequest struct {
	Namespace string
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

func (h *pluginControlHost) netAdminInNamespaceOrThrow(namespace, operation string) pluginControlNetAdmin {
	admin := h.netAdminOrThrow(operation)
	namespace = h.requirePluginNetworkNamespace(namespace, operation)
	scoped, err := pluginControlNetAdminInNamespace(admin, namespace)
	if err != nil {
		h.throwf("%s: %v", operation, err)
	}
	return scoped
}

func (h *pluginControlHost) requirePluginNetworkNamespace(namespace, operation string) string {
	namespace, err := normalizePluginControlRequestNamespace(namespace)
	if err != nil {
		h.throwf("%s: %v", operation, err)
	}
	if namespace == "host" {
		return namespace
	}
	h.requireNamespaceAccess(namespace, operation)
	provider := h.networkProviderOrThrow("net.namespace", operation)
	if _, present, err := provider.NamespaceLookup(namespace); err != nil {
		h.throwf("%s: inspect namespace %s: %v", operation, namespace, err)
	} else if !present {
		h.throwf("%s: namespace %s does not exist", operation, namespace)
	}
	return namespace
}

func (h *pluginControlHost) netNamespaceObjectField(obj *goja.Object, operation string) string {
	namespace := h.firstStringObjectField(obj, "namespace", "netns")
	namespace, err := normalizePluginControlRequestNamespace(namespace)
	if err != nil {
		h.throwf("%s: %v", operation, err)
	}
	return namespace
}

func (h *pluginControlHost) netNamespaceArgument(call goja.FunctionCall, index int, operation string) string {
	if index >= len(call.Arguments) || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		return "host"
	}
	value := call.Arguments[index]
	namespace := ""
	if object := value.ToObject(h.vm); object != nil && object.ClassName() == "Object" {
		namespace = h.firstStringObjectField(object, "namespace", "netns")
	} else {
		namespace = strings.TrimSpace(value.String())
	}
	namespace, err := normalizePluginControlRequestNamespace(namespace)
	if err != nil {
		h.throwf("%s: %v", operation, err)
	}
	return namespace
}

func (h *pluginControlHost) throwPluginNetMutationError(api string, operationErr, rollbackErr error) {
	if rollbackErr != nil {
		h.throwf("%s: %v; rollback failed: %v", api, operationErr, rollbackErr)
	}
	h.throwf("%s: %v", api, operationErr)
}

func (h *pluginControlHost) requireNetAccess(operation string, interfaceName string, api string) {
	if !pluginControlHasNetAccess(h.plugin, operation, interfaceName) {
		h.throwf("%s: net_access operation %s on interface %s is not declared", api, operation, interfaceName)
	}
}

func (h *pluginControlHost) requireNetEndpointAccess(operation, interfaceName, host string, ip net.IP, port int, api string) pluginControlNetEndpointPolicy {
	policy, err := pluginControlNetEndpointPolicyFor(h.plugin, operation, interfaceName, host, ip, port)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return policy
}

func (h *pluginControlHost) requireAnyNetAccess(operation string, api string) {
	if !pluginControlHasAnyNetAccess(h.plugin, operation) {
		h.throwf("%s: net_access operation %s is not declared", api, operation)
	}
}

func (h *pluginControlHost) netLinkGet(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	namespace := h.netNamespaceArgument(call, 1, "net.link.get")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.get")
	h.requireNetAccess("link.read", name, "net.link.get")
	info, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.get: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLeaseList(goja.FunctionCall) goja.Value {
	h.netAdminOrThrow("net.lease.list")
	items, err := pluginOwnedResourceViews(h.db, h.plugin.ID)
	if err != nil {
		h.throwf("net.lease.list: %v", err)
	}
	return h.vm.ToValue(items)
}

func (h *pluginControlHost) netLeaseRestore(call goja.FunctionCall) goja.Value {
	admin := h.netAdminOrThrow("net.lease.restore")
	resourceType := strings.ToLower(h.requiredPluginLeaseStringArg(call, 0, "type", 64))
	resourceKey := h.requiredPluginLeaseStringArg(call, 1, "key", 512)
	if !validPluginOwnedResourceType(resourceType) {
		h.throwf("net.lease.restore: unsupported resource type %q", resourceType)
	}
	if len(resourceKey) > 512 || strings.ContainsRune(resourceKey, '\x00') {
		h.throwf("net.lease.restore: invalid resource key")
	}
	item, err := store.PluginOwnedResourceOrNil(h.db, resourceType, resourceKey)
	if err != nil {
		h.throwf("net.lease.restore: %v", err)
	}
	if item == nil {
		return h.vm.ToValue(map[string]any{"restored": false, "type": resourceType, "key": resourceKey})
	}
	if item.PluginID != h.plugin.ID {
		h.throwf("net.lease.restore: resource is owned by plugin %s", item.PluginID)
	}
	if err := restorePluginOwnedResource(admin, *item); err != nil {
		h.throwf("net.lease.restore: %v", err)
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, resourceType, resourceKey); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.throwf("net.lease.restore: clear lease: %v", err)
	}
	return h.vm.ToValue(map[string]any{"restored": true, "type": resourceType, "key": resourceKey})
}

func (h *pluginControlHost) requiredPluginLeaseStringArg(call goja.FunctionCall, index int, label string, maxBytes int) string {
	if index >= len(call.Arguments) || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("net.lease.restore: %s is required", label)
	}
	value := strings.TrimSpace(call.Arguments[index].String())
	if value == "" || len(value) > maxBytes || strings.ContainsRune(value, '\x00') {
		h.throwf("net.lease.restore: invalid %s", label)
	}
	return value
}

func (h *pluginControlHost) netLinkList(call goja.FunctionCall) goja.Value {
	namespace := h.netNamespaceArgument(call, 0, "net.link.list")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.list")
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
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetVethRequest{
		Namespace: h.netNamespaceObjectField(obj, "net.link.ensureVeth"),
		Host:      h.firstStringObjectField(obj, "host", "host_name", "name"),
		Peer:      h.firstStringObjectField(obj, "peer", "peer_name"),
		MTU:       h.optionalIntObjectField(obj, 0, "mtu"),
		Up:        true,
	}
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.link.ensureVeth")
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
	h.requirePluginLinkOwnershipAvailable(req.Namespace, req.Host, "net.link.ensureVeth")
	h.requirePluginLinkOwnershipAvailable(req.Namespace, req.Peer, "net.link.ensureVeth")
	hostSnapshot, hostRefs, err := h.preparePluginEnsureLinkMutation(admin, req.Host, req.MTU, req.Up, "net.link.ensureVeth")
	if err != nil {
		h.throwf("net.link.ensureVeth: inspect host state: %v", err)
	}
	peerSnapshot, peerRefs, err := h.preparePluginEnsureLinkMutation(admin, req.Peer, req.MTU, req.Up, "net.link.ensureVeth")
	refs := append(hostRefs, peerRefs...)
	snapshots := []pluginLinkMutationSnapshot{hostSnapshot, peerSnapshot}
	if err != nil {
		rollbackErr := h.rollbackPluginLinkSnapshots(admin, snapshots[:1], refs)
		h.throwPluginNetMutationError("net.link.ensureVeth", err, rollbackErr)
	}
	result, err := admin.LinkEnsureVeth(req)
	if err != nil {
		rollbackErr := h.rollbackPluginLinkSnapshots(admin, snapshots, refs)
		h.throwPluginNetMutationError("net.link.ensureVeth", err, rollbackErr)
	}
	if result.Created {
		if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
			_ = admin.LinkDelete(req.Host)
			h.throwf("net.link.ensureVeth: release provisional leases: %v", err)
		}
		if err := h.claimPluginOwnedLinks([]pluginOwnedLinkClaim{
			{Namespace: req.Namespace, Name: req.Host, Kind: "veth", Peer: req.Peer, IfIndex: result.Host.IfIndex, MAC: result.Host.MAC},
			{Namespace: req.Namespace, Name: req.Peer, Kind: "veth", Peer: req.Host, IfIndex: result.Peer.IfIndex, MAC: result.Peer.MAC},
		}); err != nil {
			_ = admin.LinkDelete(req.Host)
			h.throwf("net.link.ensureVeth: record ownership: %v", err)
		}
	}
	return h.vm.ToValue(map[string]any{
		"host":    pluginControlNetLinkInfoMap(result.Host),
		"peer":    pluginControlNetLinkInfoMap(result.Peer),
		"created": result.Created,
	})
}

func (h *pluginControlHost) netLinkEnsureDummy(call goja.FunctionCall) goja.Value {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetDummyRequest{
		Namespace: h.netNamespaceObjectField(obj, "net.link.ensureDummy"),
		Name:      h.firstStringObjectField(obj, "name", "interface", "link"),
		MTU:       h.optionalIntObjectField(obj, 0, "mtu"),
		Up:        true,
	}
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.link.ensureDummy")
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
	h.requirePluginLinkOwnershipAvailable(req.Namespace, req.Name, "net.link.ensureDummy")
	snapshot, refs, err := h.preparePluginEnsureLinkMutation(admin, req.Name, req.MTU, req.Up, "net.link.ensureDummy")
	if err != nil {
		h.throwf("net.link.ensureDummy: inspect current state: %v", err)
	}
	result, err := admin.LinkEnsureDummy(req)
	if err != nil {
		rollbackErr := h.rollbackPluginLinkSnapshots(admin, []pluginLinkMutationSnapshot{snapshot}, refs)
		h.throwPluginNetMutationError("net.link.ensureDummy", err, rollbackErr)
	}
	if result.Created {
		if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureDummy: release provisional leases: %v", err)
		}
		if err := h.claimPluginOwnedLinks([]pluginOwnedLinkClaim{{Namespace: req.Namespace, Name: req.Name, Kind: "dummy", IfIndex: result.Link.IfIndex, MAC: result.Link.MAC}}); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureDummy: record ownership: %v", err)
		}
	}
	return h.vm.ToValue(map[string]any{
		"link":    pluginControlNetLinkInfoMap(result.Link),
		"created": result.Created,
	})
}

func (h *pluginControlHost) netLinkEnsureMacvlan(call goja.FunctionCall) goja.Value {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetMacvlanRequest{
		Namespace: h.netNamespaceObjectField(obj, "net.link.ensureMacvlan"),
		Name:      h.firstStringObjectField(obj, "name", "interface", "link"),
		Parent:    h.firstStringObjectField(obj, "parent", "parent_interface", "physical_interface"),
		Mode:      strings.ToLower(h.firstStringObjectField(obj, "mode")),
		MAC:       h.firstStringObjectField(obj, "mac", "mac_address", "address"),
		MTU:       h.optionalIntObjectField(obj, 0, "mtu"),
		Up:        true,
	}
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.link.ensureMacvlan")
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
	h.requirePluginLinkOwnershipAvailable(req.Namespace, req.Name, "net.link.ensureMacvlan")
	snapshot, refs, err := h.preparePluginEnsureLinkMutation(admin, req.Name, req.MTU, req.Up, "net.link.ensureMacvlan")
	if err != nil {
		h.throwf("net.link.ensureMacvlan: inspect current state: %v", err)
	}
	result, err := admin.LinkEnsureMacvlan(req)
	if err != nil {
		rollbackErr := h.rollbackPluginLinkSnapshots(admin, []pluginLinkMutationSnapshot{snapshot}, refs)
		h.throwPluginNetMutationError("net.link.ensureMacvlan", err, rollbackErr)
	}
	if result.Created {
		if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureMacvlan: release provisional leases: %v", err)
		}
		if err := h.claimPluginOwnedLinks([]pluginOwnedLinkClaim{{Namespace: req.Namespace, Name: req.Name, Kind: "macvlan", Parent: req.Parent, IfIndex: result.Link.IfIndex, MAC: result.Link.MAC}}); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureMacvlan: record ownership: %v", err)
		}
	}
	return h.vm.ToValue(map[string]any{
		"link":    pluginControlNetLinkInfoMap(result.Link),
		"created": result.Created,
	})
}

func (h *pluginControlHost) netLinkEnsureVLAN(call goja.FunctionCall) goja.Value {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetVLANRequest{
		Namespace: h.netNamespaceObjectField(obj, "net.link.ensureVLAN"),
		Name:      h.firstStringObjectField(obj, "name", "interface", "link"),
		Parent:    h.firstStringObjectField(obj, "parent", "parent_interface", "physical_interface"),
		VLANID:    h.optionalIntObjectField(obj, 0, "vlan_id", "vid", "id"),
		Protocol:  strings.ToLower(h.firstStringObjectField(obj, "protocol")),
		MTU:       h.optionalIntObjectField(obj, 0, "mtu"),
		Up:        true,
	}
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.link.ensureVLAN")
	if req.Protocol == "" {
		req.Protocol = "802.1q"
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Name, "name"); err != nil {
		h.throwf("net.link.ensureVLAN: %v", err)
	}
	if err := validatePluginControlInterfaceName(req.Parent, "parent"); err != nil {
		h.throwf("net.link.ensureVLAN: %v", err)
	}
	if req.Name == req.Parent {
		h.throwf("net.link.ensureVLAN: name and parent must be different")
	}
	if req.VLANID < 1 || req.VLANID > 4094 {
		h.throwf("net.link.ensureVLAN: vlan_id must be between 1 and 4094")
	}
	if req.Protocol != "802.1q" && req.Protocol != "802.1ad" {
		h.throwf("net.link.ensureVLAN: protocol must be 802.1q or 802.1ad")
	}
	if req.MTU != 0 && (req.MTU < 576 || req.MTU > 65535) {
		h.throwf("net.link.ensureVLAN: mtu must be between 576 and 65535")
	}
	h.requireNetAccess("link.read", req.Parent, "net.link.ensureVLAN")
	h.requireNetAccess("link.create", req.Name, "net.link.ensureVLAN")
	h.requirePluginLinkOwnershipAvailable(req.Namespace, req.Name, "net.link.ensureVLAN")
	snapshot, refs, err := h.preparePluginEnsureLinkMutation(admin, req.Name, req.MTU, req.Up, "net.link.ensureVLAN")
	if err != nil {
		h.throwf("net.link.ensureVLAN: inspect current state: %v", err)
	}
	result, err := admin.LinkEnsureVLAN(req)
	if err != nil {
		rollbackErr := h.rollbackPluginLinkSnapshots(admin, []pluginLinkMutationSnapshot{snapshot}, refs)
		h.throwPluginNetMutationError("net.link.ensureVLAN", err, rollbackErr)
	}
	if result.Created {
		if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureVLAN: release provisional leases: %v", err)
		}
		if err := h.claimPluginOwnedLinks([]pluginOwnedLinkClaim{{Namespace: req.Namespace, Name: req.Name, Kind: "vlan", Parent: req.Parent, IfIndex: result.Link.IfIndex, MAC: result.Link.MAC}}); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureVLAN: record ownership: %v", err)
		}
	}
	return h.vm.ToValue(map[string]any{"link": pluginControlNetLinkInfoMap(result.Link), "created": result.Created})
}

func (h *pluginControlHost) netLinkEnsureVRF(call goja.FunctionCall) goja.Value {
	obj := h.requiredObjectArg(call, 0, "request")
	table := h.optionalIntObjectField(obj, 0, "table", "table_id")
	req := pluginControlNetVRFRequest{
		Namespace: h.netNamespaceObjectField(obj, "net.link.ensureVRF"),
		Name:      h.firstStringObjectField(obj, "name", "interface", "link"),
		Up:        true,
	}
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.link.ensureVRF")
	if table > 0 {
		req.Table = uint32(table)
	}
	if raw := h.objectField(obj, "up"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Up = raw.ToBoolean()
	}
	if err := validatePluginControlInterfaceName(req.Name, "name"); err != nil {
		h.throwf("net.link.ensureVRF: %v", err)
	}
	if table < 1 || uint64(table) > uint64(^uint32(0)) {
		h.throwf("net.link.ensureVRF: table must be between 1 and 4294967295")
	}
	h.requireNetAccess("link.create", req.Name, "net.link.ensureVRF")
	h.requirePluginLinkOwnershipAvailable(req.Namespace, req.Name, "net.link.ensureVRF")
	snapshot, refs, err := h.preparePluginEnsureLinkMutation(admin, req.Name, 0, req.Up, "net.link.ensureVRF")
	if err != nil {
		h.throwf("net.link.ensureVRF: inspect current state: %v", err)
	}
	result, err := admin.LinkEnsureVRF(req)
	if err != nil {
		rollbackErr := h.rollbackPluginLinkSnapshots(admin, []pluginLinkMutationSnapshot{snapshot}, refs)
		h.throwPluginNetMutationError("net.link.ensureVRF", err, rollbackErr)
	}
	if result.Created {
		if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureVRF: release provisional leases: %v", err)
		}
		if err := h.claimPluginOwnedLinks([]pluginOwnedLinkClaim{{Namespace: req.Namespace, Name: req.Name, Kind: "vrf", IfIndex: result.Link.IfIndex, MAC: result.Link.MAC}}); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureVRF: record ownership: %v", err)
		}
	}
	return h.vm.ToValue(map[string]any{"link": pluginControlNetLinkInfoMap(result.Link), "created": result.Created})
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
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetBridgeRequest{
		Namespace: h.netNamespaceObjectField(obj, "net.link.ensureBridge"),
		Name:      h.firstStringObjectField(obj, "name", "bridge", "interface"),
		MTU:       h.optionalIntObjectField(obj, 0, "mtu"),
		Up:        true,
	}
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.link.ensureBridge")
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
	h.requirePluginLinkOwnershipAvailable(req.Namespace, req.Name, "net.link.ensureBridge")
	snapshot, refs, err := h.preparePluginEnsureLinkMutation(admin, req.Name, req.MTU, req.Up, "net.link.ensureBridge")
	if err != nil {
		h.throwf("net.link.ensureBridge: inspect current state: %v", err)
	}
	info, err := admin.LinkEnsureBridge(req)
	if err != nil {
		rollbackErr := h.rollbackPluginLinkSnapshots(admin, []pluginLinkMutationSnapshot{snapshot}, refs)
		h.throwPluginNetMutationError("net.link.ensureBridge", err, rollbackErr)
	}
	if info.Created {
		if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureBridge: release provisional leases: %v", err)
		}
		if err := h.claimPluginOwnedLinks([]pluginOwnedLinkClaim{{Namespace: req.Namespace, Name: req.Name, Kind: "bridge", IfIndex: info.IfIndex, MAC: info.MAC}}); err != nil {
			_ = admin.LinkDelete(req.Name)
			h.throwf("net.link.ensureBridge: record ownership: %v", err)
		}
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkDelete(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	namespace := h.netNamespaceArgument(call, 1, "net.link.delete")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.delete")
	h.requireNetAccess("link.delete", name, "net.link.delete")
	owned := h.requirePluginLinkDeleteOwnership(namespace, name, "net.link.delete")
	if !owned {
		h.throwf("net.link.delete: only links created and owned by this plugin may be deleted")
	}
	if err := admin.LinkDelete(name); err != nil {
		h.throwf("net.link.delete: %v", err)
	}
	if err := h.releasePluginOwnedLink(namespace, name); err != nil {
		h.throwf("net.link.delete: clear ownership: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkRelease(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	namespace := h.netNamespaceArgument(call, 1, "net.link.release")
	h.netAdminInNamespaceOrThrow(namespace, "net.link.release")
	h.requireNetAccess("link.create", name, "net.link.release")
	if err := h.releasePluginOwnedLink(namespace, name); err != nil {
		h.throwf("net.link.release: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkOwned(goja.FunctionCall) goja.Value {
	h.netAdminOrThrow("net.link.owned")
	links, err := pluginOwnedLinks(h.db, h.plugin.ID)
	if err != nil {
		h.throwf("net.link.owned: %v", err)
	}
	return h.vm.ToValue(links)
}

func (h *pluginControlHost) netLinkSetMaster(call goja.FunctionCall) goja.Value {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetMasterRequest{
		Namespace: h.netNamespaceObjectField(obj, "net.link.setMaster"),
		Link:      h.firstStringObjectField(obj, "link", "interface", "dev", "name"),
		Master:    h.firstStringObjectField(obj, "master", "bridge"),
		Up:        true,
	}
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.link.setMaster")
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
	previous, err := admin.LinkGet(req.Link)
	if err != nil {
		h.throwf("net.link.setMaster: inspect current state: %v", err)
	}
	originals := make(map[string]any)
	if previous.MasterName != req.Master {
		originals["master"] = previous.MasterName
	}
	if req.Up && !previous.Up {
		originals["up"] = previous.Up
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.setMaster")
	if err != nil {
		h.throwf("net.link.setMaster: %v", err)
	}
	info, err := admin.LinkSetMaster(req)
	if err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.setMaster", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginLinkLease(req.Namespace, req.Link, "master", req.Master); err != nil {
		h.throwf("net.link.setMaster: release restored master lease: %v", err)
	}
	if req.Up {
		if err := h.releaseRestoredPluginLinkLease(req.Namespace, req.Link, "up", true); err != nil {
			h.throwf("net.link.setMaster: release restored state lease: %v", err)
		}
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkClearMaster(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	namespace := h.netNamespaceArgument(call, 1, "net.link.clearMaster")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.clearMaster")
	h.requireNetAccess("link.master", name, "net.link.clearMaster")
	previous, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.clearMaster: inspect current state: %v", err)
	}
	originals := make(map[string]any)
	if previous.MasterName != "" {
		originals["master"] = previous.MasterName
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.clearMaster")
	if err != nil {
		h.throwf("net.link.clearMaster: %v", err)
	}
	info, err := admin.LinkClearMaster(name)
	if err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.clearMaster", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginLinkLease(namespace, name, "master", ""); err != nil {
		h.throwf("net.link.clearMaster: release restored lease: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkSetUp(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	up := true
	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		up = call.Arguments[1].ToBoolean()
	}
	namespace := h.netNamespaceArgument(call, 2, "net.link.setUp")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.setUp")
	h.requireNetAccess("link.state", name, "net.link.setUp")
	previous, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.setUp: inspect current state: %v", err)
	}
	originals := make(map[string]any)
	if previous.Up != up {
		originals["up"] = previous.Up
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.setUp")
	if err != nil {
		h.throwf("net.link.setUp: %v", err)
	}
	if err := admin.LinkSetUp(name, up); err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.setUp", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginLinkLease(namespace, name, "up", up); err != nil {
		h.throwf("net.link.setUp: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkSetMTU(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setMTU: mtu is required")
	}
	mtu := int(call.Arguments[1].ToInteger())
	if mtu < 576 || mtu > 65535 {
		h.throwf("net.link.setMTU: mtu must be between 576 and 65535")
	}
	namespace := h.netNamespaceArgument(call, 2, "net.link.setMTU")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.setMTU")
	h.requireNetAccess("link.state", name, "net.link.setMTU")
	previous, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.setMTU: inspect current state: %v", err)
	}
	originals := make(map[string]any)
	if previous.MTU != mtu {
		originals["mtu"] = previous.MTU
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.setMTU")
	if err != nil {
		h.throwf("net.link.setMTU: %v", err)
	}
	if err := admin.LinkSetMTU(name, mtu); err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.setMTU", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginLinkLease(namespace, name, "mtu", mtu); err != nil {
		h.throwf("net.link.setMTU: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkSetARP(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setARP: enabled is required")
	}
	enabled := call.Arguments[1].ToBoolean()
	namespace := h.netNamespaceArgument(call, 2, "net.link.setARP")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.setARP")
	h.requireNetAccess("link.state", name, "net.link.setARP")
	previous, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.setARP: inspect current state: %v", err)
	}
	originals := make(map[string]any)
	if previous.ARP != enabled {
		originals["arp"] = previous.ARP
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.setARP")
	if err != nil {
		h.throwf("net.link.setARP: %v", err)
	}
	info, err := admin.LinkSetARP(name, enabled)
	if err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.setARP", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginLinkLease(namespace, name, "arp", enabled); err != nil {
		h.throwf("net.link.setARP: release restored lease: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkSetPromiscuous(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	if len(call.Arguments) <= 1 || goja.IsUndefined(call.Arguments[1]) || goja.IsNull(call.Arguments[1]) {
		h.throwf("net.link.setPromiscuous: enabled is required")
	}
	enabled := call.Arguments[1].ToBoolean()
	namespace := h.netNamespaceArgument(call, 2, "net.link.setPromiscuous")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.setPromiscuous")
	h.requireNetAccess("link.state", name, "net.link.setPromiscuous")
	previous, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.setPromiscuous: inspect current state: %v", err)
	}
	originals := make(map[string]any)
	if previous.Promiscuous != enabled {
		originals["promiscuous"] = previous.Promiscuous
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.setPromiscuous")
	if err != nil {
		h.throwf("net.link.setPromiscuous: %v", err)
	}
	info, err := admin.LinkSetPromiscuous(name, enabled)
	if err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.setPromiscuous", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginLinkLease(namespace, name, "promiscuous", enabled); err != nil {
		h.throwf("net.link.setPromiscuous: release restored lease: %v", err)
	}
	return h.vm.ToValue(pluginControlNetLinkInfoMap(info))
}

func (h *pluginControlHost) netLinkSetOffloads(call goja.FunctionCall) goja.Value {
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
	namespace := h.netNamespaceArgument(call, 2, "net.link.setOffloads")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.setOffloads")
	h.requireNetAccess("link.offload", name, "net.link.setOffloads")
	previous, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.setOffloads: inspect current link: %v", err)
	}
	current, err := admin.LinkGetOffloads(name)
	if err != nil {
		h.throwf("net.link.setOffloads: inspect current features: %v", err)
	}
	owned, err := h.pluginOwnedLinkState(namespace, name, "net.link.setOffloads")
	if err != nil {
		h.throwf("net.link.setOffloads: %v", err)
	}
	originals := make(map[string]any)
	for feature, desired := range features {
		value, ok := current[feature]
		if !ok && !owned {
			h.throwf("net.link.setOffloads: current %s state is unavailable; refusing an untracked host-interface mutation", feature)
		}
		if ok && value != desired {
			originals["offload."+feature] = value
		}
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.setOffloads")
	if err != nil {
		h.throwf("net.link.setOffloads: %v", err)
	}
	if err := admin.LinkSetOffloads(pluginControlNetOffloadRequest{Namespace: namespace, Interface: name, Features: features}); err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.setOffloads", err, rollbackErr)
	}
	for feature, desired := range features {
		if err := h.releaseRestoredPluginLinkLease(namespace, name, "offload."+feature, desired); err != nil {
			h.throwf("net.link.setOffloads: release restored %s lease: %v", feature, err)
		}
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netLinkGetOffloads(call goja.FunctionCall) goja.Value {
	name := h.requiredNetStringArg(call, 0, "name")
	namespace := h.netNamespaceArgument(call, 1, "net.link.getOffloads")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.getOffloads")
	h.requireNetAccess("link.read", name, "net.link.getOffloads")
	features, err := admin.LinkGetOffloads(name)
	if err != nil {
		h.throwf("net.link.getOffloads: %v", err)
	}
	return h.vm.ToValue(features)
}

func (h *pluginControlHost) netLinkSetGSO(call goja.FunctionCall) goja.Value {
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
	namespace := h.netNamespaceArgument(call, 2, "net.link.setGSO")
	admin := h.netAdminInNamespaceOrThrow(namespace, "net.link.setGSO")
	h.requireNetAccess("link.offload", name, "net.link.setGSO")
	previous, err := admin.LinkGet(name)
	if err != nil {
		h.throwf("net.link.setGSO: inspect current state: %v", err)
	}
	originals := make(map[string]any)
	if previous.GSOMaxSize != maxSize || previous.GSOMaxSegs != maxSegs {
		owned, ownershipErr := h.pluginOwnedLinkState(namespace, name, "net.link.setGSO")
		if ownershipErr != nil {
			h.throwf("net.link.setGSO: %v", ownershipErr)
		}
		if !owned && (previous.GSOMaxSize < 576 || previous.GSOMaxSegs < 1) {
			h.throwf("net.link.setGSO: current GSO limits are unavailable; refusing an untracked host-interface mutation")
		}
		originals["gso"] = pluginControlNetGSORequest{Interface: name, MaxSize: previous.GSOMaxSize, MaxSegs: previous.GSOMaxSegs}
	}
	refs, err := h.claimPluginLinkMutations(previous, originals, "net.link.setGSO")
	if err != nil {
		h.throwf("net.link.setGSO: %v", err)
	}
	info, err := admin.LinkSetGSO(pluginControlNetGSORequest{Namespace: namespace, Interface: name, MaxSize: maxSize, MaxSegs: maxSegs})
	if err != nil {
		rollbackErr := h.rollbackNewPluginResourceClaims(admin, previous, originals, refs)
		h.throwPluginNetMutationError("net.link.setGSO", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginLinkLease(namespace, name, "gso", pluginControlNetGSORequest{Namespace: namespace, Interface: name, MaxSize: maxSize, MaxSegs: maxSegs}); err != nil {
		h.throwf("net.link.setGSO: release restored lease: %v", err)
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
	req := h.netAddrRequest(call, "net.addr.replace")
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.addr.replace")
	h.requireNetAccess("addr.write", req.Interface, "net.addr.replace")
	previous, err := admin.LinkGet(req.Interface)
	if err != nil {
		h.throwf("net.addr.replace: inspect current state: %v", err)
	}
	if _, err := h.pluginOwnedLinkState(req.Namespace, req.Interface, "net.addr.replace"); err != nil {
		h.throwf("net.addr.replace: %v", err)
	}
	normalized, err := normalizePluginControlAddressRequest(req)
	if err != nil {
		h.throwf("net.addr.replace: %v", err)
	}
	originalPresent := pluginControlNetLinkHasAddress(previous, normalized.CIDR)
	refs := []pluginOwnedResourceRef(nil)
	if !originalPresent {
		refs, normalized, err = h.claimPluginAddressMutation(previous, normalized, false, "net.addr.replace")
		if err != nil {
			h.throwf("net.addr.replace: %v", err)
		}
	}
	if err := admin.AddrReplace(normalized); err != nil {
		rollbackErr := h.rollbackPluginAddressOperation(admin, normalized, originalPresent, refs)
		h.throwPluginNetMutationError("net.addr.replace", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginAddressLease(normalized, true); err != nil {
		h.throwf("net.addr.replace: release restored lease: %v", err)
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
	req := h.netAddrRequest(call, "net.addr.delete")
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.addr.delete")
	h.requireNetAccess("addr.write", req.Interface, "net.addr.delete")
	previous, err := admin.LinkGet(req.Interface)
	if err != nil {
		h.throwf("net.addr.delete: inspect current state: %v", err)
	}
	if _, err := h.pluginOwnedLinkState(req.Namespace, req.Interface, "net.addr.delete"); err != nil {
		h.throwf("net.addr.delete: %v", err)
	}
	normalized, err := normalizePluginControlAddressRequest(req)
	if err != nil {
		h.throwf("net.addr.delete: %v", err)
	}
	originalPresent := pluginControlNetLinkHasAddress(previous, normalized.CIDR)
	refs := []pluginOwnedResourceRef(nil)
	if originalPresent {
		refs, normalized, err = h.claimPluginAddressMutation(previous, normalized, true, "net.addr.delete")
		if err != nil {
			h.throwf("net.addr.delete: %v", err)
		}
	}
	if err := admin.AddrDelete(normalized); err != nil {
		rollbackErr := h.rollbackPluginAddressOperation(admin, normalized, originalPresent, refs)
		h.throwPluginNetMutationError("net.addr.delete", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginAddressLease(normalized, false); err != nil {
		h.throwf("net.addr.delete: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func pluginControlNetLinkHasAddress(info pluginControlNetLinkInfo, cidr string) bool {
	for _, address := range info.Addresses {
		normalized, err := normalizePluginControlAddressRequest(pluginControlNetAddrRequest{Interface: info.Name, CIDR: address})
		if err == nil && normalized.CIDR == cidr {
			return true
		}
	}
	return false
}

func (h *pluginControlHost) netRouteReplace(call goja.FunctionCall) goja.Value {
	req := h.netRouteRequest(call, "net.route.replace")
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.route.replace")
	h.requireRouteNetAccess(req, "net.route.replace")
	identities, err := h.pluginRouteLinkIdentities(admin, req, "net.route.replace")
	if err != nil {
		h.throwf("net.route.replace: %v", err)
	}
	original, err := admin.RouteSnapshot(req)
	if err != nil {
		h.throwf("net.route.replace: snapshot current route: %v", err)
	}
	previous, created, leased, err := h.claimPluginRouteMutation(req, true, original, identities)
	if err != nil {
		h.throwf("net.route.replace: %v", err)
	}
	if err := admin.RouteReplace(req); err != nil {
		var rollbackErr error
		if leased {
			rollbackErr = h.rollbackPluginRouteOperation(admin, req, true, previous, created)
		}
		h.throwPluginNetMutationError("net.route.replace", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginRouteLease(req, true); err != nil {
		h.throwf("net.route.replace: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netRouteDelete(call goja.FunctionCall) goja.Value {
	req := h.netRouteRequest(call, "net.route.delete")
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.route.delete")
	h.requireRouteNetAccess(req, "net.route.delete")
	identities, err := h.pluginRouteLinkIdentities(admin, req, "net.route.delete")
	if err != nil {
		h.throwf("net.route.delete: %v", err)
	}
	original, err := admin.RouteSnapshot(req)
	if err != nil {
		h.throwf("net.route.delete: snapshot current route: %v", err)
	}
	if len(original) == 0 {
		if err := admin.RouteDelete(req); err != nil {
			h.throwf("net.route.delete: %v", err)
		}
		if err := h.releaseRestoredPluginRouteLease(req, false); err != nil {
			h.throwf("net.route.delete: release restored lease: %v", err)
		}
		return goja.Undefined()
	}
	previous, created, leased, err := h.claimPluginRouteMutation(req, false, original, identities)
	if err != nil {
		h.throwf("net.route.delete: %v", err)
	}
	if err := admin.RouteDelete(req); err != nil {
		var rollbackErr error
		if leased {
			rollbackErr = h.rollbackPluginRouteOperation(admin, req, false, previous, created)
		}
		h.throwPluginNetMutationError("net.route.delete", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginRouteLease(req, false); err != nil {
		h.throwf("net.route.delete: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) pluginRouteLinkIdentities(admin pluginControlNetAdmin, req pluginControlNetRouteRequest, operation string) ([]pluginOwnedRouteLinkIdentity, error) {
	interfaces := pluginControlNetRouteInterfaces(req)
	identities := make([]pluginOwnedRouteLinkIdentity, 0, len(interfaces))
	for _, interfaceName := range interfaces {
		link, err := admin.LinkGet(interfaceName)
		if err != nil {
			return nil, fmt.Errorf("inspect route interface %s: %w", interfaceName, err)
		}
		if _, err := h.pluginOwnedLinkState(req.Namespace, interfaceName, operation); err != nil {
			return nil, err
		}
		identities = append(identities, pluginOwnedRouteLinkIdentity{Dev: interfaceName, IfIndex: link.IfIndex})
	}
	return identities, nil
}

func (h *pluginControlHost) netRuleReplace(call goja.FunctionCall) goja.Value {
	req := h.netRuleRequest(call, "net.rule.replace")
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.rule.replace")
	h.requireRuleNetAccess(req, "net.rule.replace")
	original, err := admin.RuleSnapshot(req)
	if err != nil {
		h.throwf("net.rule.replace: snapshot current policy rule: %v", err)
	}
	previous, created, err := h.claimPluginRuleMutation(req, true, original)
	if err != nil {
		h.throwf("net.rule.replace: %v", err)
	}
	if err := admin.RuleReplace(req); err != nil {
		rollbackErr := h.rollbackPluginRuleOperation(admin, req, true, previous, created)
		h.throwPluginNetMutationError("net.rule.replace", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginRuleLease(req, true); err != nil {
		h.throwf("net.rule.replace: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netRuleDelete(call goja.FunctionCall) goja.Value {
	req := h.netRuleRequest(call, "net.rule.delete")
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.rule.delete")
	h.requireRuleNetAccess(req, "net.rule.delete")
	original, err := admin.RuleSnapshot(req)
	if err != nil {
		h.throwf("net.rule.delete: snapshot current policy rule: %v", err)
	}
	if len(original) == 0 {
		if err := admin.RuleDelete(req); err != nil {
			h.throwf("net.rule.delete: %v", err)
		}
		if err := h.releaseRestoredPluginRuleLease(req, false); err != nil {
			h.throwf("net.rule.delete: release restored lease: %v", err)
		}
		return goja.Undefined()
	}
	previous, created, err := h.claimPluginRuleMutation(req, false, original)
	if err != nil {
		h.throwf("net.rule.delete: %v", err)
	}
	if err := admin.RuleDelete(req); err != nil {
		rollbackErr := h.rollbackPluginRuleOperation(admin, req, false, previous, created)
		h.throwPluginNetMutationError("net.rule.delete", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginRuleLease(req, false); err != nil {
		h.throwf("net.rule.delete: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netNeighReplace(call goja.FunctionCall) goja.Value {
	req := h.netNeighRequest(call, "net.neigh.replace", true)
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.neigh.replace")
	h.requireNetAccess("neigh.write", req.Interface, "net.neigh.replace")
	dev, err := admin.LinkGet(req.Interface)
	if err != nil {
		h.throwf("net.neigh.replace: inspect neighbor interface: %v", err)
	}
	if _, err := h.pluginOwnedLinkState(req.Namespace, req.Interface, "net.neigh.replace"); err != nil {
		h.throwf("net.neigh.replace: %v", err)
	}
	original, err := admin.NeighSnapshot(req)
	if err != nil {
		h.throwf("net.neigh.replace: snapshot current neighbor: %v", err)
	}
	previous, created, leased, err := h.claimPluginNeighMutation(req, true, original, dev.IfIndex)
	if err != nil {
		h.throwf("net.neigh.replace: %v", err)
	}
	if err := admin.NeighReplace(req); err != nil {
		var rollbackErr error
		if leased {
			rollbackErr = h.rollbackPluginNeighOperation(admin, req, true, previous, created)
		}
		h.throwPluginNetMutationError("net.neigh.replace", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginNeighLease(req, true); err != nil {
		h.throwf("net.neigh.replace: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) netNeighDelete(call goja.FunctionCall) goja.Value {
	req := h.netNeighRequest(call, "net.neigh.delete", false)
	admin := h.netAdminInNamespaceOrThrow(req.Namespace, "net.neigh.delete")
	h.requireNetAccess("neigh.write", req.Interface, "net.neigh.delete")
	dev, err := admin.LinkGet(req.Interface)
	if err != nil {
		h.throwf("net.neigh.delete: inspect neighbor interface: %v", err)
	}
	if _, err := h.pluginOwnedLinkState(req.Namespace, req.Interface, "net.neigh.delete"); err != nil {
		h.throwf("net.neigh.delete: %v", err)
	}
	original, err := admin.NeighSnapshot(req)
	if err != nil {
		h.throwf("net.neigh.delete: snapshot current neighbor: %v", err)
	}
	if len(original) == 0 {
		if err := admin.NeighDelete(req); err != nil {
			h.throwf("net.neigh.delete: %v", err)
		}
		if err := h.releaseRestoredPluginNeighLease(req, false); err != nil {
			h.throwf("net.neigh.delete: release restored lease: %v", err)
		}
		return goja.Undefined()
	}
	previous, created, leased, err := h.claimPluginNeighMutation(req, false, original, dev.IfIndex)
	if err != nil {
		h.throwf("net.neigh.delete: %v", err)
	}
	if err := admin.NeighDelete(req); err != nil {
		var rollbackErr error
		if leased {
			rollbackErr = h.rollbackPluginNeighOperation(admin, req, false, previous, created)
		}
		h.throwPluginNetMutationError("net.neigh.delete", err, rollbackErr)
	}
	if err := h.releaseRestoredPluginNeighLease(req, false); err != nil {
		h.throwf("net.neigh.delete: release restored lease: %v", err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) requireRouteNetAccess(req pluginControlNetRouteRequest, operation string) {
	interfaces := pluginControlNetRouteInterfaces(req)
	if len(interfaces) == 0 {
		h.throwf("%s: dev or nexthops is required for route.write net_access", operation)
		return
	}
	for _, interfaceName := range interfaces {
		h.requireNetAccess("route.write", interfaceName, operation)
	}
}

func (h *pluginControlHost) requireRuleNetAccess(req pluginControlNetRuleRequest, operation string) {
	interfaces := []string{}
	if req.IIF != "" {
		interfaces = append(interfaces, req.IIF)
	}
	if req.OIF != "" && req.OIF != req.IIF {
		interfaces = append(interfaces, req.OIF)
	}
	if len(interfaces) == 0 {
		h.requireAnyNetAccess("rule.write", operation)
		return
	}
	for _, name := range interfaces {
		h.requireNetAccess("rule.write", name, operation)
	}
}

func (h *pluginControlHost) netAddrRequest(call goja.FunctionCall, operation string) pluginControlNetAddrRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetAddrRequest{
		Namespace: h.netNamespaceObjectField(obj, operation),
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
		Namespace: h.netNamespaceObjectField(obj, operation),
		Dst:       h.firstStringObjectField(obj, "dst", "destination", "cidr"),
		Gateway:   h.firstStringObjectField(obj, "gateway", "gw"),
		Dev:       h.firstStringObjectField(obj, "dev", "interface", "link"),
		Src:       h.firstStringObjectField(obj, "src", "source"),
		Table:     h.optionalIntObjectField(obj, 0, "table"),
		Metric:    h.optionalIntObjectField(obj, 0, "metric"),
		Scope:     h.optionalIntObjectField(obj, 0, "scope"),
		Nexthops:  h.netRouteNexthops(obj, operation),
	}
	if len(req.Nexthops) == 0 && strings.TrimSpace(req.Dev) == "" {
		h.throwf("%s: dev is required for route.write net_access", operation)
	}
	normalized, err := validatePluginControlRouteRequest(req)
	if err != nil {
		h.throwf("%s: %v", operation, err)
	}
	return normalized
}

func (h *pluginControlHost) netRouteNexthops(obj *goja.Object, operation string) []pluginControlNetRouteNexthop {
	value := h.objectField(obj, "nexthops")
	if goja.IsUndefined(value) || goja.IsNull(value) {
		value = h.objectField(obj, "next_hops")
	}
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil
	}
	array := value.ToObject(h.vm)
	if array.ClassName() != "Array" {
		h.throwf("%s: nexthops must be an array", operation)
	}
	length := int(array.Get("length").ToInteger())
	if length < 1 || length > pluginControlNetMaxRouteNexthops {
		h.throwf("%s: nexthops count must be between 1 and %d", operation, pluginControlNetMaxRouteNexthops)
	}
	out := make([]pluginControlNetRouteNexthop, 0, length)
	for index := 0; index < length; index++ {
		itemValue := array.Get(fmt.Sprintf("%d", index))
		if itemValue == nil || goja.IsUndefined(itemValue) || goja.IsNull(itemValue) {
			h.throwf("%s: nexthop %d is missing", operation, index)
		}
		item := itemValue.ToObject(h.vm)
		if item.ClassName() != "Object" {
			h.throwf("%s: nexthop %d must be an object", operation, index)
		}
		nexthop := pluginControlNetRouteNexthop{
			Gateway: h.firstStringObjectField(item, "gateway", "gw"),
			Dev:     h.firstStringObjectField(item, "dev", "interface", "link"),
			Weight:  h.optionalIntObjectField(item, 1, "weight"),
		}
		if raw := h.objectField(item, "onlink"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
			nexthop.Onlink = raw.ToBoolean()
		}
		out = append(out, nexthop)
	}
	return out
}

func (h *pluginControlHost) netRuleRequest(call goja.FunctionCall, operation string) pluginControlNetRuleRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	mark, hasMark := h.optionalUint32ObjectField(obj, operation, "mark", "fwmark")
	mask, hasMask := h.optionalUint32ObjectField(obj, operation, "mask", "fwmask")
	if hasMask && !hasMark {
		h.throwf("%s: mask requires mark", operation)
	}
	req := pluginControlNetRuleRequest{
		Namespace: h.netNamespaceObjectField(obj, operation),
		Family:    h.firstStringObjectField(obj, "family"),
		Priority:  h.optionalIntObjectField(obj, 0, "priority", "pref"),
		Table:     h.optionalIntObjectField(obj, 0, "table", "table_id"),
		Src:       h.firstStringObjectField(obj, "src", "source", "from"),
		Dst:       h.firstStringObjectField(obj, "dst", "destination", "to"),
		Mark:      mark,
		Mask:      mask,
		HasMask:   hasMask,
		IIF:       h.firstStringObjectField(obj, "iif", "in_interface"),
		OIF:       h.firstStringObjectField(obj, "oif", "out_interface"),
	}
	if raw := h.objectField(obj, "invert"); !goja.IsUndefined(raw) && !goja.IsNull(raw) {
		req.Invert = raw.ToBoolean()
	}
	if req.Priority < 1 || req.Priority > 32765 {
		h.throwf("%s: priority must be between 1 and 32765", operation)
	}
	if req.Table < 1 {
		h.throwf("%s: table must be positive", operation)
	}
	if req.IIF != "" {
		if err := validatePluginControlInterfaceName(req.IIF, "iif"); err != nil {
			h.throwf("%s: %v", operation, err)
		}
	}
	if req.OIF != "" {
		if err := validatePluginControlInterfaceName(req.OIF, "oif"); err != nil {
			h.throwf("%s: %v", operation, err)
		}
	}
	normalized, err := normalizePluginControlRuleRequest(req)
	if err != nil {
		h.throwf("%s: %v", operation, err)
	}
	return normalized
}

func (h *pluginControlHost) netNeighRequest(call goja.FunctionCall, operation string, requireMAC bool) pluginControlNetNeighRequest {
	obj := h.requiredObjectArg(call, 0, "request")
	req := pluginControlNetNeighRequest{
		Namespace: h.netNamespaceObjectField(obj, operation),
		Interface: h.firstStringObjectField(obj, "interface", "dev", "link"),
		IP:        h.firstStringObjectField(obj, "ip", "address"),
		MAC:       h.firstStringObjectField(obj, "mac", "lladdr"),
		State:     h.firstStringObjectField(obj, "state"),
		VLAN:      h.optionalIntObjectField(obj, 0, "vlan", "vlan_id"),
	}
	if err := validatePluginControlInterfaceName(req.Interface, "interface"); err != nil {
		h.throwf("%s: %v", operation, err)
	}
	normalized, err := normalizePluginControlNeighRequest(req, requireMAC)
	if err != nil {
		h.throwf("%s: %v", operation, err)
	}
	return normalized
}

func (h *pluginControlHost) optionalUint32ObjectField(obj *goja.Object, operation string, names ...string) (uint32, bool) {
	for _, name := range names {
		value := h.objectField(obj, name)
		if goja.IsUndefined(value) || goja.IsNull(value) {
			continue
		}
		integer := value.ToInteger()
		if integer < 0 || uint64(integer) > uint64(^uint32(0)) {
			h.throwf("%s: %s must be between 0 and 4294967295", operation, name)
		}
		return uint32(integer), true
	}
	return 0, false
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
		"namespace":      normalizePluginControlNamespace(info.Namespace),
		"name":           info.Name,
		"created":        info.Created,
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
		"vlan_id":        info.VLANID,
		"vlan_protocol":  info.VLANProtocol,
		"vrf_table":      info.VRFTable,
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
