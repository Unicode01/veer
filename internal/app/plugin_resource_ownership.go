package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const (
	pluginOwnedResourceTypeLink        = "net.link"
	pluginOwnedResourceTypeLinkState   = "net.link.state"
	pluginOwnedResourceTypeLinkOffload = "net.link.offload"
	pluginOwnedResourceTypeAddress     = "net.addr"
	pluginOwnedResourceTypeRoute       = "net.route"
	pluginOwnedResourceTypeRule        = "net.rule"
	pluginOwnedResourceTypeNeighbor    = "net.neigh"
	pluginOwnedResourceTypeTunTap      = "net.tuntap"
	pluginOwnedResourceTypeNamespace   = "net.namespace"
)

type pluginOwnedLinkClaim struct {
	BootID            string                            `json:"boot_id,omitempty"`
	Namespace         string                            `json:"namespace,omitempty"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`
	Name              string                            `json:"name"`
	Kind              string                            `json:"kind"`
	Peer              string                            `json:"peer,omitempty"`
	Parent            string                            `json:"parent,omitempty"`
	IfIndex           int                               `json:"ifindex,omitempty"`
	MAC               string                            `json:"mac,omitempty"`
}

type pluginOwnedResourceClaim struct {
	ResourceType string
	ResourceKey  string
	Metadata     any
}

type pluginOwnedResourceRef struct {
	ResourceType string
	ResourceKey  string
}

type pluginLinkMutationSnapshot struct {
	Info      pluginControlNetLinkInfo
	Present   bool
	Originals map[string]any
}

type pluginOwnedLinkMutation struct {
	Version           int                               `json:"version"`
	BootID            string                            `json:"boot_id,omitempty"`
	Namespace         string                            `json:"namespace,omitempty"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`
	Interface         string                            `json:"interface"`
	Property          string                            `json:"property"`
	Original          json.RawMessage                   `json:"original"`
	OriginalIfIndex   int                               `json:"original_ifindex,omitempty"`
	OriginalKind      string                            `json:"original_kind,omitempty"`
	OriginalMAC       string                            `json:"original_mac,omitempty"`
}

type pluginOwnedAddressMutation struct {
	Version           int                               `json:"version"`
	BootID            string                            `json:"boot_id,omitempty"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`
	Request           pluginControlNetAddrRequest       `json:"request"`
	OriginalPresent   bool                              `json:"original_present"`
	OriginalIfIndex   int                               `json:"original_ifindex,omitempty"`
	OriginalKind      string                            `json:"original_kind,omitempty"`
	OriginalMAC       string                            `json:"original_mac,omitempty"`
}

type pluginOwnedRouteMutation struct {
	Version           int                               `json:"version"`
	BootID            string                            `json:"boot_id,omitempty"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`
	Current           pluginControlNetRouteRequest      `json:"current"`
	CurrentPresent    bool                              `json:"current_present"`
	Original          []pluginControlNetRouteState      `json:"original,omitempty"`
	DevIfIndex        int                               `json:"dev_ifindex,omitempty"`
	LinkIdentities    []pluginOwnedRouteLinkIdentity    `json:"link_identities,omitempty"`
}

type pluginOwnedRouteLinkIdentity struct {
	Dev     string `json:"dev"`
	IfIndex int    `json:"ifindex"`
}

type pluginOwnedRuleMutation struct {
	Version           int                               `json:"version"`
	BootID            string                            `json:"boot_id,omitempty"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`
	Current           pluginControlNetRuleRequest       `json:"current"`
	CurrentPresent    bool                              `json:"current_present"`
	Original          []pluginControlNetRuleState       `json:"original,omitempty"`
}

type pluginOwnedNeighMutation struct {
	Version           int                               `json:"version"`
	BootID            string                            `json:"boot_id,omitempty"`
	NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity,omitempty"`
	Current           pluginControlNetNeighRequest      `json:"current"`
	CurrentPresent    bool                              `json:"current_present"`
	Original          []pluginControlNetNeighState      `json:"original,omitempty"`
	DevIfIndex        int                               `json:"dev_ifindex,omitempty"`
}

var pluginOwnershipBootID = readPluginOwnershipBootID()

func readPluginOwnershipBootID() string {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(raw))
	if len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	return value
}

func pluginControlNetScopedResourceKey(namespace, key string) string {
	namespace = normalizePluginControlNamespace(namespace)
	key = strings.TrimSpace(key)
	if namespace == "host" {
		return key
	}
	return namespace + "/" + key
}

func (h *pluginControlHost) pluginControlNamespaceIdentity(namespace string) (pluginControlNetNamespaceIdentity, error) {
	namespace = normalizePluginControlNamespace(namespace)
	if namespace == "host" {
		return pluginControlNetNamespaceIdentity{}, nil
	}
	provider, ok := h.netAdmin.(pluginControlNetworkProvider)
	if !ok || provider == nil {
		return pluginControlNetNamespaceIdentity{}, fmt.Errorf("network namespace provider is unavailable")
	}
	info, present, err := provider.NamespaceLookup(namespace)
	if err != nil {
		return pluginControlNetNamespaceIdentity{}, err
	}
	if !present {
		return pluginControlNetNamespaceIdentity{}, fmt.Errorf("namespace %s does not exist", namespace)
	}
	return info.Identity, nil
}

func (h *pluginControlHost) requirePluginLinkOwnershipAvailable(namespace, name, api string) {
	if h.db == nil {
		h.throwf("%s: plugin ownership store is unavailable", api)
	}
	key := pluginControlNetScopedResourceKey(namespace, name)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeLink, key)
	if err != nil {
		h.throwf("%s: inspect link ownership: %v", api, err)
	}
	if owned != nil && owned.PluginID != h.plugin.ID {
		h.throwf("%s: link %s is owned by plugin %s", api, name, owned.PluginID)
	}
}

func (h *pluginControlHost) requirePluginLinkDeleteOwnership(namespace, name, api string) bool {
	if h.db == nil {
		h.throwf("%s: plugin ownership store is unavailable", api)
	}
	key := pluginControlNetScopedResourceKey(namespace, name)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeLink, key)
	if err != nil {
		h.throwf("%s: inspect link ownership: %v", api, err)
	}
	if owned == nil {
		return false
	}
	if owned.PluginID != h.plugin.ID {
		h.throwf("%s: link %s is owned by plugin %s", api, name, owned.PluginID)
	}
	return true
}

func (h *pluginControlHost) pluginOwnedLinkState(namespace, name, api string) (bool, error) {
	if h.db == nil {
		return false, fmt.Errorf("%s: plugin ownership store is unavailable", api)
	}
	key := pluginControlNetScopedResourceKey(namespace, name)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeLink, key)
	if err != nil {
		return false, fmt.Errorf("%s: inspect link ownership: %w", api, err)
	}
	if owned == nil {
		return false, nil
	}
	if owned.PluginID != h.plugin.ID {
		return false, fmt.Errorf("%s: link %s is owned by plugin %s", api, name, owned.PluginID)
	}
	return true, nil
}

func (h *pluginControlHost) claimPluginOwnedResources(claims []pluginOwnedResourceClaim) ([]pluginOwnedResourceRef, error) {
	if h.db == nil {
		return nil, fmt.Errorf("plugin ownership store is unavailable")
	}
	if len(claims) == 0 {
		return nil, nil
	}
	tx, err := h.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	newlyClaimed := make([]pluginOwnedResourceRef, 0, len(claims))
	seen := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		key := claim.ResourceType + "\x00" + claim.ResourceKey
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		metadata, err := json.Marshal(claim.Metadata)
		if err != nil {
			return nil, err
		}
		existing, err := store.PluginOwnedResourceOrNil(tx, claim.ResourceType, claim.ResourceKey)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			if existing.PluginID != h.plugin.ID {
				return nil, fmt.Errorf("%s %s is owned by plugin %s", claim.ResourceType, claim.ResourceKey, existing.PluginID)
			}
			if pluginOwnedResourceGenerationChanged(existing.MetadataJSON, metadata) {
				if err := store.UpdatePluginOwnedResource(tx, h.plugin.ID, claim.ResourceType, claim.ResourceKey, string(metadata)); err != nil {
					return nil, err
				}
				newlyClaimed = append(newlyClaimed, pluginOwnedResourceRef{ResourceType: claim.ResourceType, ResourceKey: claim.ResourceKey})
			}
			continue
		}
		if err := store.AddPluginOwnedResource(tx, store.PluginOwnedResource{
			PluginID: h.plugin.ID, ResourceType: claim.ResourceType, ResourceKey: claim.ResourceKey, MetadataJSON: string(metadata),
		}); err != nil {
			return nil, err
		}
		newlyClaimed = append(newlyClaimed, pluginOwnedResourceRef{ResourceType: claim.ResourceType, ResourceKey: claim.ResourceKey})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return newlyClaimed, nil
}

func pluginOwnedResourceGenerationChanged(previous string, next []byte) bool {
	type generation struct {
		BootID            string                            `json:"boot_id"`
		Namespace         string                            `json:"namespace"`
		NamespaceIdentity pluginControlNetNamespaceIdentity `json:"namespace_identity"`
		IfIndex           int                               `json:"ifindex"`
		OriginalIfIndex   int                               `json:"original_ifindex"`
		DevIfIndex        int                               `json:"dev_ifindex"`
		Kind              string                            `json:"kind"`
		OriginalKind      string                            `json:"original_kind"`
		MAC               string                            `json:"mac"`
		OriginalMAC       string                            `json:"original_mac"`
		LinkIdentities    []pluginOwnedRouteLinkIdentity    `json:"link_identities"`
	}
	var oldGeneration, newGeneration generation
	if json.Unmarshal([]byte(previous), &oldGeneration) != nil || json.Unmarshal(next, &newGeneration) != nil {
		return false
	}
	if oldGeneration.BootID != "" && newGeneration.BootID != "" && oldGeneration.BootID != newGeneration.BootID {
		return true
	}
	if normalizePluginControlNamespace(oldGeneration.Namespace) != normalizePluginControlNamespace(newGeneration.Namespace) {
		return true
	}
	if (oldGeneration.NamespaceIdentity.Device != 0 || oldGeneration.NamespaceIdentity.Inode != 0) &&
		(newGeneration.NamespaceIdentity.Device != 0 || newGeneration.NamespaceIdentity.Inode != 0) &&
		!pluginControlNamespaceIdentityEqual(oldGeneration.NamespaceIdentity, newGeneration.NamespaceIdentity) {
		return true
	}
	oldIfIndex := oldGeneration.IfIndex
	if oldIfIndex == 0 {
		oldIfIndex = oldGeneration.OriginalIfIndex
	}
	if oldIfIndex == 0 {
		oldIfIndex = oldGeneration.DevIfIndex
	}
	newIfIndex := newGeneration.IfIndex
	if newIfIndex == 0 {
		newIfIndex = newGeneration.OriginalIfIndex
	}
	if newIfIndex == 0 {
		newIfIndex = newGeneration.DevIfIndex
	}
	if oldIfIndex > 0 && newIfIndex > 0 && oldIfIndex != newIfIndex {
		return true
	}
	oldKind := oldGeneration.Kind
	if oldKind == "" {
		oldKind = oldGeneration.OriginalKind
	}
	newKind := newGeneration.Kind
	if newKind == "" {
		newKind = newGeneration.OriginalKind
	}
	if oldKind != "" && newKind != "" && oldKind != newKind {
		return true
	}
	oldMAC := oldGeneration.MAC
	if oldMAC == "" {
		oldMAC = oldGeneration.OriginalMAC
	}
	newMAC := newGeneration.MAC
	if newMAC == "" {
		newMAC = newGeneration.OriginalMAC
	}
	if oldMAC != "" && newMAC != "" && !strings.EqualFold(oldMAC, newMAC) {
		return true
	}
	if len(oldGeneration.LinkIdentities) != len(newGeneration.LinkIdentities) {
		return true
	}
	for index := range oldGeneration.LinkIdentities {
		if oldGeneration.LinkIdentities[index] != newGeneration.LinkIdentities[index] {
			return true
		}
	}
	return false
}

func releasePluginOwnedResourceRefs(db store.RuleStore, pluginID string, refs []pluginOwnedResourceRef) error {
	failures := make([]string, 0)
	for _, ref := range refs {
		if err := store.DeletePluginOwnedResource(db, pluginID, ref.ResourceType, ref.ResourceKey); err != nil && !errors.Is(err, sql.ErrNoRows) {
			failures = append(failures, ref.ResourceType+"/"+ref.ResourceKey+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("release plugin resource claims: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) claimPluginOwnedLinks(claims []pluginOwnedLinkClaim) error {
	resources := make([]pluginOwnedResourceClaim, 0, len(claims))
	for i := range claims {
		claims[i].BootID = pluginOwnershipBootID
		claims[i].Namespace = normalizePluginControlNamespace(claims[i].Namespace)
		identity, err := h.pluginControlNamespaceIdentity(claims[i].Namespace)
		if err != nil {
			return err
		}
		claims[i].NamespaceIdentity = identity
		claim := claims[i]
		resources = append(resources, pluginOwnedResourceClaim{ResourceType: pluginOwnedResourceTypeLink, ResourceKey: pluginControlNetScopedResourceKey(claim.Namespace, claim.Name), Metadata: claim})
	}
	newlyClaimed, err := h.claimPluginOwnedResources(resources)
	if err != nil {
		return err
	}
	for _, claim := range claims {
		metadata, err := json.Marshal(claim)
		if err == nil {
			err = store.UpdatePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeLink, pluginControlNetScopedResourceKey(claim.Namespace, claim.Name), string(metadata))
		}
		if err != nil {
			_ = releasePluginOwnedResourceRefs(h.db, h.plugin.ID, newlyClaimed)
			return err
		}
	}
	return nil
}

func (h *pluginControlHost) releasePluginOwnedLink(namespace, name string) error {
	if h.db == nil {
		return fmt.Errorf("plugin ownership store is unavailable")
	}
	key := pluginControlNetScopedResourceKey(namespace, name)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeLink, key)
	if err != nil {
		return err
	}
	if owned == nil {
		return nil
	}
	if owned.PluginID != h.plugin.ID {
		return fmt.Errorf("link %s is owned by plugin %s", name, owned.PluginID)
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeLink, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (h *pluginControlHost) claimPluginLinkMutations(info pluginControlNetLinkInfo, originals map[string]any, api string) ([]pluginOwnedResourceRef, error) {
	namespace := normalizePluginControlNamespace(info.Namespace)
	owned, err := h.pluginOwnedLinkState(namespace, info.Name, api)
	if err != nil {
		return nil, err
	}
	if owned || len(originals) == 0 {
		return nil, nil
	}
	properties := make([]string, 0, len(originals))
	for property := range originals {
		properties = append(properties, property)
	}
	sort.Strings(properties)
	claims := make([]pluginOwnedResourceClaim, 0, len(properties))
	namespaceIdentity, err := h.pluginControlNamespaceIdentity(namespace)
	if err != nil {
		return nil, err
	}
	for _, property := range properties {
		original, err := json.Marshal(originals[property])
		if err != nil {
			return nil, err
		}
		resourceType := pluginOwnedResourceTypeLinkState
		if strings.HasPrefix(property, "offload.") {
			resourceType = pluginOwnedResourceTypeLinkOffload
		}
		claims = append(claims, pluginOwnedResourceClaim{
			ResourceType: resourceType,
			ResourceKey:  pluginControlNetScopedResourceKey(namespace, info.Name+"/"+property),
			Metadata: pluginOwnedLinkMutation{
				Version: 1, BootID: pluginOwnershipBootID, Namespace: namespace, NamespaceIdentity: namespaceIdentity,
				Interface: info.Name, Property: property, Original: original,
				OriginalIfIndex: info.IfIndex, OriginalKind: info.Kind, OriginalMAC: info.MAC,
			},
		})
	}
	return h.claimPluginOwnedResources(claims)
}

func (h *pluginControlHost) preparePluginEnsureLinkMutation(admin pluginControlNetAdmin, name string, mtu int, up bool, api string) (pluginLinkMutationSnapshot, []pluginOwnedResourceRef, error) {
	info, present, err := pluginOwnedLinkForRestore(admin, name)
	if err != nil {
		return pluginLinkMutationSnapshot{}, nil, err
	}
	snapshot := pluginLinkMutationSnapshot{Info: info, Present: present, Originals: make(map[string]any)}
	if !present {
		return snapshot, nil, nil
	}
	if mtu > 0 && info.MTU != mtu {
		snapshot.Originals["mtu"] = info.MTU
	}
	if up && !info.Up {
		snapshot.Originals["up"] = info.Up
	}
	refs, err := h.claimPluginLinkMutations(info, snapshot.Originals, api)
	return snapshot, refs, err
}

func (h *pluginControlHost) claimPluginAddressMutation(info pluginControlNetLinkInfo, req pluginControlNetAddrRequest, originalPresent bool, api string) ([]pluginOwnedResourceRef, pluginControlNetAddrRequest, error) {
	req.Namespace = normalizePluginControlNamespace(req.Namespace)
	owned, err := h.pluginOwnedLinkState(req.Namespace, info.Name, api)
	if err != nil {
		return nil, req, err
	}
	normalized, err := normalizePluginControlAddressRequest(req)
	if err != nil {
		return nil, req, err
	}
	if owned {
		return nil, normalized, nil
	}
	namespaceIdentity, err := h.pluginControlNamespaceIdentity(normalized.Namespace)
	if err != nil {
		return nil, req, err
	}
	refs, err := h.claimPluginOwnedResources([]pluginOwnedResourceClaim{{
		ResourceType: pluginOwnedResourceTypeAddress,
		ResourceKey:  pluginControlNetScopedResourceKey(normalized.Namespace, normalized.Interface+"/"+normalized.CIDR),
		Metadata: pluginOwnedAddressMutation{
			Version: 1, BootID: pluginOwnershipBootID, NamespaceIdentity: namespaceIdentity, Request: normalized, OriginalPresent: originalPresent,
			OriginalIfIndex: info.IfIndex, OriginalKind: info.Kind, OriginalMAC: info.MAC,
		},
	}})
	return refs, normalized, err
}

func normalizePluginControlAddressRequest(req pluginControlNetAddrRequest) (pluginControlNetAddrRequest, error) {
	var err error
	req.Namespace, err = normalizePluginControlRequestNamespace(req.Namespace)
	if err != nil {
		return req, err
	}
	req.Interface = strings.TrimSpace(req.Interface)
	ip, network, err := net.ParseCIDR(strings.TrimSpace(req.CIDR))
	if err != nil {
		return req, fmt.Errorf("cidr: %w", err)
	}
	network.IP = ip
	req.CIDR = network.String()
	return req, nil
}

func pluginControlNetRouteLeaseKey(req pluginControlNetRouteRequest) string {
	req = normalizePluginControlRouteRequest(req)
	return pluginControlNetScopedResourceKey(req.Namespace, fmt.Sprintf("%s|%d|%d", req.Dst, req.Table, req.Metric))
}

func normalizePluginControlRouteRequest(req pluginControlNetRouteRequest) pluginControlNetRouteRequest {
	req.Namespace = normalizePluginControlNamespace(req.Namespace)
	req.Dev = strings.TrimSpace(req.Dev)
	req.Gateway = normalizePluginControlRouteIP(req.Gateway)
	req.Src = normalizePluginControlRouteIP(req.Src)
	if req.Table == 0 {
		req.Table = 254
	}
	if len(req.Nexthops) > 0 {
		nexthops := append([]pluginControlNetRouteNexthop(nil), req.Nexthops...)
		for index := range nexthops {
			nexthops[index].Dev = strings.TrimSpace(nexthops[index].Dev)
			nexthops[index].Gateway = normalizePluginControlRouteIP(nexthops[index].Gateway)
			if nexthops[index].Weight == 0 {
				nexthops[index].Weight = 1
			}
		}
		sort.Slice(nexthops, func(i, j int) bool {
			left := fmt.Sprintf("%s\x00%s\x00%03d\x00%t", nexthops[i].Dev, nexthops[i].Gateway, nexthops[i].Weight, nexthops[i].Onlink)
			right := fmt.Sprintf("%s\x00%s\x00%03d\x00%t", nexthops[j].Dev, nexthops[j].Gateway, nexthops[j].Weight, nexthops[j].Onlink)
			return left < right
		})
		req.Nexthops = nexthops
	}
	dst := strings.TrimSpace(strings.ToLower(req.Dst))
	if dst == "" || dst == "default" || dst == "0.0.0.0/0" || dst == "::/0" {
		dst = "0.0.0.0/0"
		if strings.TrimSpace(req.Dst) == "::/0" || pluginControlNetRouteIPFamilyHint(req) == 6 {
			dst = "::/0"
		}
	} else if strings.Contains(dst, "/") {
		if _, network, err := net.ParseCIDR(dst); err == nil {
			dst = network.String()
		}
	} else if ip := net.ParseIP(dst); ip != nil {
		if ip.To4() != nil {
			dst = ip.String() + "/32"
		} else {
			dst = ip.String() + "/128"
		}
	}
	req.Dst = dst
	return req
}

func normalizePluginControlRouteIP(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func pluginControlNetRouteIPFamilyHint(req pluginControlNetRouteRequest) int {
	for _, value := range append([]string{req.Gateway, req.Src}, pluginControlNetRouteNexthopGateways(req.Nexthops)...) {
		if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
			if ip.To4() != nil {
				return 4
			}
			return 6
		}
	}
	return 0
}

func pluginControlNetRouteNexthopGateways(nexthops []pluginControlNetRouteNexthop) []string {
	out := make([]string, 0, len(nexthops))
	for _, nexthop := range nexthops {
		out = append(out, nexthop.Gateway)
	}
	return out
}

func validatePluginControlRouteRequest(req pluginControlNetRouteRequest) (pluginControlNetRouteRequest, error) {
	if strings.TrimSpace(req.Dst) == "" {
		return req, fmt.Errorf("dst is required")
	}
	var err error
	req.Namespace, err = normalizePluginControlRequestNamespace(req.Namespace)
	if err != nil {
		return req, err
	}
	req = normalizePluginControlRouteRequest(req)
	if req.Table < 0 || req.Table > 0x7fffffff {
		return req, fmt.Errorf("table out of range")
	}
	if req.Metric < 0 || req.Metric > 0x7fffffff {
		return req, fmt.Errorf("metric out of range")
	}
	if req.Scope < 0 || req.Scope > 255 {
		return req, fmt.Errorf("scope out of range")
	}
	if len(req.Nexthops) > pluginControlNetMaxRouteNexthops {
		return req, fmt.Errorf("nexthops count exceeds %d", pluginControlNetMaxRouteNexthops)
	}
	if len(req.Nexthops) > 0 {
		if req.Dev != "" || req.Gateway != "" {
			return req, fmt.Errorf("dev and gateway cannot be combined with nexthops")
		}
	} else {
		if err := validatePluginControlInterfaceName(req.Dev, "dev"); err != nil {
			return req, err
		}
	}
	_, destination, err := net.ParseCIDR(req.Dst)
	if err != nil {
		return req, fmt.Errorf("dst: %w", err)
	}
	family := 6
	if destination.IP.To4() != nil {
		family = 4
	}
	if err := validatePluginControlRouteFamilyIP("gateway", req.Gateway, family); err != nil {
		return req, err
	}
	if err := validatePluginControlRouteFamilyIP("src", req.Src, family); err != nil {
		return req, err
	}
	seen := make(map[string]struct{}, len(req.Nexthops))
	for index, nexthop := range req.Nexthops {
		if err := validatePluginControlInterfaceName(nexthop.Dev, fmt.Sprintf("nexthops[%d].dev", index)); err != nil {
			return req, err
		}
		if nexthop.Weight < 1 || nexthop.Weight > 256 {
			return req, fmt.Errorf("nexthops[%d].weight must be between 1 and 256", index)
		}
		if err := validatePluginControlRouteFamilyIP(fmt.Sprintf("nexthops[%d].gateway", index), nexthop.Gateway, family); err != nil {
			return req, err
		}
		if nexthop.Onlink && nexthop.Gateway == "" {
			return req, fmt.Errorf("nexthops[%d].onlink requires gateway", index)
		}
		key := nexthop.Dev + "\x00" + nexthop.Gateway
		if _, duplicate := seen[key]; duplicate {
			return req, fmt.Errorf("nexthops[%d] duplicates dev/gateway %s/%s", index, nexthop.Dev, nexthop.Gateway)
		}
		seen[key] = struct{}{}
	}
	return req, nil
}

func validatePluginControlRouteFamilyIP(field, value string, family int) error {
	if value == "" {
		return nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return fmt.Errorf("%s must be an IP address", field)
	}
	if (family == 4) != (ip.To4() != nil) {
		return fmt.Errorf("%s does not match destination address family", field)
	}
	return nil
}

func pluginControlNetRouteInterfaces(req pluginControlNetRouteRequest) []string {
	req = normalizePluginControlRouteRequest(req)
	seen := make(map[string]struct{})
	if req.Dev != "" {
		seen[req.Dev] = struct{}{}
	}
	for _, nexthop := range req.Nexthops {
		if nexthop.Dev != "" {
			seen[nexthop.Dev] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func pluginControlNetRuleLeaseKey(req pluginControlNetRuleRequest) string {
	req, _ = normalizePluginControlRuleRequest(req)
	return pluginControlNetScopedResourceKey(req.Namespace, fmt.Sprintf("%s|%d|%d|%s|%s|%d|%d|%t|%s|%s|%t",
		req.Family, req.Priority, req.Table, req.Src, req.Dst, req.Mark, req.Mask, req.HasMask, req.IIF, req.OIF, req.Invert))
}

func normalizePluginControlRuleRequest(req pluginControlNetRuleRequest) (pluginControlNetRuleRequest, error) {
	var err error
	req.Namespace, err = normalizePluginControlRequestNamespace(req.Namespace)
	if err != nil {
		return req, err
	}
	req.Family = strings.ToLower(strings.TrimSpace(req.Family))
	switch req.Family {
	case "4", "inet":
		req.Family = "ipv4"
	case "6", "inet6":
		req.Family = "ipv6"
	}
	if req.Src, req.Family, err = normalizePluginControlRulePrefix("src", req.Src, req.Family); err != nil {
		return req, err
	}
	if req.Dst, req.Family, err = normalizePluginControlRulePrefix("dst", req.Dst, req.Family); err != nil {
		return req, err
	}
	if req.Family != "ipv4" && req.Family != "ipv6" {
		return req, fmt.Errorf("family must be ipv4 or ipv6")
	}
	req.IIF = strings.TrimSpace(req.IIF)
	req.OIF = strings.TrimSpace(req.OIF)
	if !req.HasMask || req.Mask == ^uint32(0) {
		req.HasMask = false
		req.Mask = 0
	}
	return req, nil
}

func normalizePluginControlRulePrefix(field, value, family string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "all") {
		return "", family, nil
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", family, fmt.Errorf("%s: %w", field, err)
	}
	prefixFamily := "ipv6"
	if ip.To4() != nil {
		prefixFamily = "ipv4"
	}
	if family == "" {
		family = prefixFamily
	} else if family != prefixFamily {
		return "", family, fmt.Errorf("%s does not match family %s", field, family)
	}
	return network.String(), family, nil
}

func pluginControlNetNeighLeaseKey(req pluginControlNetNeighRequest) string {
	req, _ = normalizePluginControlNeighRequest(req, false)
	return pluginControlNetScopedResourceKey(req.Namespace, fmt.Sprintf("%s|%s|%d", req.Interface, req.IP, req.VLAN))
}

func normalizePluginControlNeighRequest(req pluginControlNetNeighRequest, requireMAC bool) (pluginControlNetNeighRequest, error) {
	var err error
	req.Namespace, err = normalizePluginControlRequestNamespace(req.Namespace)
	if err != nil {
		return req, err
	}
	req.Interface = strings.TrimSpace(req.Interface)
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		return req, fmt.Errorf("ip is invalid")
	}
	req.IP = ip.String()
	req.State = strings.ToLower(strings.TrimSpace(req.State))
	if req.State == "" {
		req.State = "permanent"
	}
	if req.State != "permanent" && req.State != "noarp" {
		return req, fmt.Errorf("state must be permanent or noarp")
	}
	if req.VLAN < 0 || req.VLAN > 4094 {
		return req, fmt.Errorf("vlan must be between 0 and 4094")
	}
	if strings.TrimSpace(req.MAC) == "" {
		if requireMAC {
			return req, fmt.Errorf("mac is required")
		}
		return req, nil
	}
	mac, err := normalizePluginControlUnicastMAC(req.MAC)
	if err != nil {
		return req, err
	}
	req.MAC = mac
	return req, nil
}

func (h *pluginControlHost) claimPluginRouteMutation(req pluginControlNetRouteRequest, currentPresent bool, original []pluginControlNetRouteState, identities []pluginOwnedRouteLinkIdentity) (pluginOwnedRouteMutation, bool, bool, error) {
	if h.db == nil {
		return pluginOwnedRouteMutation{}, false, false, fmt.Errorf("plugin ownership store is unavailable")
	}
	var err error
	req, err = validatePluginControlRouteRequest(req)
	if err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	identities, err = normalizePluginOwnedRouteLinkIdentities(req, identities)
	if err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	allOwned := len(identities) > 0
	for _, identity := range identities {
		owned, err := h.pluginOwnedLinkState(req.Namespace, identity.Dev, "net.route")
		if err != nil {
			return pluginOwnedRouteMutation{}, false, false, err
		}
		if !owned {
			allOwned = false
		}
	}
	if allOwned {
		return pluginOwnedRouteMutation{}, false, false, nil
	}
	namespaceIdentity, err := h.pluginControlNamespaceIdentity(req.Namespace)
	if err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	key := pluginControlNetRouteLeaseKey(req)
	tx, err := h.db.Begin()
	if err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	defer tx.Rollback()
	existing, err := store.PluginOwnedResourceOrNil(tx, pluginOwnedResourceTypeRoute, key)
	if err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	previous := pluginOwnedRouteMutation{}
	insert := existing == nil
	fresh := insert
	if existing != nil {
		if existing.PluginID != h.plugin.ID {
			return pluginOwnedRouteMutation{}, false, false, fmt.Errorf("route slot %s is owned by plugin %s", key, existing.PluginID)
		}
		if err := json.Unmarshal([]byte(existing.MetadataJSON), &previous); err != nil {
			return pluginOwnedRouteMutation{}, false, false, fmt.Errorf("decode route ownership metadata: %w", err)
		}
		candidate := pluginOwnedRouteMutation{
			Version: 1, BootID: pluginOwnershipBootID, NamespaceIdentity: namespaceIdentity, Original: clonePluginControlNetRouteStates(original),
			DevIfIndex: pluginOwnedRouteLegacyIfIndex(req, identities), LinkIdentities: append([]pluginOwnedRouteLinkIdentity(nil), identities...),
		}
		candidateJSON, marshalErr := json.Marshal(candidate)
		if marshalErr != nil {
			return pluginOwnedRouteMutation{}, false, false, marshalErr
		}
		if pluginOwnedResourceGenerationChanged(existing.MetadataJSON, candidateJSON) {
			previous = candidate
			fresh = true
		}
	} else {
		previous = pluginOwnedRouteMutation{
			Version: 1, BootID: pluginOwnershipBootID, NamespaceIdentity: namespaceIdentity, Original: clonePluginControlNetRouteStates(original),
			DevIfIndex: pluginOwnedRouteLegacyIfIndex(req, identities), LinkIdentities: append([]pluginOwnedRouteLinkIdentity(nil), identities...),
		}
	}
	next := previous
	next.Current = req
	next.CurrentPresent = currentPresent
	metadata, err := json.Marshal(next)
	if err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	if insert {
		err = store.AddPluginOwnedResource(tx, store.PluginOwnedResource{
			PluginID: h.plugin.ID, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: key, MetadataJSON: string(metadata),
		})
	} else {
		err = store.UpdatePluginOwnedResource(tx, h.plugin.ID, pluginOwnedResourceTypeRoute, key, string(metadata))
	}
	if err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	if err := tx.Commit(); err != nil {
		return pluginOwnedRouteMutation{}, false, false, err
	}
	return previous, fresh, true, nil
}

func normalizePluginOwnedRouteLinkIdentities(req pluginControlNetRouteRequest, identities []pluginOwnedRouteLinkIdentity) ([]pluginOwnedRouteLinkIdentity, error) {
	want := pluginControlNetRouteInterfaces(req)
	out := append([]pluginOwnedRouteLinkIdentity(nil), identities...)
	for index := range out {
		out[index].Dev = strings.TrimSpace(out[index].Dev)
		if out[index].IfIndex < 1 {
			return nil, fmt.Errorf("route interface %s has invalid ifindex", out[index].Dev)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dev < out[j].Dev })
	if len(out) != len(want) {
		return nil, fmt.Errorf("route interface identity count does not match request")
	}
	for index := range want {
		if out[index].Dev != want[index] {
			return nil, fmt.Errorf("route interface identity %s does not match request interface %s", out[index].Dev, want[index])
		}
		if index > 0 && out[index-1].Dev == out[index].Dev {
			return nil, fmt.Errorf("duplicate route interface identity %s", out[index].Dev)
		}
	}
	return out, nil
}

func pluginOwnedRouteLegacyIfIndex(req pluginControlNetRouteRequest, identities []pluginOwnedRouteLinkIdentity) int {
	if len(identities) == 1 && req.Dev != "" && identities[0].Dev == req.Dev {
		return identities[0].IfIndex
	}
	return 0
}

func clonePluginControlNetRouteStates(states []pluginControlNetRouteState) []pluginControlNetRouteState {
	out := append([]pluginControlNetRouteState(nil), states...)
	for index := range out {
		out[index].Nexthops = append([]pluginControlNetRouteNexthopState(nil), states[index].Nexthops...)
	}
	return out
}

func (h *pluginControlHost) claimPluginRuleMutation(req pluginControlNetRuleRequest, currentPresent bool, original []pluginControlNetRuleState) (pluginOwnedRuleMutation, bool, error) {
	if h.db == nil {
		return pluginOwnedRuleMutation{}, false, fmt.Errorf("plugin ownership store is unavailable")
	}
	req, err := normalizePluginControlRuleRequest(req)
	if err != nil {
		return pluginOwnedRuleMutation{}, false, err
	}
	namespaceIdentity, err := h.pluginControlNamespaceIdentity(req.Namespace)
	if err != nil {
		return pluginOwnedRuleMutation{}, false, err
	}
	key := pluginControlNetRuleLeaseKey(req)
	tx, err := h.db.Begin()
	if err != nil {
		return pluginOwnedRuleMutation{}, false, err
	}
	defer tx.Rollback()
	existing, err := store.PluginOwnedResourceOrNil(tx, pluginOwnedResourceTypeRule, key)
	if err != nil {
		return pluginOwnedRuleMutation{}, false, err
	}
	previous := pluginOwnedRuleMutation{}
	created := existing == nil
	if existing != nil {
		if existing.PluginID != h.plugin.ID {
			return pluginOwnedRuleMutation{}, false, fmt.Errorf("policy rule slot %s is owned by plugin %s", key, existing.PluginID)
		}
		if err := json.Unmarshal([]byte(existing.MetadataJSON), &previous); err != nil {
			return pluginOwnedRuleMutation{}, false, fmt.Errorf("decode policy rule ownership metadata: %w", err)
		}
		candidate := pluginOwnedRuleMutation{Version: 1, BootID: pluginOwnershipBootID, NamespaceIdentity: namespaceIdentity, Original: append([]pluginControlNetRuleState(nil), original...)}
		candidateJSON, marshalErr := json.Marshal(candidate)
		if marshalErr != nil {
			return pluginOwnedRuleMutation{}, false, marshalErr
		}
		if pluginOwnedResourceGenerationChanged(existing.MetadataJSON, candidateJSON) {
			previous = candidate
			created = true
		}
	} else {
		previous = pluginOwnedRuleMutation{Version: 1, BootID: pluginOwnershipBootID, NamespaceIdentity: namespaceIdentity, Original: append([]pluginControlNetRuleState(nil), original...)}
	}
	next := previous
	next.Current = req
	next.CurrentPresent = currentPresent
	metadata, err := json.Marshal(next)
	if err != nil {
		return pluginOwnedRuleMutation{}, false, err
	}
	if existing == nil {
		err = store.AddPluginOwnedResource(tx, store.PluginOwnedResource{PluginID: h.plugin.ID, ResourceType: pluginOwnedResourceTypeRule, ResourceKey: key, MetadataJSON: string(metadata)})
	} else {
		err = store.UpdatePluginOwnedResource(tx, h.plugin.ID, pluginOwnedResourceTypeRule, key, string(metadata))
	}
	if err != nil {
		return pluginOwnedRuleMutation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return pluginOwnedRuleMutation{}, false, err
	}
	return previous, created, nil
}

func (h *pluginControlHost) claimPluginNeighMutation(req pluginControlNetNeighRequest, currentPresent bool, original []pluginControlNetNeighState, devIfIndex int) (pluginOwnedNeighMutation, bool, bool, error) {
	if h.db == nil {
		return pluginOwnedNeighMutation{}, false, false, fmt.Errorf("plugin ownership store is unavailable")
	}
	req, err := normalizePluginControlNeighRequest(req, currentPresent)
	if err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	owned, err := h.pluginOwnedLinkState(req.Namespace, req.Interface, "net.neigh")
	if err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	if owned {
		return pluginOwnedNeighMutation{}, false, false, nil
	}
	namespaceIdentity, err := h.pluginControlNamespaceIdentity(req.Namespace)
	if err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	key := pluginControlNetNeighLeaseKey(req)
	tx, err := h.db.Begin()
	if err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	defer tx.Rollback()
	existing, err := store.PluginOwnedResourceOrNil(tx, pluginOwnedResourceTypeNeighbor, key)
	if err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	previous := pluginOwnedNeighMutation{}
	created := existing == nil
	if existing != nil {
		if existing.PluginID != h.plugin.ID {
			return pluginOwnedNeighMutation{}, false, false, fmt.Errorf("neighbor slot %s is owned by plugin %s", key, existing.PluginID)
		}
		if err := json.Unmarshal([]byte(existing.MetadataJSON), &previous); err != nil {
			return pluginOwnedNeighMutation{}, false, false, fmt.Errorf("decode neighbor ownership metadata: %w", err)
		}
		candidate := pluginOwnedNeighMutation{
			Version: 1, BootID: pluginOwnershipBootID, NamespaceIdentity: namespaceIdentity, Original: append([]pluginControlNetNeighState(nil), original...), DevIfIndex: devIfIndex,
		}
		candidateJSON, marshalErr := json.Marshal(candidate)
		if marshalErr != nil {
			return pluginOwnedNeighMutation{}, false, false, marshalErr
		}
		if pluginOwnedResourceGenerationChanged(existing.MetadataJSON, candidateJSON) {
			previous = candidate
			created = true
		}
	} else {
		previous = pluginOwnedNeighMutation{
			Version: 1, BootID: pluginOwnershipBootID, NamespaceIdentity: namespaceIdentity, Original: append([]pluginControlNetNeighState(nil), original...), DevIfIndex: devIfIndex,
		}
	}
	next := previous
	next.Current = req
	next.CurrentPresent = currentPresent
	metadata, err := json.Marshal(next)
	if err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	if existing == nil {
		err = store.AddPluginOwnedResource(tx, store.PluginOwnedResource{PluginID: h.plugin.ID, ResourceType: pluginOwnedResourceTypeNeighbor, ResourceKey: key, MetadataJSON: string(metadata)})
	} else {
		err = store.UpdatePluginOwnedResource(tx, h.plugin.ID, pluginOwnedResourceTypeNeighbor, key, string(metadata))
	}
	if err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	if err := tx.Commit(); err != nil {
		return pluginOwnedNeighMutation{}, false, false, err
	}
	return previous, created, true, nil
}

func rollbackPluginLinkOperation(admin pluginControlNetAdmin, info pluginControlNetLinkInfo, originals map[string]any) error {
	properties := make([]string, 0, len(originals))
	for property := range originals {
		properties = append(properties, property)
	}
	sort.Strings(properties)
	failures := make([]string, 0)
	for _, property := range properties {
		original, err := json.Marshal(originals[property])
		if err == nil {
			err = restorePluginOwnedLinkMutation(admin, pluginOwnedLinkMutation{Interface: info.Name, Property: property, Original: original})
		}
		if err != nil {
			failures = append(failures, property+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("restore link state: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) rollbackNewPluginResourceClaims(admin pluginControlNetAdmin, info pluginControlNetLinkInfo, originals map[string]any, refs []pluginOwnedResourceRef) error {
	failures := make([]string, 0, 2)
	if err := rollbackPluginLinkOperation(admin, info, originals); err != nil {
		failures = append(failures, err.Error())
	}
	if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback plugin network mutation: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) rollbackPluginLinkSnapshots(admin pluginControlNetAdmin, snapshots []pluginLinkMutationSnapshot, refs []pluginOwnedResourceRef) error {
	failures := make([]string, 0, len(snapshots)+1)
	for _, snapshot := range snapshots {
		if !snapshot.Present {
			continue
		}
		if err := rollbackPluginLinkOperation(admin, snapshot.Info, snapshot.Originals); err != nil {
			failures = append(failures, snapshot.Info.Name+": "+err.Error())
		}
	}
	if err := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback plugin link changes: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) rollbackPluginAddressOperation(admin pluginControlNetAdmin, req pluginControlNetAddrRequest, originalPresent bool, refs []pluginOwnedResourceRef) error {
	var restoreErr error
	if originalPresent {
		restoreErr = admin.AddrReplace(req)
	} else {
		restoreErr = admin.AddrDelete(req)
	}
	releaseErr := releasePluginOwnedResourceRefs(h.db, h.plugin.ID, refs)
	if restoreErr != nil && releaseErr != nil {
		return fmt.Errorf("restore address: %v; %v", restoreErr, releaseErr)
	}
	if restoreErr != nil {
		return restoreErr
	}
	return releaseErr
}

func (h *pluginControlHost) rollbackPluginRouteOperation(admin pluginControlNetAdmin, intended pluginControlNetRouteRequest, intendedPresent bool, previous pluginOwnedRouteMutation, created bool) error {
	key := pluginControlNetRouteLeaseKey(intended)
	failures := make([]string, 0, 3)
	if intendedPresent {
		if err := admin.RouteDelete(intended); err != nil {
			failures = append(failures, "delete intended route: "+err.Error())
		}
	}
	if previous.CurrentPresent {
		if err := admin.RouteReplace(previous.Current); err != nil {
			failures = append(failures, "restore previous route: "+err.Error())
		}
	} else if created {
		if err := admin.RouteRestore(previous.Original); err != nil {
			failures = append(failures, "restore original route: "+err.Error())
		}
	}
	if created {
		if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeRoute, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
			failures = append(failures, "release route lease: "+err.Error())
		}
	} else {
		metadata, err := json.Marshal(previous)
		if err == nil {
			err = store.UpdatePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeRoute, key, string(metadata))
		}
		if err != nil {
			failures = append(failures, "restore route lease: "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback route mutation: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) rollbackPluginRuleOperation(admin pluginControlNetAdmin, intended pluginControlNetRuleRequest, intendedPresent bool, previous pluginOwnedRuleMutation, created bool) error {
	key := pluginControlNetRuleLeaseKey(intended)
	failures := make([]string, 0, 3)
	if intendedPresent {
		if err := admin.RuleDelete(intended); err != nil {
			failures = append(failures, "delete intended policy rule: "+err.Error())
		}
	}
	if previous.CurrentPresent {
		if err := admin.RuleReplace(previous.Current); err != nil {
			failures = append(failures, "restore previous policy rule: "+err.Error())
		}
	} else if created {
		if err := admin.RuleRestore(previous.Original); err != nil {
			failures = append(failures, "restore original policy rule: "+err.Error())
		}
	}
	if created {
		if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeRule, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
			failures = append(failures, "release policy rule lease: "+err.Error())
		}
	} else {
		metadata, err := json.Marshal(previous)
		if err == nil {
			err = store.UpdatePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeRule, key, string(metadata))
		}
		if err != nil {
			failures = append(failures, "restore policy rule lease: "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback policy rule mutation: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) rollbackPluginNeighOperation(admin pluginControlNetAdmin, intended pluginControlNetNeighRequest, intendedPresent bool, previous pluginOwnedNeighMutation, created bool) error {
	key := pluginControlNetNeighLeaseKey(intended)
	failures := make([]string, 0, 3)
	if intendedPresent {
		if err := admin.NeighDelete(intended); err != nil {
			failures = append(failures, "delete intended neighbor: "+err.Error())
		}
	}
	if previous.CurrentPresent {
		if err := admin.NeighReplace(previous.Current); err != nil {
			failures = append(failures, "restore previous neighbor: "+err.Error())
		}
	} else if created {
		if err := admin.NeighRestore(previous.Original); err != nil {
			failures = append(failures, "restore original neighbor: "+err.Error())
		}
	}
	if created {
		if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNeighbor, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
			failures = append(failures, "release neighbor lease: "+err.Error())
		}
	} else {
		metadata, err := json.Marshal(previous)
		if err == nil {
			err = store.UpdatePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNeighbor, key, string(metadata))
		}
		if err != nil {
			failures = append(failures, "restore neighbor lease: "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("rollback neighbor mutation: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *pluginControlHost) releaseRestoredPluginLinkLease(namespace, interfaceName, property string, desired any) error {
	resourceType := pluginOwnedResourceTypeLinkState
	if strings.HasPrefix(property, "offload.") {
		resourceType = pluginOwnedResourceTypeLinkOffload
	}
	key := pluginControlNetScopedResourceKey(namespace, interfaceName+"/"+property)
	owned, err := store.PluginOwnedResourceOrNil(h.db, resourceType, key)
	if err != nil || owned == nil || owned.PluginID != h.plugin.ID {
		return err
	}
	var metadata pluginOwnedLinkMutation
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &metadata); err != nil {
		return err
	}
	raw, err := json.Marshal(desired)
	if err != nil || !bytes.Equal(bytes.TrimSpace(metadata.Original), raw) {
		return err
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, resourceType, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (h *pluginControlHost) releaseRestoredPluginAddressLease(req pluginControlNetAddrRequest, present bool) error {
	req, err := normalizePluginControlAddressRequest(req)
	if err != nil {
		return err
	}
	key := pluginControlNetScopedResourceKey(req.Namespace, req.Interface+"/"+req.CIDR)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeAddress, key)
	if err != nil || owned == nil || owned.PluginID != h.plugin.ID {
		return err
	}
	var metadata pluginOwnedAddressMutation
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &metadata); err != nil {
		return err
	}
	if metadata.OriginalPresent != present {
		return nil
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeAddress, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (h *pluginControlHost) releaseRestoredPluginRouteLease(req pluginControlNetRouteRequest, present bool) error {
	key := pluginControlNetRouteLeaseKey(req)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeRoute, key)
	if err != nil || owned == nil || owned.PluginID != h.plugin.ID {
		return err
	}
	var metadata pluginOwnedRouteMutation
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &metadata); err != nil {
		return err
	}
	restored := !present && len(metadata.Original) == 0
	if present && len(metadata.Original) == 1 {
		restored = pluginControlRouteRequestMatchesState(req, metadata.Original[0])
	}
	if !restored {
		return nil
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeRoute, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (h *pluginControlHost) releaseRestoredPluginRuleLease(req pluginControlNetRuleRequest, present bool) error {
	key := pluginControlNetRuleLeaseKey(req)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeRule, key)
	if err != nil || owned == nil || owned.PluginID != h.plugin.ID {
		return err
	}
	var metadata pluginOwnedRuleMutation
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &metadata); err != nil {
		return err
	}
	restored := !present && len(metadata.Original) == 0
	if present && len(metadata.Original) == 1 {
		restored = pluginControlRuleRequestMatchesState(req, metadata.Original[0])
	}
	if !restored {
		return nil
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeRule, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func (h *pluginControlHost) releaseRestoredPluginNeighLease(req pluginControlNetNeighRequest, present bool) error {
	key := pluginControlNetNeighLeaseKey(req)
	owned, err := store.PluginOwnedResourceOrNil(h.db, pluginOwnedResourceTypeNeighbor, key)
	if err != nil || owned == nil || owned.PluginID != h.plugin.ID {
		return err
	}
	var metadata pluginOwnedNeighMutation
	if err := json.Unmarshal([]byte(owned.MetadataJSON), &metadata); err != nil {
		return err
	}
	restored := !present && len(metadata.Original) == 0
	if present && len(metadata.Original) == 1 {
		restored = pluginControlNeighRequestMatchesState(req, metadata.Original[0])
	}
	if !restored {
		return nil
	}
	if err := store.DeletePluginOwnedResource(h.db, h.plugin.ID, pluginOwnedResourceTypeNeighbor, key); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func pluginControlRuleRequestMatchesState(req pluginControlNetRuleRequest, state pluginControlNetRuleState) bool {
	req, err := normalizePluginControlRuleRequest(req)
	if err != nil {
		return false
	}
	want, err := normalizePluginControlRuleRequest(state.Request)
	return err == nil && req == want
}

func pluginControlNeighRequestMatchesState(req pluginControlNetNeighRequest, state pluginControlNetNeighState) bool {
	req, err := normalizePluginControlNeighRequest(req, true)
	if err != nil {
		return false
	}
	want, err := normalizePluginControlNeighRequest(state.Request, true)
	return err == nil && req == want
}

func pluginControlRouteRequestMatchesState(req pluginControlNetRouteRequest, state pluginControlNetRouteState) bool {
	req, err := validatePluginControlRouteRequest(req)
	if err != nil {
		return false
	}
	want, err := pluginControlNetRouteRequestForState(state)
	if err != nil || req.Dst != want.Dst || req.Dev != want.Dev || req.Gateway != want.Gateway || req.Src != want.Src ||
		req.Table != want.Table || req.Metric != want.Metric || req.Scope != want.Scope || len(req.Nexthops) != len(want.Nexthops) {
		return false
	}
	for index := range req.Nexthops {
		if req.Nexthops[index] != want.Nexthops[index] {
			return false
		}
	}
	return true
}

func pluginControlNetRouteRequestForState(state pluginControlNetRouteState) (pluginControlNetRouteRequest, error) {
	request := pluginControlNetRouteRequest{
		Namespace: state.Namespace, Dst: state.Dst, Dev: state.Dev, Gateway: state.Gateway, Src: state.Src,
		Table: state.Table, Metric: state.Metric, Scope: state.Scope,
		Nexthops: make([]pluginControlNetRouteNexthop, 0, len(state.Nexthops)),
	}
	if len(state.Nexthops) > 0 && (state.Dev != "" || state.Gateway != "" || state.DevIfIndex != 0) {
		return request, fmt.Errorf("multipath route state contains single-path fields")
	}
	for index, nexthop := range state.Nexthops {
		if nexthop.Weight < 1 || nexthop.Weight > 256 {
			return request, fmt.Errorf("nexthops[%d].weight is invalid", index)
		}
		request.Nexthops = append(request.Nexthops, pluginControlNetRouteNexthop{
			Gateway: nexthop.Gateway, Dev: nexthop.Dev, Weight: nexthop.Weight, Onlink: nexthop.Onlink,
		})
	}
	return validatePluginControlRouteRequest(request)
}

func pluginOwnedLinks(db store.RuleStore, pluginID string) ([]map[string]any, error) {
	items, err := store.GetPluginOwnedResources(db, pluginID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if item.ResourceType != pluginOwnedResourceTypeLink {
			continue
		}
		var metadata map[string]any
		_ = json.Unmarshal([]byte(item.MetadataJSON), &metadata)
		name := item.ResourceKey
		if value, ok := metadata["name"].(string); ok && strings.TrimSpace(value) != "" {
			name = value
		}
		namespace := "host"
		if value, ok := metadata["namespace"].(string); ok {
			namespace = normalizePluginControlNamespace(value)
		}
		out = append(out, map[string]any{
			"name": name, "namespace": namespace,
			"key": item.ResourceKey, "type": item.ResourceType, "metadata": metadata, "created_at": item.CreatedAt, "updated_at": item.UpdatedAt,
		})
	}
	return out, nil
}

func pluginOwnedResourceViews(db store.RuleStore, pluginID string) ([]map[string]any, error) {
	items, err := store.GetPluginOwnedResources(db, pluginID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		var metadata map[string]any
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"type": item.ResourceType, "key": item.ResourceKey, "metadata": metadata,
			"created_at": item.CreatedAt, "updated_at": item.UpdatedAt,
		})
	}
	return out, nil
}

func pluginOwnedResourceLeaseStatesByPlugin(db store.RuleStore, pluginIDs []string) (map[string][]PluginResourceLeaseState, error) {
	itemsByPlugin, err := store.GetPluginOwnedResourcesByPluginIDs(db, pluginIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]PluginResourceLeaseState, len(itemsByPlugin))
	for pluginID, items := range itemsByPlugin {
		leases := make([]PluginResourceLeaseState, 0, len(items))
		for _, item := range items {
			leases = append(leases, PluginResourceLeaseState{
				Type: item.ResourceType, Key: item.ResourceKey, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
			})
		}
		out[pluginID] = leases
	}
	return out, nil
}

func validPluginOwnedResourceType(value string) bool {
	switch value {
	case pluginOwnedResourceTypeLink, pluginOwnedResourceTypeLinkState, pluginOwnedResourceTypeLinkOffload, pluginOwnedResourceTypeAddress,
		pluginOwnedResourceTypeRoute, pluginOwnedResourceTypeRule, pluginOwnedResourceTypeNeighbor, pluginOwnedResourceTypeTunTap,
		pluginOwnedResourceTypeNamespace:
		return true
	default:
		return false
	}
}

func cleanupPluginOwnedLinks(db *sql.DB, admin pluginControlNetAdmin, pluginID string) error {
	return cleanupPluginOwnedResources(db, admin, pluginID)
}

func cleanupPluginOwnedResources(db *sql.DB, admin pluginControlNetAdmin, pluginID string) error {
	if db == nil || admin == nil || strings.TrimSpace(pluginID) == "" {
		return nil
	}
	items, err := store.GetPluginOwnedResources(db, pluginID)
	if err != nil {
		return err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return pluginOwnedResourceCleanupPriority(items[i]) < pluginOwnedResourceCleanupPriority(items[j])
	})
	failures := make([]string, 0)
	for _, item := range items {
		if err := restorePluginOwnedResource(admin, item); err != nil {
			failures = append(failures, item.ResourceKey+": "+err.Error())
			continue
		}
		if err := store.DeletePluginOwnedResource(db, pluginID, item.ResourceType, item.ResourceKey); err != nil && !errors.Is(err, sql.ErrNoRows) {
			failures = append(failures, item.ResourceKey+" ledger: "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("owned resource cleanup failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func restorePluginOwnedResource(admin pluginControlNetAdmin, item store.PluginOwnedResource) error {
	var generation struct {
		BootID string `json:"boot_id"`
	}
	if err := json.Unmarshal([]byte(item.MetadataJSON), &generation); err != nil {
		return err
	}
	if generation.BootID != "" && pluginOwnershipBootID != "" && generation.BootID != pluginOwnershipBootID {
		return nil
	}
	switch item.ResourceType {
	case pluginOwnedResourceTypeLink:
		var metadata pluginOwnedLinkClaim
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		scoped, currentNamespace, err := pluginControlNetAdminForOwnedNamespace(admin, metadata.Namespace, metadata.NamespaceIdentity)
		if err != nil || !currentNamespace {
			return err
		}
		current, present, err := pluginOwnedLinkForRestore(scoped, metadata.Name)
		if err != nil || !present {
			return err
		}
		if !pluginOwnedLinkIdentityMatches(current, metadata.IfIndex, metadata.Kind, metadata.MAC) {
			return nil
		}
		return scoped.LinkDelete(metadata.Name)
	case pluginOwnedResourceTypeLinkState, pluginOwnedResourceTypeLinkOffload:
		var metadata pluginOwnedLinkMutation
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		scoped, currentNamespace, err := pluginControlNetAdminForOwnedNamespace(admin, metadata.Namespace, metadata.NamespaceIdentity)
		if err != nil || !currentNamespace {
			return err
		}
		current, present, err := pluginOwnedLinkForRestore(scoped, metadata.Interface)
		if err != nil || !present {
			return err
		}
		if !pluginOwnedLinkIdentityMatches(current, metadata.OriginalIfIndex, metadata.OriginalKind, metadata.OriginalMAC) {
			return nil
		}
		return restorePluginOwnedLinkMutation(scoped, metadata)
	case pluginOwnedResourceTypeAddress:
		var metadata pluginOwnedAddressMutation
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		scoped, currentNamespace, err := pluginControlNetAdminForOwnedNamespace(admin, metadata.Request.Namespace, metadata.NamespaceIdentity)
		if err != nil || !currentNamespace {
			return err
		}
		current, present, err := pluginOwnedLinkForRestore(scoped, metadata.Request.Interface)
		if err != nil || !present {
			return err
		}
		if !pluginOwnedLinkIdentityMatches(current, metadata.OriginalIfIndex, metadata.OriginalKind, metadata.OriginalMAC) {
			return nil
		}
		if metadata.OriginalPresent {
			return scoped.AddrReplace(metadata.Request)
		}
		return scoped.AddrDelete(metadata.Request)
	case pluginOwnedResourceTypeRoute:
		var metadata pluginOwnedRouteMutation
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		scoped, currentNamespace, err := pluginControlNetAdminForOwnedNamespace(admin, metadata.Current.Namespace, metadata.NamespaceIdentity)
		if err != nil || !currentNamespace {
			return err
		}
		return restorePluginOwnedRouteMutation(scoped, metadata)
	case pluginOwnedResourceTypeRule:
		var metadata pluginOwnedRuleMutation
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		scoped, currentNamespace, err := pluginControlNetAdminForOwnedNamespace(admin, metadata.Current.Namespace, metadata.NamespaceIdentity)
		if err != nil || !currentNamespace {
			return err
		}
		return restorePluginOwnedRuleMutation(scoped, metadata)
	case pluginOwnedResourceTypeNeighbor:
		var metadata pluginOwnedNeighMutation
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		scoped, currentNamespace, err := pluginControlNetAdminForOwnedNamespace(admin, metadata.Current.Namespace, metadata.NamespaceIdentity)
		if err != nil || !currentNamespace {
			return err
		}
		return restorePluginOwnedNeighMutation(scoped, metadata)
	case pluginOwnedResourceTypeTunTap:
		provider, ok := admin.(pluginControlNetworkProvider)
		if !ok {
			return fmt.Errorf("TUN/TAP provider is unavailable")
		}
		var metadata pluginOwnedTunTapClaim
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		return provider.TunTapClose(item.PluginID, pluginControlNetTunTapCloseRequest{
			Name: metadata.Name, Namespace: metadata.Namespace, IfIndex: metadata.IfIndex,
		})
	case pluginOwnedResourceTypeNamespace:
		provider, ok := admin.(pluginControlNetworkProvider)
		if !ok {
			return fmt.Errorf("network namespace provider is unavailable")
		}
		var metadata pluginOwnedNamespaceClaim
		if err := json.Unmarshal([]byte(item.MetadataJSON), &metadata); err != nil {
			return err
		}
		return provider.NamespaceDelete(metadata.Name, metadata.Identity)
	default:
		return fmt.Errorf("unsupported owned resource type %q", item.ResourceType)
	}
}

func pluginControlNetAdminForOwnedNamespace(admin pluginControlNetAdmin, namespace string, expected pluginControlNetNamespaceIdentity) (pluginControlNetAdmin, bool, error) {
	namespace = normalizePluginControlNamespace(namespace)
	if namespace == "host" {
		return admin, true, nil
	}
	provider, ok := admin.(pluginControlNetworkProvider)
	if !ok || provider == nil {
		return nil, false, fmt.Errorf("network namespace provider is unavailable")
	}
	info, present, err := provider.NamespaceLookup(namespace)
	if err != nil || !present {
		return nil, false, err
	}
	if (expected.Device != 0 || expected.Inode != 0) && !pluginControlNamespaceIdentityEqual(info.Identity, expected) {
		return nil, false, nil
	}
	scoped, err := pluginControlNetAdminInNamespace(admin, namespace)
	if err != nil {
		return nil, false, err
	}
	return scoped, true, nil
}

func restorePluginOwnedLinkMutation(admin pluginControlNetAdmin, metadata pluginOwnedLinkMutation) error {
	switch metadata.Property {
	case "master":
		var master string
		if err := json.Unmarshal(metadata.Original, &master); err != nil {
			return err
		}
		if master == "" {
			_, err := admin.LinkClearMaster(metadata.Interface)
			return err
		}
		_, err := admin.LinkSetMaster(pluginControlNetMasterRequest{Link: metadata.Interface, Master: master, Up: false})
		return err
	case "up":
		var value bool
		if err := json.Unmarshal(metadata.Original, &value); err != nil {
			return err
		}
		return admin.LinkSetUp(metadata.Interface, value)
	case "mtu":
		var value int
		if err := json.Unmarshal(metadata.Original, &value); err != nil {
			return err
		}
		return admin.LinkSetMTU(metadata.Interface, value)
	case "arp":
		var value bool
		if err := json.Unmarshal(metadata.Original, &value); err != nil {
			return err
		}
		_, err := admin.LinkSetARP(metadata.Interface, value)
		return err
	case "promiscuous":
		var value bool
		if err := json.Unmarshal(metadata.Original, &value); err != nil {
			return err
		}
		_, err := admin.LinkSetPromiscuous(metadata.Interface, value)
		return err
	case "gso":
		var value pluginControlNetGSORequest
		if err := json.Unmarshal(metadata.Original, &value); err != nil {
			return err
		}
		value.Interface = metadata.Interface
		_, err := admin.LinkSetGSO(value)
		return err
	default:
		if strings.HasPrefix(metadata.Property, "offload.") {
			feature := strings.TrimPrefix(metadata.Property, "offload.")
			var value bool
			if err := json.Unmarshal(metadata.Original, &value); err != nil {
				return err
			}
			return admin.LinkSetOffloads(pluginControlNetOffloadRequest{Interface: metadata.Interface, Features: map[string]bool{feature: value}})
		}
		return fmt.Errorf("unsupported link mutation property %q", metadata.Property)
	}
}

func restorePluginOwnedRouteMutation(admin pluginControlNetAdmin, metadata pluginOwnedRouteMutation) error {
	if len(metadata.LinkIdentities) > 0 {
		for _, identity := range metadata.LinkIdentities {
			current, present, err := pluginOwnedLinkForRestore(admin, identity.Dev)
			if err != nil || !present {
				return err
			}
			if current.IfIndex != identity.IfIndex {
				return nil
			}
		}
	} else if metadata.Current.Dev != "" && metadata.DevIfIndex > 0 {
		current, present, err := pluginOwnedLinkForRestore(admin, metadata.Current.Dev)
		if err != nil || !present {
			return err
		}
		if current.IfIndex != metadata.DevIfIndex {
			return nil
		}
	}
	if metadata.CurrentPresent {
		if err := admin.RouteDelete(metadata.Current); err != nil {
			return err
		}
	}
	return admin.RouteRestore(metadata.Original)
}

func restorePluginOwnedRuleMutation(admin pluginControlNetAdmin, metadata pluginOwnedRuleMutation) error {
	if metadata.CurrentPresent {
		if err := admin.RuleDelete(metadata.Current); err != nil {
			return err
		}
	}
	return admin.RuleRestore(metadata.Original)
}

func restorePluginOwnedNeighMutation(admin pluginControlNetAdmin, metadata pluginOwnedNeighMutation) error {
	if metadata.Current.Interface != "" && metadata.DevIfIndex > 0 {
		current, present, err := pluginOwnedLinkForRestore(admin, metadata.Current.Interface)
		if err != nil || !present {
			return err
		}
		if current.IfIndex != metadata.DevIfIndex {
			return nil
		}
	}
	if metadata.CurrentPresent {
		if err := admin.NeighDelete(metadata.Current); err != nil {
			return err
		}
	}
	return admin.NeighRestore(metadata.Original)
}

func pluginOwnedLinkForRestore(admin pluginControlNetAdmin, name string) (pluginControlNetLinkInfo, bool, error) {
	return admin.LinkLookup(name)
}

func pluginOwnedLinkIdentityMatches(info pluginControlNetLinkInfo, ifIndex int, kind, mac string) bool {
	if ifIndex > 0 && info.IfIndex != ifIndex {
		return false
	}
	if kind != "" && info.Kind != "" && info.Kind != kind {
		return false
	}
	if mac != "" && info.MAC != "" && !strings.EqualFold(info.MAC, mac) {
		return false
	}
	return true
}

func pluginOwnedLinkCleanupPriority(item store.PluginOwnedResource) int {
	var metadata pluginOwnedLinkClaim
	_ = json.Unmarshal([]byte(item.MetadataJSON), &metadata)
	switch metadata.Kind {
	case "macvlan", "vlan", "veth":
		return 0
	case "dummy":
		return 1
	case "bridge", "vrf":
		return 2
	default:
		return 1
	}
}

func pluginOwnedResourceCleanupPriority(item store.PluginOwnedResource) int {
	switch item.ResourceType {
	case pluginOwnedResourceTypeTunTap:
		return -1
	case pluginOwnedResourceTypeRule, pluginOwnedResourceTypeNeighbor:
		return 0
	case pluginOwnedResourceTypeRoute:
		return 1
	case pluginOwnedResourceTypeAddress:
		return 2
	case pluginOwnedResourceTypeLinkState:
		var metadata pluginOwnedLinkMutation
		_ = json.Unmarshal([]byte(item.MetadataJSON), &metadata)
		if metadata.Property == "master" {
			return 3
		}
		return 4
	case pluginOwnedResourceTypeLinkOffload:
		return 4
	case pluginOwnedResourceTypeLink:
		return 10 + pluginOwnedLinkCleanupPriority(item)
	case pluginOwnedResourceTypeNamespace:
		return 30
	default:
		return 5
	}
}

func (rt *gojaPluginControlRuntime) cleanupInactivePluginOwnedResources(active map[string]LoadedPlugin) map[string]error {
	if rt == nil || rt.db == nil || rt.netAdmin == nil {
		return nil
	}
	items, err := store.GetPluginOwnedResources(rt.db, "")
	if err != nil {
		return map[string]error{"ownership": err}
	}
	owners := make(map[string]struct{})
	for _, item := range items {
		if _, ok := active[item.PluginID]; !ok {
			owners[item.PluginID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(owners))
	for id := range owners {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	failures := make(map[string]error)
	for _, id := range ids {
		if err := cleanupPluginOwnedResources(rt.db, rt.netAdmin, id); err != nil {
			failures[id] = err
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return failures
}
