package app

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/netservice"
)

type ipv6AssignmentRuntime interface {
	Reconcile(items []IPv6Assignment) error
	SnapshotStats() map[int64]ipv6AssignmentRuntimeStats
	Close() error
}

type ipv6AssignmentRuntimeStats = netservice.IPv6AssignmentRuntimeStats
type ipv6AssignmentRuntimeCounter = netservice.IPv6RuntimeCounter
type ipv6AssignmentRouteSpec = netservice.IPv6RouteSpec
type ipv6AssignmentAddressSpec = netservice.IPv6AddressSpec
type ipv6AssignmentRejectRouteSpec = netservice.IPv6RejectRouteSpec
type ipv6AssignmentProxySpec = netservice.IPv6ProxySpec
type ipv6AssignmentRAConfig = netservice.RAConfig
type ipv6AssignmentDHCPv6Config = netservice.DHCPv6Config
type ipv6AssignmentNetOps = netservice.IPv6AssignmentNetOps

type ipv6AssignmentRuntimePlan struct {
	ID                int64
	ParentInterface   string
	TargetInterface   string
	ParentPrefix      string
	AssignedPrefix    string
	ProxyAddress      string
	Intent            ipv6AssignmentIntent
	NeedsForwarding   bool
	NeedsProxyNDP     bool
	NeedsRADvertise   bool
	ParentPrefixNet   *net.IPNet
	AssignedPrefixNet *net.IPNet
	GatewayCIDR       string
	RejectPrefix      string
	DNSServers        []string
}

type ipv6AssignmentClosePreserver interface {
	PreserveIPv6AssignmentStateOnClose() bool
}

type managedIPv6AssignmentRuntime struct {
	ops   ipv6AssignmentNetOps
	inner *netservice.IPv6AssignmentRuntime
}

func newManagedIPv6AssignmentRuntime(ops ipv6AssignmentNetOps) ipv6AssignmentRuntime {
	inner := netservice.NewIPv6AssignmentRuntime(ops)
	if inner == nil {
		return nil
	}
	return &managedIPv6AssignmentRuntime{ops: ops, inner: inner}
}

func buildIPv6AssignmentRuntimePlan(item IPv6Assignment) (ipv6AssignmentRuntimePlan, error) {
	hydrateIPv6AssignmentCompatibilityFields(&item)
	item.ParentInterface = strings.TrimSpace(item.ParentInterface)
	item.TargetInterface = strings.TrimSpace(item.TargetInterface)
	if item.ParentInterface == "" {
		return ipv6AssignmentRuntimePlan{}, fmt.Errorf("assignment #%d missing parent interface", item.ID)
	}
	if item.TargetInterface == "" {
		return ipv6AssignmentRuntimePlan{}, fmt.Errorf("assignment #%d missing target interface", item.ID)
	}
	parentPrefix, parentNet, err := normalizeIPv6Prefix(item.ParentPrefix)
	if err != nil {
		return ipv6AssignmentRuntimePlan{}, fmt.Errorf("assignment #%d invalid parent_prefix: %w", item.ID, err)
	}
	assignedPrefix, assignedNet, _, err := normalizeIPv6AssignmentRequestedPrefix(item)
	if err != nil {
		return ipv6AssignmentRuntimePlan{}, fmt.Errorf("assignment #%d invalid assigned prefix: %w", item.ID, err)
	}
	if !ipv6PrefixContainsPrefix(parentNet, assignedNet) {
		return ipv6AssignmentRuntimePlan{}, fmt.Errorf("assignment #%d assigned prefix %s is outside parent prefix %s", item.ID, assignedPrefix, parentPrefix)
	}

	intent := classifyIPv6AssignmentIntent(assignedNet)
	plan := ipv6AssignmentRuntimePlan{
		ID:                item.ID,
		ParentInterface:   item.ParentInterface,
		TargetInterface:   item.TargetInterface,
		ParentPrefix:      parentPrefix,
		AssignedPrefix:    assignedPrefix,
		Intent:            intent,
		NeedsForwarding:   true,
		NeedsProxyNDP:     intent.kind == ipv6AssignmentIntentSingleAddress,
		NeedsRADvertise:   intent.addressing == ipv6AssignmentAddressingSLAACRecommended,
		ParentPrefixNet:   cloneIPv6Net(parentNet),
		AssignedPrefixNet: cloneIPv6Net(assignedNet),
		GatewayCIDR:       strings.TrimSpace(item.gatewayCIDR),
		RejectPrefix:      strings.TrimSpace(item.rejectPrefix),
		DNSServers:        append([]string(nil), item.dnsServers...),
	}
	if plan.NeedsProxyNDP {
		plan.ProxyAddress = canonicalIPLiteral(assignedNet.IP)
	}
	return plan, nil
}

func (rt *managedIPv6AssignmentRuntime) Reconcile(items []IPv6Assignment) error {
	if rt == nil || rt.inner == nil {
		return nil
	}

	hostIfaceByName := map[string]HostNetworkInterface{}
	needsHostResolution := false
	for _, item := range items {
		if item.Enabled && !item.upstreamRouted {
			needsHostResolution = true
			break
		}
	}
	if needsHostResolution {
		hostIfaces, err := loadIPv6AssignmentHostNetworkInterfaces()
		if err != nil {
			return fmt.Errorf("load host interfaces for ipv6 resolution: %w", err)
		}
		hostIfaceByName = buildHostNetworkInterfaceMap(hostIfaces)
	}

	plans := make([]netservice.IPv6AssignmentPlan, 0, len(items))
	issues := make([]netservice.IPv6AssignmentPlanIssue, 0)
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		resolvedItem, _, err := resolveIPv6AssignmentForCurrentHost(item, hostIfaceByName)
		if err != nil {
			summary := fmt.Sprintf("assignment #%d resolve current parent prefix: %v", item.ID, err)
			issues = append(issues, netservice.IPv6AssignmentPlanIssue{
				ID:      item.ID,
				Summary: summary,
				Detail:  fmt.Sprintf("resolve current parent prefix: %v", err),
			})
			continue
		}
		plan, err := buildIPv6AssignmentRuntimePlan(resolvedItem)
		if err != nil {
			issues = append(issues, netservice.IPv6AssignmentPlanIssue{
				ID:      item.ID,
				Summary: err.Error(),
				Detail:  err.Error(),
			})
			continue
		}
		plans = append(plans, netservice.IPv6AssignmentPlan{
			ID:              plan.ID,
			ParentInterface: plan.ParentInterface,
			TargetInterface: plan.TargetInterface,
			ParentPrefix:    plan.ParentPrefix,
			AssignedPrefix:  plan.AssignedPrefix,
			ProxyAddress:    plan.ProxyAddress,
			GatewayCIDR:     plan.GatewayCIDR,
			RejectPrefix:    plan.RejectPrefix,
			DNSServers:      append([]string(nil), plan.DNSServers...),
			NeedsForwarding: plan.NeedsForwarding,
			NeedsProxyNDP:   plan.NeedsProxyNDP,
			NeedsRA:         plan.NeedsRADvertise,
			IsSingleAddress: plan.Intent.kind == ipv6AssignmentIntentSingleAddress,
			AssignedAddress: canonicalIPLiteral(plan.AssignedPrefixNet.IP),
		})
	}
	return rt.inner.Reconcile(plans, issues)
}

func (rt *managedIPv6AssignmentRuntime) SnapshotStats() map[int64]ipv6AssignmentRuntimeStats {
	if rt == nil || rt.inner == nil {
		return nil
	}
	return rt.inner.SnapshotStats()
}

func (rt *managedIPv6AssignmentRuntime) Close() error {
	if rt == nil || rt.inner == nil {
		return nil
	}
	preserve := false
	if preserver, ok := rt.ops.(ipv6AssignmentClosePreserver); ok {
		preserve = preserver.PreserveIPv6AssignmentStateOnClose()
	}
	return rt.inner.Close(preserve)
}

func collectIPv6AssignmentInterfaceNames(items []IPv6Assignment) (map[string]struct{}, int) {
	if len(items) == 0 {
		return nil, 0
	}
	names := make(map[string]struct{}, len(items)*2)
	count := 0
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		count++
		if name := strings.TrimSpace(item.ParentInterface); name != "" {
			names[name] = struct{}{}
		}
		if name := strings.TrimSpace(item.TargetInterface); name != "" {
			names[name] = struct{}{}
		}
	}
	if len(names) == 0 {
		return nil, count
	}
	return names, count
}

func cloneIPv6Net(prefix *net.IPNet) *net.IPNet {
	if prefix == nil {
		return nil
	}
	out := &net.IPNet{}
	if prefix.IP != nil {
		out.IP = append(net.IP(nil), prefix.IP...)
	}
	if prefix.Mask != nil {
		out.Mask = append(net.IPMask(nil), prefix.Mask...)
	}
	return out
}

func sortAndDedupeStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func (pm *ProcessManager) shouldRedistributeIPv6AssignmentsForInterface(name string) bool {
	if pm == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.ipv6AssignmentsConfigured {
		return false
	}
	name = strings.TrimSpace(name)
	if isManagedNetworkDynamicGuestLink(name) {
		return true
	}
	if name == "" || len(pm.ipv6AssignmentInterfaces) == 0 {
		return true
	}
	_, ok := pm.ipv6AssignmentInterfaces[name]
	return ok
}

func isManagedNetworkDynamicGuestLink(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	_, _, ok := parseManagedNetworkProxmoxGuestPort(name)
	if ok {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "tap")
}

func (pm *ProcessManager) snapshotIPv6AssignmentRuntimeStats() map[int64]ipv6AssignmentRuntimeStats {
	if pm == nil {
		return nil
	}

	pm.mu.Lock()
	rt := pm.ipv6Runtime
	pm.mu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.SnapshotStats()
}

func (pm *ProcessManager) snapshotManagedNetworkRuntimeStatus() map[int64]managedNetworkRuntimeStatus {
	if pm == nil {
		return nil
	}

	pm.mu.Lock()
	rt := pm.managedNetworkRuntime
	pm.mu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.SnapshotStatus()
}
