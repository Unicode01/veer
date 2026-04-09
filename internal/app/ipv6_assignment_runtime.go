package app

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
)

type ipv6AssignmentRuntime interface {
	Reconcile(items []IPv6Assignment) error
	SnapshotStats() map[int64]ipv6AssignmentRuntimeStats
	Close() error
}

type ipv6AssignmentRuntimeStats struct {
	RAAdvertisementCount uint64
	DHCPv6ReplyCount     uint64
	RuntimeStatus        string
	RuntimeDetail        string
}

type ipv6AssignmentRuntimeCounter struct {
	RAAdvertisementCount uint64
	DHCPv6ReplyCount     uint64
	RAStatus             string
	RAStatusDetail       string
	DHCPv6Status         string
	DHCPv6StatusDetail   string
}

type ipv6AssignmentRuntimeEntryState struct {
	ParentInterface string
	TargetInterface string
	AdvertisesRA    bool
	ServesDHCPv6    bool
}

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
}

type ipv6AssignmentRouteSpec struct {
	Prefix          string
	TargetInterface string
}

type ipv6AssignmentProxySpec struct {
	ParentInterface string
	Address         string
}

type ipv6AssignmentRAConfig struct {
	TargetInterface string
	Managed         bool
	Prefixes        []string
	Routes          []string
}

type ipv6AssignmentDHCPv6Config struct {
	TargetInterface string
	Addresses       []string
}

type ipv6AssignmentNetOps interface {
	EnsureIPv6ForwardingEnabled() error
	EnsureIPv6ForwardingEnabledOnInterface(interfaceName string) error
	EnsureIPv6AcceptRAEnabled(interfaceName string) error
	EnsureIPv6ProxyNDPEnabled(parentInterface string) error
	EnsureIPv6Route(spec ipv6AssignmentRouteSpec) error
	DeleteIPv6Route(spec ipv6AssignmentRouteSpec) error
	EnsureIPv6Proxy(spec ipv6AssignmentProxySpec) error
	DeleteIPv6Proxy(spec ipv6AssignmentProxySpec) error
	EnsureIPv6RA(config ipv6AssignmentRAConfig) error
	DeleteIPv6RA(targetInterface string) error
	EnsureIPv6DHCPv6(config ipv6AssignmentDHCPv6Config) error
	DeleteIPv6DHCPv6(targetInterface string) error
	SnapshotIPv6AssignmentCounters() map[string]ipv6AssignmentRuntimeCounter
}

type ipv6AssignmentClosePreserver interface {
	PreserveIPv6AssignmentStateOnClose() bool
}

type managedIPv6AssignmentRuntime struct {
	mu               sync.Mutex
	ops              ipv6AssignmentNetOps
	routes           map[ipv6AssignmentRouteSpec]struct{}
	proxies          map[ipv6AssignmentProxySpec]struct{}
	advertisements   map[string]ipv6AssignmentRAConfig
	dhcpv6           map[string]ipv6AssignmentDHCPv6Config
	assignmentStates map[int64]ipv6AssignmentRuntimeEntryState
	assignmentErrors map[int64][]string
}

func newManagedIPv6AssignmentRuntime(ops ipv6AssignmentNetOps) ipv6AssignmentRuntime {
	if ops == nil {
		return nil
	}
	return &managedIPv6AssignmentRuntime{
		ops:              ops,
		routes:           make(map[ipv6AssignmentRouteSpec]struct{}),
		proxies:          make(map[ipv6AssignmentProxySpec]struct{}),
		advertisements:   make(map[string]ipv6AssignmentRAConfig),
		dhcpv6:           make(map[string]ipv6AssignmentDHCPv6Config),
		assignmentStates: make(map[int64]ipv6AssignmentRuntimeEntryState),
		assignmentErrors: make(map[int64][]string),
	}
}

func appendIPv6AssignmentRuntimeError(store map[int64][]string, id int64, text string) {
	text = strings.TrimSpace(text)
	if id <= 0 || text == "" {
		return
	}
	store[id] = append(store[id], text)
}

func appendIPv6AssignmentRuntimeErrorToAll(store map[int64][]string, states map[int64]ipv6AssignmentRuntimeEntryState, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	for id := range states {
		appendIPv6AssignmentRuntimeError(store, id, text)
	}
}

func appendIPv6AssignmentRuntimeErrorMatching(store map[int64][]string, states map[int64]ipv6AssignmentRuntimeEntryState, text string, match func(ipv6AssignmentRuntimeEntryState) bool) {
	text = strings.TrimSpace(text)
	if text == "" || match == nil {
		return
	}
	for id, state := range states {
		if !match(state) {
			continue
		}
		appendIPv6AssignmentRuntimeError(store, id, text)
	}
}

func appendIPv6AssignmentRuntimeErrorForInterface(store map[int64][]string, states map[int64]ipv6AssignmentRuntimeEntryState, interfaceName string, text string) {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return
	}
	appendIPv6AssignmentRuntimeErrorMatching(store, states, text, func(state ipv6AssignmentRuntimeEntryState) bool {
		return state.ParentInterface == interfaceName || state.TargetInterface == interfaceName
	})
}

func appendIPv6AssignmentRuntimeErrorForParentInterface(store map[int64][]string, states map[int64]ipv6AssignmentRuntimeEntryState, parentInterface string, text string) {
	parentInterface = strings.TrimSpace(parentInterface)
	if parentInterface == "" {
		return
	}
	appendIPv6AssignmentRuntimeErrorMatching(store, states, text, func(state ipv6AssignmentRuntimeEntryState) bool {
		return state.ParentInterface == parentInterface
	})
}

func appendIPv6AssignmentRuntimeErrorForRAInterface(store map[int64][]string, states map[int64]ipv6AssignmentRuntimeEntryState, targetInterface string, text string) {
	targetInterface = strings.TrimSpace(targetInterface)
	if targetInterface == "" {
		return
	}
	appendIPv6AssignmentRuntimeErrorMatching(store, states, text, func(state ipv6AssignmentRuntimeEntryState) bool {
		return state.TargetInterface == targetInterface && state.AdvertisesRA
	})
}

func appendIPv6AssignmentRuntimeErrorForDHCPv6Interface(store map[int64][]string, states map[int64]ipv6AssignmentRuntimeEntryState, targetInterface string, text string) {
	targetInterface = strings.TrimSpace(targetInterface)
	if targetInterface == "" {
		return
	}
	appendIPv6AssignmentRuntimeErrorMatching(store, states, text, func(state ipv6AssignmentRuntimeEntryState) bool {
		return state.TargetInterface == targetInterface && state.ServesDHCPv6
	})
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
	}
	if plan.NeedsProxyNDP {
		plan.ProxyAddress = canonicalIPLiteral(assignedNet.IP)
	}
	return plan, nil
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

func (rt *managedIPv6AssignmentRuntime) Reconcile(items []IPv6Assignment) error {
	if rt == nil || rt.ops == nil {
		return nil
	}

	hostIfaceByName := map[string]HostNetworkInterface{}
	if hostIfaces, err := loadCurrentHostNetworkInterfaces(); err == nil {
		hostIfaceByName = buildHostNetworkInterfaceMap(hostIfaces)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	desiredRoutes := make(map[ipv6AssignmentRouteSpec]struct{})
	desiredProxies := make(map[ipv6AssignmentProxySpec]struct{})
	desiredAdvertisements := make(map[string]ipv6AssignmentRAConfig)
	desiredDHCPv6 := make(map[string]ipv6AssignmentDHCPv6Config)
	desiredAssignmentStates := make(map[int64]ipv6AssignmentRuntimeEntryState)
	desiredAssignmentErrors := make(map[int64][]string)
	errs := make([]string, 0)
	needsForwarding := false
	forwardingInterfaces := make(map[string]struct{})
	parentInterfaces := make(map[string]struct{})

	for _, item := range items {
		if !item.Enabled {
			continue
		}
		resolvedItem, _, err := resolveIPv6AssignmentForCurrentHost(item, hostIfaceByName)
		if err != nil {
			msg := fmt.Sprintf("assignment #%d resolve current parent prefix: %v", item.ID, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeError(desiredAssignmentErrors, item.ID, fmt.Sprintf("resolve current parent prefix: %v", err))
			continue
		}
		plan, err := buildIPv6AssignmentRuntimePlan(resolvedItem)
		if err != nil {
			errs = append(errs, err.Error())
			appendIPv6AssignmentRuntimeError(desiredAssignmentErrors, item.ID, err.Error())
			continue
		}
		if plan.NeedsForwarding {
			needsForwarding = true
			if plan.ParentInterface != "" {
				parentInterfaces[plan.ParentInterface] = struct{}{}
				forwardingInterfaces[plan.ParentInterface] = struct{}{}
			}
			if plan.TargetInterface != "" {
				forwardingInterfaces[plan.TargetInterface] = struct{}{}
			}
		}
		desiredAssignmentStates[item.ID] = ipv6AssignmentRuntimeEntryState{
			ParentInterface: plan.ParentInterface,
			TargetInterface: plan.TargetInterface,
			AdvertisesRA:    plan.NeedsRADvertise || plan.Intent.kind == ipv6AssignmentIntentSingleAddress,
			ServesDHCPv6:    plan.Intent.kind == ipv6AssignmentIntentSingleAddress,
		}
		routeSpec := ipv6AssignmentRouteSpec{
			Prefix:          plan.AssignedPrefix,
			TargetInterface: plan.TargetInterface,
		}
		desiredRoutes[routeSpec] = struct{}{}
		if err := rt.ops.EnsureIPv6Route(routeSpec); err != nil {
			msg := fmt.Sprintf("assignment #%d route %s via %s: %v", plan.ID, routeSpec.Prefix, routeSpec.TargetInterface, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeError(desiredAssignmentErrors, plan.ID, fmt.Sprintf("route %s via %s: %v", routeSpec.Prefix, routeSpec.TargetInterface, err))
		}
		if plan.NeedsRADvertise {
			cfg := desiredAdvertisements[plan.TargetInterface]
			cfg.TargetInterface = plan.TargetInterface
			cfg.Prefixes = append(cfg.Prefixes, plan.AssignedPrefix)
			desiredAdvertisements[plan.TargetInterface] = cfg
		}
		if plan.Intent.kind == ipv6AssignmentIntentSingleAddress {
			raCfg := desiredAdvertisements[plan.TargetInterface]
			raCfg.TargetInterface = plan.TargetInterface
			raCfg.Routes = append(raCfg.Routes, plan.ParentPrefix)
			desiredAdvertisements[plan.TargetInterface] = raCfg

			cfg := desiredDHCPv6[plan.TargetInterface]
			cfg.TargetInterface = plan.TargetInterface
			cfg.Addresses = append(cfg.Addresses, canonicalIPLiteral(plan.AssignedPrefixNet.IP))
			desiredDHCPv6[plan.TargetInterface] = cfg
		}
		if !plan.NeedsProxyNDP {
			continue
		}
		if err := rt.ops.EnsureIPv6ProxyNDPEnabled(plan.ParentInterface); err != nil {
			msg := fmt.Sprintf("assignment #%d enable proxy_ndp on %s: %v", plan.ID, plan.ParentInterface, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeError(desiredAssignmentErrors, plan.ID, fmt.Sprintf("enable proxy_ndp on %s: %v", plan.ParentInterface, err))
		}
		proxySpec := ipv6AssignmentProxySpec{
			ParentInterface: plan.ParentInterface,
			Address:         plan.ProxyAddress,
		}
		desiredProxies[proxySpec] = struct{}{}
		if err := rt.ops.EnsureIPv6Proxy(proxySpec); err != nil {
			msg := fmt.Sprintf("assignment #%d proxy ndp %s on %s: %v", plan.ID, proxySpec.Address, proxySpec.ParentInterface, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeError(desiredAssignmentErrors, plan.ID, fmt.Sprintf("proxy ndp %s on %s: %v", proxySpec.Address, proxySpec.ParentInterface, err))
		}
	}

	if needsForwarding {
		if err := rt.ops.EnsureIPv6ForwardingEnabled(); err != nil {
			msg := fmt.Sprintf("enable ipv6 forwarding: %v", err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeErrorToAll(desiredAssignmentErrors, desiredAssignmentStates, msg)
		}
	}
	for interfaceName := range forwardingInterfaces {
		if err := rt.ops.EnsureIPv6ForwardingEnabledOnInterface(interfaceName); err != nil {
			msg := fmt.Sprintf("enable ipv6 forwarding on %s: %v", interfaceName, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeErrorForInterface(desiredAssignmentErrors, desiredAssignmentStates, interfaceName, msg)
		}
	}
	for parentInterface := range parentInterfaces {
		if err := rt.ops.EnsureIPv6AcceptRAEnabled(parentInterface); err != nil {
			msg := fmt.Sprintf("enable ipv6 accept_ra on %s: %v", parentInterface, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeErrorForParentInterface(desiredAssignmentErrors, desiredAssignmentStates, parentInterface, msg)
		}
	}
	for targetInterface, cfg := range desiredDHCPv6 {
		cfg.Addresses = sortAndDedupeStrings(cfg.Addresses)
		raCfg := desiredAdvertisements[targetInterface]
		raCfg.TargetInterface = targetInterface
		raCfg.Managed = true
		desiredAdvertisements[targetInterface] = raCfg
		desiredDHCPv6[targetInterface] = cfg
	}
	for targetInterface, cfg := range desiredAdvertisements {
		cfg.Prefixes = sortAndDedupeStrings(cfg.Prefixes)
		cfg.Routes = sortAndDedupeStrings(cfg.Routes)
		if err := rt.ops.EnsureIPv6RA(cfg); err != nil {
			msg := fmt.Sprintf("advertise ipv6 on %s: %v", targetInterface, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeErrorForRAInterface(desiredAssignmentErrors, desiredAssignmentStates, targetInterface, msg)
		}
	}
	for targetInterface, cfg := range desiredDHCPv6 {
		if err := rt.ops.EnsureIPv6DHCPv6(cfg); err != nil {
			msg := fmt.Sprintf("serve dhcpv6 on %s: %v", targetInterface, err)
			errs = append(errs, msg)
			appendIPv6AssignmentRuntimeErrorForDHCPv6Interface(desiredAssignmentErrors, desiredAssignmentStates, targetInterface, msg)
		}
	}

	for route := range rt.routes {
		if _, ok := desiredRoutes[route]; ok {
			continue
		}
		if err := rt.ops.DeleteIPv6Route(route); err != nil {
			errs = append(errs, fmt.Sprintf("remove ipv6 route %s via %s: %v", route.Prefix, route.TargetInterface, err))
		}
	}
	for proxy := range rt.proxies {
		if _, ok := desiredProxies[proxy]; ok {
			continue
		}
		if err := rt.ops.DeleteIPv6Proxy(proxy); err != nil {
			errs = append(errs, fmt.Sprintf("remove proxy ndp %s on %s: %v", proxy.Address, proxy.ParentInterface, err))
		}
	}
	for targetInterface := range rt.advertisements {
		if _, ok := desiredAdvertisements[targetInterface]; ok {
			continue
		}
		if err := rt.ops.DeleteIPv6RA(targetInterface); err != nil {
			errs = append(errs, fmt.Sprintf("remove router advertisement on %s: %v", targetInterface, err))
		}
	}
	for targetInterface := range rt.dhcpv6 {
		if _, ok := desiredDHCPv6[targetInterface]; ok {
			continue
		}
		if err := rt.ops.DeleteIPv6DHCPv6(targetInterface); err != nil {
			errs = append(errs, fmt.Sprintf("remove dhcpv6 on %s: %v", targetInterface, err))
		}
	}

	rt.routes = desiredRoutes
	rt.proxies = desiredProxies
	rt.advertisements = desiredAdvertisements
	rt.dhcpv6 = desiredDHCPv6
	rt.assignmentStates = desiredAssignmentStates
	rt.assignmentErrors = desiredAssignmentErrors
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func (rt *managedIPv6AssignmentRuntime) SnapshotStats() map[int64]ipv6AssignmentRuntimeStats {
	if rt == nil || rt.ops == nil {
		return nil
	}

	rt.mu.Lock()
	assignmentStates := make(map[int64]ipv6AssignmentRuntimeEntryState, len(rt.assignmentStates))
	for id, state := range rt.assignmentStates {
		assignmentStates[id] = state
	}
	assignmentErrors := make(map[int64][]string, len(rt.assignmentErrors))
	for id, errs := range rt.assignmentErrors {
		assignmentErrors[id] = append([]string(nil), errs...)
	}
	rt.mu.Unlock()

	if len(assignmentStates) == 0 && len(assignmentErrors) == 0 {
		return nil
	}

	counters := rt.ops.SnapshotIPv6AssignmentCounters()
	allIDs := make(map[int64]struct{}, len(assignmentStates)+len(assignmentErrors))
	for id := range assignmentStates {
		allIDs[id] = struct{}{}
	}
	for id := range assignmentErrors {
		allIDs[id] = struct{}{}
	}
	stats := make(map[int64]ipv6AssignmentRuntimeStats, len(allIDs))
	for id := range allIDs {
		state := assignmentStates[id]
		counter := counters[state.TargetInterface]
		stat := ipv6AssignmentRuntimeStats{}
		if state.AdvertisesRA {
			stat.RAAdvertisementCount = counter.RAAdvertisementCount
		}
		if state.ServesDHCPv6 {
			stat.DHCPv6ReplyCount = counter.DHCPv6ReplyCount
		}
		details := append([]string(nil), assignmentErrors[id]...)
		componentStatuses := make([]string, 0, 2)
		if state.AdvertisesRA {
			if strings.TrimSpace(counter.RAStatusDetail) != "" {
				details = append(details, "router advertisement: "+counter.RAStatusDetail)
			}
			componentStatuses = append(componentStatuses, strings.TrimSpace(counter.RAStatus))
		}
		if state.ServesDHCPv6 {
			if strings.TrimSpace(counter.DHCPv6StatusDetail) != "" {
				details = append(details, "dhcpv6: "+counter.DHCPv6StatusDetail)
			}
			componentStatuses = append(componentStatuses, strings.TrimSpace(counter.DHCPv6Status))
		}
		switch {
		case len(assignmentErrors[id]) > 0:
			stat.RuntimeStatus = "error"
		case len(componentStatuses) == 0:
			stat.RuntimeStatus = "running"
			details = append(details, "route/proxy only")
		default:
			stat.RuntimeStatus = "running"
			for _, status := range componentStatuses {
				switch status {
				case "error":
					stat.RuntimeStatus = "error"
				case "draining":
					if stat.RuntimeStatus != "error" {
						stat.RuntimeStatus = "draining"
					}
				case "":
					if stat.RuntimeStatus != "error" {
						stat.RuntimeStatus = "draining"
					}
				}
			}
		}
		stat.RuntimeDetail = strings.Join(sortAndDedupeStrings(details), "; ")
		stats[id] = stat
	}
	return stats
}

func (rt *managedIPv6AssignmentRuntime) Close() error {
	if rt == nil || rt.ops == nil {
		return nil
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if preserver, ok := rt.ops.(ipv6AssignmentClosePreserver); ok && preserver.PreserveIPv6AssignmentStateOnClose() {
		log.Printf("ipv6 assignment runtime: preserving applied state for hot restart (routes=%d proxies=%d ra=%d dhcpv6=%d)", len(rt.routes), len(rt.proxies), len(rt.advertisements), len(rt.dhcpv6))
		rt.routes = make(map[ipv6AssignmentRouteSpec]struct{})
		rt.proxies = make(map[ipv6AssignmentProxySpec]struct{})
		rt.advertisements = make(map[string]ipv6AssignmentRAConfig)
		rt.dhcpv6 = make(map[string]ipv6AssignmentDHCPv6Config)
		rt.assignmentStates = make(map[int64]ipv6AssignmentRuntimeEntryState)
		rt.assignmentErrors = make(map[int64][]string)
		return nil
	}

	errs := make([]string, 0)
	for proxy := range rt.proxies {
		if err := rt.ops.DeleteIPv6Proxy(proxy); err != nil {
			errs = append(errs, fmt.Sprintf("remove proxy ndp %s on %s: %v", proxy.Address, proxy.ParentInterface, err))
		}
	}
	for route := range rt.routes {
		if err := rt.ops.DeleteIPv6Route(route); err != nil {
			errs = append(errs, fmt.Sprintf("remove ipv6 route %s via %s: %v", route.Prefix, route.TargetInterface, err))
		}
	}
	for targetInterface := range rt.advertisements {
		if err := rt.ops.DeleteIPv6RA(targetInterface); err != nil {
			errs = append(errs, fmt.Sprintf("remove router advertisement on %s: %v", targetInterface, err))
		}
	}
	for targetInterface := range rt.dhcpv6 {
		if err := rt.ops.DeleteIPv6DHCPv6(targetInterface); err != nil {
			errs = append(errs, fmt.Sprintf("remove dhcpv6 on %s: %v", targetInterface, err))
		}
	}
	rt.routes = make(map[ipv6AssignmentRouteSpec]struct{})
	rt.proxies = make(map[ipv6AssignmentProxySpec]struct{})
	rt.advertisements = make(map[string]ipv6AssignmentRAConfig)
	rt.dhcpv6 = make(map[string]ipv6AssignmentDHCPv6Config)
	rt.assignmentStates = make(map[int64]ipv6AssignmentRuntimeEntryState)
	rt.assignmentErrors = make(map[int64][]string)
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
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
