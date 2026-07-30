package netservice

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
)

type IPv6AssignmentRuntimeStats struct {
	RAAdvertisementCount uint64
	DHCPv6ReplyCount     uint64
	RuntimeStatus        string
	RuntimeDetail        string
}

type IPv6AssignmentPlan struct {
	ID              int64
	ParentInterface string
	TargetInterface string
	ParentPrefix    string
	AssignedPrefix  string
	AssignedAddress string
	ProxyAddress    string
	GatewayCIDR     string
	RejectPrefix    string
	DNSServers      []string
	NeedsForwarding bool
	NeedsProxyNDP   bool
	NeedsRA         bool
	IsSingleAddress bool
}

type IPv6AssignmentPlanIssue struct {
	ID      int64
	Summary string
	Detail  string
}

type IPv6RouteSpec struct {
	Prefix          string
	TargetInterface string
}

type IPv6AddressSpec struct {
	TargetInterface string
	CIDR            string
}

type IPv6RejectRouteSpec struct {
	Prefix string
}

type IPv6ProxySpec struct {
	ParentInterface string
	Address         string
}

type IPv6AssignmentNetOps interface {
	EnsureIPv6ForwardingEnabled() error
	EnsureIPv6ForwardingEnabledOnInterface(interfaceName string) error
	EnsureIPv6AcceptRAEnabled(interfaceName string) error
	EnsureIPv6ProxyNDPEnabled(parentInterface string) error
	EnsureIPv6Route(spec IPv6RouteSpec) error
	DeleteIPv6Route(spec IPv6RouteSpec) error
	EnsureIPv6Address(spec IPv6AddressSpec) error
	DeleteIPv6Address(spec IPv6AddressSpec) error
	EnsureIPv6RejectRoute(spec IPv6RejectRouteSpec) error
	DeleteIPv6RejectRoute(spec IPv6RejectRouteSpec) error
	EnsureIPv6Proxy(spec IPv6ProxySpec) error
	DeleteIPv6Proxy(spec IPv6ProxySpec) error
	EnsureIPv6RA(config RAConfig) error
	DeleteIPv6RA(targetInterface string) error
	EnsureIPv6DHCPv6(config DHCPv6Config) error
	DeleteIPv6DHCPv6(targetInterface string) error
	SnapshotIPv6AssignmentCounters() map[string]IPv6RuntimeCounter
}

type ipv6AssignmentRuntimeEntryState struct {
	ParentInterface string
	TargetInterface string
	AdvertisesRA    bool
	ServesDHCPv6    bool
}

type IPv6AssignmentRuntime struct {
	mu               sync.Mutex
	ops              IPv6AssignmentNetOps
	routes           map[IPv6RouteSpec]struct{}
	addresses        map[IPv6AddressSpec]struct{}
	rejectRoutes     map[IPv6RejectRouteSpec]struct{}
	proxies          map[IPv6ProxySpec]struct{}
	advertisements   map[string]RAConfig
	dhcpv6           map[string]DHCPv6Config
	assignmentStates map[int64]ipv6AssignmentRuntimeEntryState
	assignmentErrors map[int64][]string
}

func NewIPv6AssignmentRuntime(ops IPv6AssignmentNetOps) *IPv6AssignmentRuntime {
	if ops == nil {
		return nil
	}
	return &IPv6AssignmentRuntime{
		ops:              ops,
		routes:           make(map[IPv6RouteSpec]struct{}),
		addresses:        make(map[IPv6AddressSpec]struct{}),
		rejectRoutes:     make(map[IPv6RejectRouteSpec]struct{}),
		proxies:          make(map[IPv6ProxySpec]struct{}),
		advertisements:   make(map[string]RAConfig),
		dhcpv6:           make(map[string]DHCPv6Config),
		assignmentStates: make(map[int64]ipv6AssignmentRuntimeEntryState),
		assignmentErrors: make(map[int64][]string),
	}
}

func appendIPv6RuntimeError(store map[int64][]string, id int64, text string) {
	text = strings.TrimSpace(text)
	if id == 0 || text == "" {
		return
	}
	store[id] = append(store[id], text)
}

func appendIPv6RuntimeErrorMatching(store map[int64][]string, states map[int64]ipv6AssignmentRuntimeEntryState, text string, match func(ipv6AssignmentRuntimeEntryState) bool) {
	text = strings.TrimSpace(text)
	if text == "" || match == nil {
		return
	}
	for id, state := range states {
		if match(state) {
			appendIPv6RuntimeError(store, id, text)
		}
	}
}

func (rt *IPv6AssignmentRuntime) Reconcile(plans []IPv6AssignmentPlan, planIssues []IPv6AssignmentPlanIssue) error {
	if rt == nil || rt.ops == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	desiredRoutes := make(map[IPv6RouteSpec]struct{})
	desiredAddresses := make(map[IPv6AddressSpec]struct{})
	desiredRejectRoutes := make(map[IPv6RejectRouteSpec]struct{})
	desiredProxies := make(map[IPv6ProxySpec]struct{})
	desiredAdvertisements := make(map[string]RAConfig)
	desiredDHCPv6 := make(map[string]DHCPv6Config)
	desiredStates := make(map[int64]ipv6AssignmentRuntimeEntryState)
	desiredErrors := make(map[int64][]string)
	errs := make([]string, 0, len(planIssues))
	for _, issue := range planIssues {
		if summary := strings.TrimSpace(issue.Summary); summary != "" {
			errs = append(errs, summary)
		}
		appendIPv6RuntimeError(desiredErrors, issue.ID, issue.Detail)
	}

	needsForwarding := false
	forwardingInterfaces := make(map[string]struct{})
	parentInterfaces := make(map[string]struct{})
	for _, plan := range plans {
		if plan.ID == 0 {
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
		desiredStates[plan.ID] = ipv6AssignmentRuntimeEntryState{
			ParentInterface: plan.ParentInterface,
			TargetInterface: plan.TargetInterface,
			AdvertisesRA:    plan.NeedsRA || plan.IsSingleAddress,
			ServesDHCPv6:    plan.IsSingleAddress,
		}
		if plan.GatewayCIDR != "" {
			spec := IPv6AddressSpec{TargetInterface: plan.TargetInterface, CIDR: plan.GatewayCIDR}
			desiredAddresses[spec] = struct{}{}
			if err := rt.ops.EnsureIPv6Address(spec); err != nil {
				msg := fmt.Sprintf("assignment #%d gateway address %s on %s: %v", plan.ID, spec.CIDR, spec.TargetInterface, err)
				errs = append(errs, msg)
				appendIPv6RuntimeError(desiredErrors, plan.ID, fmt.Sprintf("gateway address %s on %s: %v", spec.CIDR, spec.TargetInterface, err))
			}
		}
		route := IPv6RouteSpec{Prefix: plan.AssignedPrefix, TargetInterface: plan.TargetInterface}
		desiredRoutes[route] = struct{}{}
		if err := rt.ops.EnsureIPv6Route(route); err != nil {
			msg := fmt.Sprintf("assignment #%d route %s via %s: %v", plan.ID, route.Prefix, route.TargetInterface, err)
			errs = append(errs, msg)
			appendIPv6RuntimeError(desiredErrors, plan.ID, fmt.Sprintf("route %s via %s: %v", route.Prefix, route.TargetInterface, err))
		}
		if plan.RejectPrefix != "" {
			reject := IPv6RejectRouteSpec{Prefix: plan.RejectPrefix}
			desiredRejectRoutes[reject] = struct{}{}
			if err := rt.ops.EnsureIPv6RejectRoute(reject); err != nil {
				msg := fmt.Sprintf("assignment #%d reject unassigned prefix %s: %v", plan.ID, reject.Prefix, err)
				errs = append(errs, msg)
				appendIPv6RuntimeError(desiredErrors, plan.ID, fmt.Sprintf("reject unassigned prefix %s: %v", reject.Prefix, err))
			}
		}
		if plan.NeedsRA {
			cfg := desiredAdvertisements[plan.TargetInterface]
			cfg.TargetInterface = plan.TargetInterface
			cfg.Prefixes = append(cfg.Prefixes, plan.AssignedPrefix)
			desiredAdvertisements[plan.TargetInterface] = cfg
		}
		if len(plan.DNSServers) > 0 {
			cfg := desiredAdvertisements[plan.TargetInterface]
			cfg.TargetInterface = plan.TargetInterface
			cfg.DNSServers = append(cfg.DNSServers, plan.DNSServers...)
			desiredAdvertisements[plan.TargetInterface] = cfg
		}
		if plan.IsSingleAddress {
			raCfg := desiredAdvertisements[plan.TargetInterface]
			raCfg.TargetInterface = plan.TargetInterface
			raCfg.Routes = append(raCfg.Routes, plan.ParentPrefix)
			desiredAdvertisements[plan.TargetInterface] = raCfg
			dhcpCfg := desiredDHCPv6[plan.TargetInterface]
			dhcpCfg.TargetInterface = plan.TargetInterface
			dhcpCfg.Addresses = append(dhcpCfg.Addresses, plan.AssignedAddress)
			dhcpCfg.DNSServers = append(dhcpCfg.DNSServers, plan.DNSServers...)
			desiredDHCPv6[plan.TargetInterface] = dhcpCfg
		}
		if !plan.NeedsProxyNDP {
			continue
		}
		if err := rt.ops.EnsureIPv6ProxyNDPEnabled(plan.ParentInterface); err != nil {
			msg := fmt.Sprintf("assignment #%d enable proxy_ndp on %s: %v", plan.ID, plan.ParentInterface, err)
			errs = append(errs, msg)
			appendIPv6RuntimeError(desiredErrors, plan.ID, fmt.Sprintf("enable proxy_ndp on %s: %v", plan.ParentInterface, err))
		}
		proxy := IPv6ProxySpec{ParentInterface: plan.ParentInterface, Address: plan.ProxyAddress}
		desiredProxies[proxy] = struct{}{}
		if err := rt.ops.EnsureIPv6Proxy(proxy); err != nil {
			msg := fmt.Sprintf("assignment #%d proxy ndp %s on %s: %v", plan.ID, proxy.Address, proxy.ParentInterface, err)
			errs = append(errs, msg)
			appendIPv6RuntimeError(desiredErrors, plan.ID, fmt.Sprintf("proxy ndp %s on %s: %v", proxy.Address, proxy.ParentInterface, err))
		}
	}

	if needsForwarding {
		if err := rt.ops.EnsureIPv6ForwardingEnabled(); err != nil {
			msg := fmt.Sprintf("enable ipv6 forwarding: %v", err)
			errs = append(errs, msg)
			for id := range desiredStates {
				appendIPv6RuntimeError(desiredErrors, id, msg)
			}
		}
	}
	for interfaceName := range forwardingInterfaces {
		if err := rt.ops.EnsureIPv6ForwardingEnabledOnInterface(interfaceName); err != nil {
			msg := fmt.Sprintf("enable ipv6 forwarding on %s: %v", interfaceName, err)
			errs = append(errs, msg)
			appendIPv6RuntimeErrorMatching(desiredErrors, desiredStates, msg, func(state ipv6AssignmentRuntimeEntryState) bool {
				return state.ParentInterface == interfaceName || state.TargetInterface == interfaceName
			})
		}
	}
	for parentInterface := range parentInterfaces {
		if err := rt.ops.EnsureIPv6AcceptRAEnabled(parentInterface); err != nil {
			msg := fmt.Sprintf("enable ipv6 accept_ra on %s: %v", parentInterface, err)
			errs = append(errs, msg)
			appendIPv6RuntimeErrorMatching(desiredErrors, desiredStates, msg, func(state ipv6AssignmentRuntimeEntryState) bool {
				return state.ParentInterface == parentInterface
			})
		}
	}
	for targetInterface, cfg := range desiredDHCPv6 {
		cfg.Addresses = sortAndDedupe(cfg.Addresses)
		cfg.DNSServers = sortAndDedupe(cfg.DNSServers)
		raCfg := desiredAdvertisements[targetInterface]
		raCfg.TargetInterface = targetInterface
		raCfg.Managed = true
		desiredAdvertisements[targetInterface] = raCfg
		desiredDHCPv6[targetInterface] = cfg
	}
	for targetInterface, cfg := range desiredAdvertisements {
		cfg.Prefixes = sortAndDedupe(cfg.Prefixes)
		cfg.Routes = sortAndDedupe(cfg.Routes)
		cfg.DNSServers = sortAndDedupe(cfg.DNSServers)
		if err := rt.ops.EnsureIPv6RA(cfg); err != nil {
			msg := fmt.Sprintf("advertise ipv6 on %s: %v", targetInterface, err)
			errs = append(errs, msg)
			appendIPv6RuntimeErrorMatching(desiredErrors, desiredStates, msg, func(state ipv6AssignmentRuntimeEntryState) bool {
				return state.TargetInterface == targetInterface && state.AdvertisesRA
			})
		}
	}
	for targetInterface, cfg := range desiredDHCPv6 {
		if err := rt.ops.EnsureIPv6DHCPv6(cfg); err != nil {
			msg := fmt.Sprintf("serve dhcpv6 on %s: %v", targetInterface, err)
			errs = append(errs, msg)
			appendIPv6RuntimeErrorMatching(desiredErrors, desiredStates, msg, func(state ipv6AssignmentRuntimeEntryState) bool {
				return state.TargetInterface == targetInterface && state.ServesDHCPv6
			})
		}
	}

	for route := range rt.routes {
		if _, ok := desiredRoutes[route]; !ok {
			if err := rt.ops.DeleteIPv6Route(route); err != nil {
				errs = append(errs, fmt.Sprintf("remove ipv6 route %s via %s: %v", route.Prefix, route.TargetInterface, err))
			}
		}
	}
	for reject := range rt.rejectRoutes {
		if _, ok := desiredRejectRoutes[reject]; !ok {
			if err := rt.ops.DeleteIPv6RejectRoute(reject); err != nil {
				errs = append(errs, fmt.Sprintf("remove ipv6 reject route %s: %v", reject.Prefix, err))
			}
		}
	}
	for address := range rt.addresses {
		if _, ok := desiredAddresses[address]; !ok {
			if err := rt.ops.DeleteIPv6Address(address); err != nil {
				errs = append(errs, fmt.Sprintf("remove ipv6 gateway address %s on %s: %v", address.CIDR, address.TargetInterface, err))
			}
		}
	}
	for proxy := range rt.proxies {
		if _, ok := desiredProxies[proxy]; !ok {
			if err := rt.ops.DeleteIPv6Proxy(proxy); err != nil {
				errs = append(errs, fmt.Sprintf("remove proxy ndp %s on %s: %v", proxy.Address, proxy.ParentInterface, err))
			}
		}
	}
	for target := range rt.advertisements {
		if _, ok := desiredAdvertisements[target]; !ok {
			if err := rt.ops.DeleteIPv6RA(target); err != nil {
				errs = append(errs, fmt.Sprintf("remove router advertisement on %s: %v", target, err))
			}
		}
	}
	for target := range rt.dhcpv6 {
		if _, ok := desiredDHCPv6[target]; !ok {
			if err := rt.ops.DeleteIPv6DHCPv6(target); err != nil {
				errs = append(errs, fmt.Sprintf("remove dhcpv6 on %s: %v", target, err))
			}
		}
	}

	rt.routes = desiredRoutes
	rt.addresses = desiredAddresses
	rt.rejectRoutes = desiredRejectRoutes
	rt.proxies = desiredProxies
	rt.advertisements = desiredAdvertisements
	rt.dhcpv6 = desiredDHCPv6
	rt.assignmentStates = desiredStates
	rt.assignmentErrors = desiredErrors
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func (rt *IPv6AssignmentRuntime) SnapshotStats() map[int64]IPv6AssignmentRuntimeStats {
	if rt == nil || rt.ops == nil {
		return nil
	}
	rt.mu.Lock()
	states := make(map[int64]ipv6AssignmentRuntimeEntryState, len(rt.assignmentStates))
	for id, state := range rt.assignmentStates {
		states[id] = state
	}
	errorsByID := make(map[int64][]string, len(rt.assignmentErrors))
	for id, errs := range rt.assignmentErrors {
		errorsByID[id] = append([]string(nil), errs...)
	}
	rt.mu.Unlock()
	if len(states) == 0 && len(errorsByID) == 0 {
		return nil
	}
	counters := rt.ops.SnapshotIPv6AssignmentCounters()
	allIDs := make(map[int64]struct{}, len(states)+len(errorsByID))
	for id := range states {
		allIDs[id] = struct{}{}
	}
	for id := range errorsByID {
		allIDs[id] = struct{}{}
	}
	stats := make(map[int64]IPv6AssignmentRuntimeStats, len(allIDs))
	for id := range allIDs {
		state := states[id]
		counter := counters[state.TargetInterface]
		stat := IPv6AssignmentRuntimeStats{}
		if state.AdvertisesRA {
			stat.RAAdvertisementCount = counter.RAAdvertisementCount
		}
		if state.ServesDHCPv6 {
			stat.DHCPv6ReplyCount = counter.DHCPv6ReplyCount
		}
		details := append([]string(nil), errorsByID[id]...)
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
		case len(errorsByID[id]) > 0:
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
		stat.RuntimeDetail = strings.Join(sortAndDedupe(details), "; ")
		stats[id] = stat
	}
	return stats
}

func (rt *IPv6AssignmentRuntime) Close(preserve bool) error {
	if rt == nil || rt.ops == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if preserve {
		log.Printf("ipv6 assignment runtime: preserving applied state for hot restart (routes=%d addresses=%d reject_routes=%d proxies=%d ra=%d dhcpv6=%d)", len(rt.routes), len(rt.addresses), len(rt.rejectRoutes), len(rt.proxies), len(rt.advertisements), len(rt.dhcpv6))
		rt.reset()
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
	for reject := range rt.rejectRoutes {
		if err := rt.ops.DeleteIPv6RejectRoute(reject); err != nil {
			errs = append(errs, fmt.Sprintf("remove ipv6 reject route %s: %v", reject.Prefix, err))
		}
	}
	for address := range rt.addresses {
		if err := rt.ops.DeleteIPv6Address(address); err != nil {
			errs = append(errs, fmt.Sprintf("remove ipv6 gateway address %s on %s: %v", address.CIDR, address.TargetInterface, err))
		}
	}
	for target := range rt.advertisements {
		if err := rt.ops.DeleteIPv6RA(target); err != nil {
			errs = append(errs, fmt.Sprintf("remove router advertisement on %s: %v", target, err))
		}
	}
	for target := range rt.dhcpv6 {
		if err := rt.ops.DeleteIPv6DHCPv6(target); err != nil {
			errs = append(errs, fmt.Sprintf("remove dhcpv6 on %s: %v", target, err))
		}
	}
	rt.reset()
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func (rt *IPv6AssignmentRuntime) reset() {
	rt.routes = make(map[IPv6RouteSpec]struct{})
	rt.addresses = make(map[IPv6AddressSpec]struct{})
	rt.rejectRoutes = make(map[IPv6RejectRouteSpec]struct{})
	rt.proxies = make(map[IPv6ProxySpec]struct{})
	rt.advertisements = make(map[string]RAConfig)
	rt.dhcpv6 = make(map[string]DHCPv6Config)
	rt.assignmentStates = make(map[int64]ipv6AssignmentRuntimeEntryState)
	rt.assignmentErrors = make(map[int64][]string)
}

func sortAndDedupe(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
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
