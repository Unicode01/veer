package managednet

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

type Runtime interface {
	Reconcile(items []ManagedNetwork, reservations []ManagedNetworkReservation) error
	SnapshotStatus() map[int64]RuntimeStatus
	Close() error
}

type RuntimeStatus struct {
	RuntimeStatus    string
	RuntimeDetail    string
	DHCPv4ReplyCount uint64
}

type IPv4AddressSpec struct {
	InterfaceName string
	CIDR          string
}

type DHCPv4Reservation struct {
	MACAddress  string
	IPv4Address string
	Remark      string
}

type DHCPv4Config struct {
	Bridge          string
	UplinkInterface string
	ServerCIDR      string
	ServerIP        string
	Gateway         string
	PoolStart       string
	PoolEnd         string
	DNSServers      []string
	Reservations    []DHCPv4Reservation
}

type InterfaceSpec struct {
	Name            string
	Mode            string
	BridgeMTU       int
	BridgeVLANAware bool
}

type DHCPv4RuntimeState struct {
	Status     string
	Detail     string
	ReplyCount uint64
}

type NetOps interface {
	EnsureIPv4ForwardingEnabled() error
	EnsureIPv4ForwardingEnabledOnInterface(interfaceName string) error
	EnsureManagedNetworkInterface(spec InterfaceSpec) error
	EnsureManagedNetworkIPv4Address(spec IPv4AddressSpec) error
	DeleteManagedNetworkIPv4Address(spec IPv4AddressSpec) error
	EnsureManagedNetworkDHCPv4(config DHCPv4Config) error
	DeleteManagedNetworkDHCPv4(bridge string) error
	SnapshotManagedNetworkDHCPv4States() map[string]DHCPv4RuntimeState
}

type IPv4Plan struct {
	ID              int64
	Name            string
	BridgeMode      string
	Bridge          string
	UplinkInterface string
	AddressSpec     IPv4AddressSpec
	DHCPv4          DHCPv4Config
	NeedsForwarding bool
}

type IPv4Runtime struct {
	mu                   sync.Mutex
	ops                  NetOps
	preserveStateOnClose func() bool
	addresses            map[string]IPv4AddressSpec
	dhcpv4               map[string]DHCPv4Config
	bridges              map[int64]string
	status               map[int64]RuntimeStatus
}

func NewIPv4Runtime(ops NetOps, preserveStateOnClose func() bool) *IPv4Runtime {
	if ops == nil {
		return nil
	}
	return &IPv4Runtime{
		ops:                  ops,
		preserveStateOnClose: preserveStateOnClose,
		addresses:            make(map[string]IPv4AddressSpec),
		dhcpv4:               make(map[string]DHCPv4Config),
		bridges:              make(map[int64]string),
		status:               make(map[int64]RuntimeStatus),
	}
}

func InterfaceSpecForItem(item ManagedNetwork) InterfaceSpec {
	item = normalizeManagedNetwork(item)
	return InterfaceSpec{
		Name:            item.Bridge,
		Mode:            item.BridgeMode,
		BridgeMTU:       item.BridgeMTU,
		BridgeVLANAware: item.BridgeVLANAware,
	}
}

func BuildIPv4Plan(item ManagedNetwork, reservations []ManagedNetworkReservation) (IPv4Plan, error) {
	item = normalizeManagedNetwork(item)
	if !item.Enabled || !item.IPv4Enabled {
		return IPv4Plan{}, errors.New("ipv4 is disabled")
	}
	if item.Bridge == "" {
		return IPv4Plan{}, fmt.Errorf("bridge is required")
	}

	serverCIDR, serverIP, subnet, err := normalizeManagedNetworkIPv4CIDR(item.IPv4CIDR)
	if err != nil {
		return IPv4Plan{}, err
	}
	gateway, err := normalizeManagedNetworkIPv4Gateway(item.IPv4Gateway, serverIP)
	if err != nil {
		return IPv4Plan{}, err
	}
	poolStart, poolEnd, err := normalizeManagedNetworkIPv4Pool(item.IPv4PoolStart, item.IPv4PoolEnd, serverIP, subnet)
	if err != nil {
		return IPv4Plan{}, err
	}
	dnsServers, err := normalizeManagedNetworkIPv4DNSServers(item.IPv4DNSServers)
	if err != nil {
		return IPv4Plan{}, err
	}

	return IPv4Plan{
		ID:              item.ID,
		Name:            item.Name,
		BridgeMode:      item.BridgeMode,
		Bridge:          item.Bridge,
		UplinkInterface: item.UplinkInterface,
		AddressSpec: IPv4AddressSpec{
			InterfaceName: item.Bridge,
			CIDR:          serverCIDR,
		},
		DHCPv4: DHCPv4Config{
			Bridge:          item.Bridge,
			UplinkInterface: item.UplinkInterface,
			ServerCIDR:      serverCIDR,
			ServerIP:        serverIP,
			Gateway:         gateway,
			PoolStart:       poolStart,
			PoolEnd:         poolEnd,
			DNSServers:      dnsServers,
			Reservations:    buildManagedNetworkDHCPv4Reservations(reservations),
		},
		NeedsForwarding: strings.TrimSpace(item.UplinkInterface) != "",
	}, nil
}

func NormalizeIPv4CIDR(value string) (string, string, *net.IPNet, error) {
	return normalizeManagedNetworkIPv4CIDR(value)
}

func NormalizeIPv4Gateway(value string, serverIP string) (string, error) {
	return normalizeManagedNetworkIPv4Gateway(value, serverIP)
}

func NormalizeIPv4Literal(value string) (string, error) {
	return normalizeManagedNetworkIPv4Literal(value)
}

func IsReservedIPv4Host(ip net.IP, network net.IP, mask net.IPMask) bool {
	return isManagedNetworkIPv4ReservedHost(ip, network, mask)
}

func (rt *IPv4Runtime) Reconcile(items []ManagedNetwork, reservations []ManagedNetworkReservation) error {
	if rt == nil || rt.ops == nil {
		return nil
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	desiredAddresses := make(map[string]IPv4AddressSpec)
	desiredDHCPv4 := make(map[string]DHCPv4Config)
	desiredBridges := make(map[int64]string)
	desiredForwarding := make(map[string]struct{})
	desiredInterfaces := make(map[string]InterfaceSpec)
	plansByBridge := make(map[string]IPv4Plan)
	reservationsByNetwork := make(map[int64][]ManagedNetworkReservation)
	desiredStatus := make(map[int64]RuntimeStatus)
	errs := make([]string, 0)
	markBridgeError := func(bridge string, detail string) {
		plan, ok := plansByBridge[bridge]
		if !ok {
			return
		}
		desiredStatus[plan.ID] = RuntimeStatus{
			RuntimeStatus: "error",
			RuntimeDetail: strings.TrimSpace(detail),
		}
	}
	markPlanError := func(id int64, detail string) {
		if id <= 0 {
			return
		}
		desiredStatus[id] = RuntimeStatus{
			RuntimeStatus: "error",
			RuntimeDetail: strings.TrimSpace(detail),
		}
	}
	markAllPlanErrors := func(detail string) {
		detail = strings.TrimSpace(detail)
		if detail == "" {
			return
		}
		for id, status := range desiredStatus {
			if status.RuntimeStatus == "error" {
				continue
			}
			markPlanError(id, detail)
		}
	}

	for _, item := range reservations {
		if item.ManagedNetworkID <= 0 {
			continue
		}
		reservationsByNetwork[item.ManagedNetworkID] = append(reservationsByNetwork[item.ManagedNetworkID], item)
	}

	networks := append([]ManagedNetwork(nil), items...)
	sort.Slice(networks, func(i, j int) bool { return networks[i].ID < networks[j].ID })
	for _, item := range networks {
		item = normalizeManagedNetwork(item)
		if !item.Enabled {
			continue
		}
		if item.Bridge != "" {
			desiredInterfaces[item.Bridge] = InterfaceSpecForItem(item)
		}
		if !item.IPv4Enabled {
			continue
		}
		desiredStatus[item.ID] = RuntimeStatus{
			RuntimeStatus: "draining",
			RuntimeDetail: "waiting for dhcpv4 runtime apply",
		}
		plan, err := BuildIPv4Plan(item, reservationsByNetwork[item.ID])
		if err != nil {
			msg := fmt.Sprintf("managed network #%d (%s): %v", item.ID, item.Name, err)
			errs = append(errs, msg)
			desiredStatus[item.ID] = RuntimeStatus{
				RuntimeStatus: "error",
				RuntimeDetail: err.Error(),
			}
			continue
		}
		if existing, ok := plansByBridge[plan.Bridge]; ok {
			msg := fmt.Sprintf("managed network #%d (%s): bridge %s conflicts with managed network #%d (%s)", plan.ID, plan.Name, plan.Bridge, existing.ID, existing.Name)
			errs = append(errs, msg)
			desiredStatus[item.ID] = RuntimeStatus{
				RuntimeStatus: "error",
				RuntimeDetail: fmt.Sprintf("bridge %s conflicts with managed network #%d (%s)", plan.Bridge, existing.ID, existing.Name),
			}
			continue
		}
		plansByBridge[plan.Bridge] = plan
		desiredBridges[plan.ID] = plan.Bridge
		desiredInterfaces[plan.Bridge] = InterfaceSpecForItem(item)
		desiredAddresses[plan.Bridge] = plan.AddressSpec
		desiredDHCPv4[plan.Bridge] = plan.DHCPv4
		if plan.NeedsForwarding {
			desiredForwarding[plan.Bridge] = struct{}{}
			if uplink := strings.TrimSpace(plan.UplinkInterface); uplink != "" {
				desiredForwarding[uplink] = struct{}{}
			}
		}
	}

	for name, spec := range desiredInterfaces {
		if err := rt.ops.EnsureManagedNetworkInterface(spec); err != nil {
			errs = append(errs, fmt.Sprintf("ensure managed interface %s: %v", name, err))
			delete(desiredAddresses, name)
			delete(desiredDHCPv4, name)
			delete(desiredForwarding, name)
			markBridgeError(name, fmt.Sprintf("ensure managed interface %s: %v", name, err))
		}
	}

	if len(desiredForwarding) > 0 {
		if err := rt.ops.EnsureIPv4ForwardingEnabled(); err != nil {
			msg := fmt.Sprintf("enable ipv4 forwarding: %v", err)
			errs = append(errs, msg)
			markAllPlanErrors(msg)
		}
		for name := range desiredForwarding {
			if err := rt.ops.EnsureIPv4ForwardingEnabledOnInterface(name); err != nil {
				msg := fmt.Sprintf("enable ipv4 forwarding on %s: %v", name, err)
				errs = append(errs, msg)
				for _, plan := range plansByBridge {
					if plan.Bridge == name || strings.TrimSpace(plan.UplinkInterface) == name {
						markPlanError(plan.ID, msg)
					}
				}
			}
		}
	}

	for bridge, spec := range desiredAddresses {
		if err := rt.ops.EnsureManagedNetworkIPv4Address(spec); err != nil {
			errs = append(errs, fmt.Sprintf("configure ipv4 address on %s: %v", bridge, err))
			markBridgeError(bridge, fmt.Sprintf("configure ipv4 address on %s: %v", bridge, err))
		}
	}
	for bridge, config := range desiredDHCPv4 {
		if err := rt.ops.EnsureManagedNetworkDHCPv4(config); err != nil {
			errs = append(errs, fmt.Sprintf("serve dhcpv4 on %s: %v", bridge, err))
			markBridgeError(bridge, fmt.Sprintf("serve dhcpv4 on %s: %v", bridge, err))
		}
	}

	if states := rt.ops.SnapshotManagedNetworkDHCPv4States(); len(states) > 0 {
		for bridge, plan := range plansByBridge {
			if status, ok := desiredStatus[plan.ID]; ok && status.RuntimeStatus == "error" {
				continue
			}
			state, ok := states[bridge]
			if !ok {
				desiredStatus[plan.ID] = RuntimeStatus{
					RuntimeStatus: "draining",
					RuntimeDetail: "waiting for dhcpv4 listener",
				}
				continue
			}
			desiredStatus[plan.ID] = RuntimeStatus{
				RuntimeStatus:    state.Status,
				RuntimeDetail:    state.Detail,
				DHCPv4ReplyCount: state.ReplyCount,
			}
		}
	} else {
		for _, plan := range plansByBridge {
			if status, ok := desiredStatus[plan.ID]; ok && status.RuntimeStatus == "error" {
				continue
			}
			desiredStatus[plan.ID] = RuntimeStatus{
				RuntimeStatus: "draining",
				RuntimeDetail: "waiting for dhcpv4 listener",
			}
		}
	}

	for bridge, config := range rt.dhcpv4 {
		if _, ok := desiredDHCPv4[bridge]; ok {
			continue
		}
		if err := rt.ops.DeleteManagedNetworkDHCPv4(config.Bridge); err != nil {
			errs = append(errs, fmt.Sprintf("remove dhcpv4 on %s: %v", bridge, err))
		}
	}
	for bridge, spec := range rt.addresses {
		if _, ok := desiredAddresses[bridge]; ok {
			continue
		}
		if err := rt.ops.DeleteManagedNetworkIPv4Address(spec); err != nil {
			errs = append(errs, fmt.Sprintf("remove ipv4 address on %s: %v", bridge, err))
		}
	}

	rt.addresses = desiredAddresses
	rt.dhcpv4 = desiredDHCPv4
	rt.bridges = desiredBridges
	rt.status = desiredStatus
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func (rt *IPv4Runtime) SnapshotStatus() map[int64]RuntimeStatus {
	if rt == nil {
		return nil
	}

	rt.mu.Lock()
	if len(rt.status) == 0 {
		rt.mu.Unlock()
		return nil
	}
	out := make(map[int64]RuntimeStatus, len(rt.status))
	for id, status := range rt.status {
		out[id] = status
	}
	bridges := make(map[int64]string, len(rt.bridges))
	for id, bridge := range rt.bridges {
		bridges[id] = bridge
	}
	ops := rt.ops
	rt.mu.Unlock()

	if ops == nil || len(bridges) == 0 {
		return out
	}

	states := ops.SnapshotManagedNetworkDHCPv4States()
	for id, bridge := range bridges {
		status := out[id]
		if status.RuntimeStatus == "error" {
			continue
		}
		state, ok := states[bridge]
		if !ok {
			out[id] = RuntimeStatus{
				RuntimeStatus: "draining",
				RuntimeDetail: "waiting for dhcpv4 listener",
			}
			continue
		}
		out[id] = RuntimeStatus{
			RuntimeStatus:    state.Status,
			RuntimeDetail:    state.Detail,
			DHCPv4ReplyCount: state.ReplyCount,
		}
	}
	return out
}

func (rt *IPv4Runtime) Close() error {
	if rt == nil || rt.ops == nil {
		return nil
	}

	rt.mu.Lock()
	preserveAddresses := false
	if rt.preserveStateOnClose != nil {
		preserveAddresses = rt.preserveStateOnClose()
	}
	dhcpv4 := make([]DHCPv4Config, 0, len(rt.dhcpv4))
	for _, config := range rt.dhcpv4 {
		dhcpv4 = append(dhcpv4, config)
	}
	addresses := make(map[string]IPv4AddressSpec, len(rt.addresses))
	if !preserveAddresses {
		for bridge, spec := range rt.addresses {
			addresses[bridge] = spec
		}
	}
	rt.dhcpv4 = make(map[string]DHCPv4Config)
	rt.addresses = make(map[string]IPv4AddressSpec)
	rt.bridges = make(map[int64]string)
	rt.status = make(map[int64]RuntimeStatus)
	rt.mu.Unlock()

	errs := closeDHCPv4Configs(rt.ops, dhcpv4)
	if !preserveAddresses {
		for bridge, spec := range addresses {
			if err := rt.ops.DeleteManagedNetworkIPv4Address(spec); err != nil {
				errs = append(errs, fmt.Sprintf("remove ipv4 address on %s: %v", bridge, err))
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return errors.New(strings.Join(errs, "; "))
}

func buildManagedNetworkDHCPv4Reservations(items []ManagedNetworkReservation) []DHCPv4Reservation {
	if len(items) == 0 {
		return nil
	}
	out := make([]DHCPv4Reservation, 0, len(items))
	for _, item := range items {
		macAddress := strings.TrimSpace(item.MACAddress)
		ipv4Address := strings.TrimSpace(item.IPv4Address)
		if macAddress == "" || ipv4Address == "" {
			continue
		}
		out = append(out, DHCPv4Reservation{
			MACAddress:  macAddress,
			IPv4Address: ipv4Address,
			Remark:      strings.TrimSpace(item.Remark),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IPv4Address != out[j].IPv4Address {
			return strings.Compare(out[i].IPv4Address, out[j].IPv4Address) < 0
		}
		return strings.Compare(out[i].MACAddress, out[j].MACAddress) < 0
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeManagedNetworkIPv4DNSServers(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r', '\t', ' ':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		normalized, err := normalizeManagedNetworkIPv4Literal(field)
		if err != nil {
			return nil, fmt.Errorf("ipv4_dns_servers %v", err)
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func closeDHCPv4Configs(ops NetOps, configs []DHCPv4Config) []string {
	if ops == nil || len(configs) == 0 {
		return nil
	}

	errs := make(chan string, len(configs))
	var wg sync.WaitGroup
	for _, config := range configs {
		config := config
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ops.DeleteManagedNetworkDHCPv4(config.Bridge); err != nil {
				errs <- fmt.Sprintf("remove dhcpv4 on %s: %v", config.Bridge, err)
			}
		}()
	}
	wg.Wait()
	close(errs)

	out := make([]string, 0, len(errs))
	for errText := range errs {
		out = append(out, errText)
	}
	return out
}
