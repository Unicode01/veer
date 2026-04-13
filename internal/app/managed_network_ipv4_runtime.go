package app

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

type managedNetworkRuntime interface {
	Reconcile(items []ManagedNetwork, reservations []ManagedNetworkReservation) error
	SnapshotStatus() map[int64]managedNetworkRuntimeStatus
	Close() error
}

type managedNetworkRuntimeStatus struct {
	RuntimeStatus    string
	RuntimeDetail    string
	DHCPv4ReplyCount uint64
}

type managedNetworkIPv4AddressSpec struct {
	InterfaceName string
	CIDR          string
}

type managedNetworkDHCPv4Reservation struct {
	MACAddress  string
	IPv4Address string
	Remark      string
}

type managedNetworkDHCPv4Config struct {
	Bridge          string
	UplinkInterface string
	ServerCIDR      string
	ServerIP        string
	Gateway         string
	PoolStart       string
	PoolEnd         string
	DNSServers      []string
	Reservations    []managedNetworkDHCPv4Reservation
}

type managedNetworkInterfaceSpec struct {
	Name            string
	Mode            string
	BridgeMTU       int
	BridgeVLANAware bool
}

type managedNetworkNetOps interface {
	EnsureIPv4ForwardingEnabled() error
	EnsureIPv4ForwardingEnabledOnInterface(interfaceName string) error
	EnsureManagedNetworkInterface(spec managedNetworkInterfaceSpec) error
	EnsureManagedNetworkIPv4Address(spec managedNetworkIPv4AddressSpec) error
	DeleteManagedNetworkIPv4Address(spec managedNetworkIPv4AddressSpec) error
	EnsureManagedNetworkDHCPv4(config managedNetworkDHCPv4Config) error
	DeleteManagedNetworkDHCPv4(bridge string) error
	SnapshotManagedNetworkDHCPv4States() map[string]managedNetworkDHCPv4RuntimeState
}

func managedNetworkInterfaceSpecForItem(item ManagedNetwork) managedNetworkInterfaceSpec {
	item = normalizeManagedNetwork(item)
	return managedNetworkInterfaceSpec{
		Name:            item.Bridge,
		Mode:            item.BridgeMode,
		BridgeMTU:       item.BridgeMTU,
		BridgeVLANAware: item.BridgeVLANAware,
	}
}

type managedNetworkDHCPv4RuntimeState struct {
	Status     string
	Detail     string
	ReplyCount uint64
}

type managedNetworkIPv4Plan struct {
	ID              int64
	Name            string
	BridgeMode      string
	Bridge          string
	UplinkInterface string
	AddressSpec     managedNetworkIPv4AddressSpec
	DHCPv4          managedNetworkDHCPv4Config
	NeedsForwarding bool
}

type managedIPv4NetworkRuntime struct {
	mu        sync.Mutex
	ops       managedNetworkNetOps
	addresses map[string]managedNetworkIPv4AddressSpec
	dhcpv4    map[string]managedNetworkDHCPv4Config
	bridges   map[int64]string
	status    map[int64]managedNetworkRuntimeStatus
}

func newManagedIPv4NetworkRuntime(ops managedNetworkNetOps) managedNetworkRuntime {
	if ops == nil {
		return nil
	}
	return &managedIPv4NetworkRuntime{
		ops:       ops,
		addresses: make(map[string]managedNetworkIPv4AddressSpec),
		dhcpv4:    make(map[string]managedNetworkDHCPv4Config),
		bridges:   make(map[int64]string),
		status:    make(map[int64]managedNetworkRuntimeStatus),
	}
}

func buildManagedNetworkIPv4Plan(item ManagedNetwork, reservations []ManagedNetworkReservation) (managedNetworkIPv4Plan, error) {
	item = normalizeManagedNetwork(item)
	if !item.Enabled || !item.IPv4Enabled {
		return managedNetworkIPv4Plan{}, errors.New("ipv4 is disabled")
	}
	if item.Bridge == "" {
		return managedNetworkIPv4Plan{}, fmt.Errorf("bridge is required")
	}

	serverCIDR, serverIP, subnet, err := normalizeManagedNetworkIPv4CIDR(item.IPv4CIDR)
	if err != nil {
		return managedNetworkIPv4Plan{}, err
	}
	gateway, err := normalizeManagedNetworkIPv4Gateway(item.IPv4Gateway, serverIP)
	if err != nil {
		return managedNetworkIPv4Plan{}, err
	}
	poolStart, poolEnd, err := normalizeManagedNetworkIPv4Pool(item.IPv4PoolStart, item.IPv4PoolEnd, serverIP, subnet)
	if err != nil {
		return managedNetworkIPv4Plan{}, err
	}
	dnsServers, err := normalizeManagedNetworkIPv4DNSServers(item.IPv4DNSServers)
	if err != nil {
		return managedNetworkIPv4Plan{}, err
	}

	return managedNetworkIPv4Plan{
		ID:              item.ID,
		Name:            item.Name,
		BridgeMode:      item.BridgeMode,
		Bridge:          item.Bridge,
		UplinkInterface: item.UplinkInterface,
		AddressSpec: managedNetworkIPv4AddressSpec{
			InterfaceName: item.Bridge,
			CIDR:          serverCIDR,
		},
		DHCPv4: managedNetworkDHCPv4Config{
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

func buildManagedNetworkDHCPv4Reservations(items []ManagedNetworkReservation) []managedNetworkDHCPv4Reservation {
	if len(items) == 0 {
		return nil
	}
	out := make([]managedNetworkDHCPv4Reservation, 0, len(items))
	for _, item := range items {
		macAddress := strings.TrimSpace(item.MACAddress)
		ipv4Address := strings.TrimSpace(item.IPv4Address)
		if macAddress == "" || ipv4Address == "" {
			continue
		}
		out = append(out, managedNetworkDHCPv4Reservation{
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

func normalizeManagedNetworkIPv4CIDR(value string) (string, string, *net.IPNet, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", "", nil, fmt.Errorf("ipv4_cidr is required")
	}
	ip, prefix, err := net.ParseCIDR(text)
	if err != nil || ip == nil || prefix == nil {
		return "", "", nil, fmt.Errorf("ipv4_cidr must be a valid IPv4 CIDR")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", nil, fmt.Errorf("ipv4_cidr must be a valid IPv4 CIDR")
	}
	networkIP := prefix.IP.Mask(prefix.Mask).To4()
	if networkIP == nil {
		return "", "", nil, fmt.Errorf("ipv4_cidr must be a valid IPv4 CIDR")
	}
	ones, bits := prefix.Mask.Size()
	if ones < 0 || bits != 32 {
		return "", "", nil, fmt.Errorf("ipv4_cidr must be a valid IPv4 CIDR")
	}
	serverIP := canonicalIPLiteral(ip4)
	if isManagedNetworkIPv4ReservedHost(ip4, networkIP, prefix.Mask) {
		return "", "", nil, fmt.Errorf("ipv4_cidr must use a usable host address")
	}
	return (&net.IPNet{IP: ip4, Mask: prefix.Mask}).String(), serverIP, &net.IPNet{IP: networkIP, Mask: prefix.Mask}, nil
}

func normalizeManagedNetworkIPv4Gateway(value string, serverIP string) (string, error) {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return "", fmt.Errorf("gateway is unavailable")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return serverIP, nil
	}
	normalized, err := normalizeManagedNetworkIPv4Literal(value)
	if err != nil {
		return "", fmt.Errorf("ipv4_gateway %v", err)
	}
	if normalized != serverIP {
		return "", fmt.Errorf("ipv4_gateway must match the host address in ipv4_cidr")
	}
	return normalized, nil
}

func normalizeManagedNetworkIPv4Pool(startValue string, endValue string, serverIP string, subnet *net.IPNet) (string, string, error) {
	if subnet == nil {
		return "", "", fmt.Errorf("ipv4 pool requires a valid subnet")
	}
	defaultStart, defaultEnd, err := deriveManagedNetworkIPv4Pool(serverIP, subnet)
	if err != nil {
		return "", "", err
	}
	start := strings.TrimSpace(startValue)
	end := strings.TrimSpace(endValue)
	if start == "" {
		start = defaultStart
	}
	if end == "" {
		end = defaultEnd
	}

	startIP, err := normalizeManagedNetworkIPv4Literal(start)
	if err != nil {
		return "", "", fmt.Errorf("ipv4_pool_start %v", err)
	}
	endIP, err := normalizeManagedNetworkIPv4Literal(end)
	if err != nil {
		return "", "", fmt.Errorf("ipv4_pool_end %v", err)
	}
	if !subnet.Contains(parseIPLiteral(startIP)) || !subnet.Contains(parseIPLiteral(endIP)) {
		return "", "", fmt.Errorf("ipv4_pool_start and ipv4_pool_end must stay inside ipv4_cidr")
	}
	if compareManagedNetworkIPv4(startIP, endIP) > 0 {
		return "", "", fmt.Errorf("ipv4_pool_start must be less than or equal to ipv4_pool_end")
	}
	if startIP == serverIP || endIP == serverIP || ipRangeContainsManagedNetworkIPv4(startIP, endIP, serverIP) {
		return "", "", fmt.Errorf("ipv4 pool must not include the gateway address")
	}
	if isManagedNetworkIPv4ReservedHost(parseIPLiteral(startIP).To4(), subnet.IP.To4(), subnet.Mask) || isManagedNetworkIPv4ReservedHost(parseIPLiteral(endIP).To4(), subnet.IP.To4(), subnet.Mask) {
		return "", "", fmt.Errorf("ipv4 pool must use usable host addresses")
	}
	return startIP, endIP, nil
}

func deriveManagedNetworkIPv4Pool(serverIP string, subnet *net.IPNet) (string, string, error) {
	start, end, ok := managedNetworkIPv4HostRange(subnet)
	if !ok {
		return "", "", fmt.Errorf("ipv4_cidr does not leave room for a dhcp pool")
	}
	server := managedNetworkIPv4ToUint32(parseIPLiteral(serverIP))
	if start == server {
		start++
	}
	if end == server {
		end--
	}
	if server > start && server < end {
		start = server + 1
	}
	if start > end {
		return "", "", fmt.Errorf("ipv4_cidr does not leave room for a dhcp pool")
	}
	return uint32ToIPv4(start).String(), uint32ToIPv4(end).String(), nil
}

func managedNetworkIPv4HostRange(subnet *net.IPNet) (uint32, uint32, bool) {
	if subnet == nil || subnet.IP == nil {
		return 0, 0, false
	}
	ones, bits := subnet.Mask.Size()
	if ones < 0 || bits != 32 || ones >= 31 {
		return 0, 0, false
	}
	network := managedNetworkIPv4ToUint32(subnet.IP)
	mask := managedNetworkIPv4ToUint32(net.IP(subnet.Mask))
	broadcast := network | ^mask
	start := network + 1
	end := broadcast - 1
	return start, end, start <= end
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

func normalizeManagedNetworkIPv4Literal(value string) (string, error) {
	ip := parseIPLiteral(value)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("must be a valid IPv4 address")
	}
	ip4 := ip.To4()
	if ip4 == nil || ip4.IsUnspecified() {
		return "", fmt.Errorf("must be a specific IPv4 address")
	}
	return ip4.String(), nil
}

func isManagedNetworkIPv4ReservedHost(ip net.IP, network net.IP, mask net.IPMask) bool {
	ip4 := ip.To4()
	network4 := network.To4()
	mask4 := net.IP(mask).To4()
	if ip4 == nil || network4 == nil || mask4 == nil {
		return true
	}
	ones, bits := mask.Size()
	if ones < 0 || bits != 32 {
		return true
	}
	networkValue := managedNetworkIPv4ToUint32(network4)
	ipValue := managedNetworkIPv4ToUint32(ip4)
	if ipValue == networkValue {
		return true
	}
	if ones <= 30 {
		broadcast := networkValue | ^managedNetworkIPv4ToUint32(mask4)
		if ipValue == broadcast {
			return true
		}
	}
	return false
}

func compareManagedNetworkIPv4(a string, b string) int {
	aValue := managedNetworkIPv4LiteralToUint32(a)
	bValue := managedNetworkIPv4LiteralToUint32(b)
	switch {
	case aValue < bValue:
		return -1
	case aValue > bValue:
		return 1
	default:
		return 0
	}
}

func ipRangeContainsManagedNetworkIPv4(start string, end string, value string) bool {
	startValue := managedNetworkIPv4LiteralToUint32(start)
	endValue := managedNetworkIPv4LiteralToUint32(end)
	current := managedNetworkIPv4LiteralToUint32(value)
	return current >= startValue && current <= endValue
}

func managedNetworkIPv4LiteralToUint32(text string) uint32 {
	return managedNetworkIPv4ToUint32(parseIPLiteral(text))
}

func managedNetworkIPv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func uint32ToIPv4(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func (rt *managedIPv4NetworkRuntime) Reconcile(items []ManagedNetwork, reservations []ManagedNetworkReservation) error {
	if rt == nil || rt.ops == nil {
		return nil
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	desiredAddresses := make(map[string]managedNetworkIPv4AddressSpec)
	desiredDHCPv4 := make(map[string]managedNetworkDHCPv4Config)
	desiredBridges := make(map[int64]string)
	desiredForwarding := make(map[string]struct{})
	desiredInterfaces := make(map[string]managedNetworkInterfaceSpec)
	plansByBridge := make(map[string]managedNetworkIPv4Plan)
	reservationsByNetwork := make(map[int64][]ManagedNetworkReservation)
	desiredStatus := make(map[int64]managedNetworkRuntimeStatus)
	errs := make([]string, 0)
	markBridgeError := func(bridge string, detail string) {
		plan, ok := plansByBridge[bridge]
		if !ok {
			return
		}
		desiredStatus[plan.ID] = managedNetworkRuntimeStatus{
			RuntimeStatus: "error",
			RuntimeDetail: strings.TrimSpace(detail),
		}
	}
	markPlanError := func(id int64, detail string) {
		if id <= 0 {
			return
		}
		desiredStatus[id] = managedNetworkRuntimeStatus{
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
			desiredInterfaces[item.Bridge] = managedNetworkInterfaceSpecForItem(item)
		}
		if !item.IPv4Enabled {
			continue
		}
		desiredStatus[item.ID] = managedNetworkRuntimeStatus{
			RuntimeStatus: "draining",
			RuntimeDetail: "waiting for dhcpv4 runtime apply",
		}
		plan, err := buildManagedNetworkIPv4Plan(item, reservationsByNetwork[item.ID])
		if err != nil {
			msg := fmt.Sprintf("managed network #%d (%s): %v", item.ID, item.Name, err)
			errs = append(errs, msg)
			desiredStatus[item.ID] = managedNetworkRuntimeStatus{
				RuntimeStatus: "error",
				RuntimeDetail: err.Error(),
			}
			continue
		}
		if existing, ok := plansByBridge[plan.Bridge]; ok {
			msg := fmt.Sprintf("managed network #%d (%s): bridge %s conflicts with managed network #%d (%s)", plan.ID, plan.Name, plan.Bridge, existing.ID, existing.Name)
			errs = append(errs, msg)
			desiredStatus[item.ID] = managedNetworkRuntimeStatus{
				RuntimeStatus: "error",
				RuntimeDetail: fmt.Sprintf("bridge %s conflicts with managed network #%d (%s)", plan.Bridge, existing.ID, existing.Name),
			}
			continue
		}
		plansByBridge[plan.Bridge] = plan
		desiredBridges[plan.ID] = plan.Bridge
		desiredInterfaces[plan.Bridge] = managedNetworkInterfaceSpecForItem(item)
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
				desiredStatus[plan.ID] = managedNetworkRuntimeStatus{
					RuntimeStatus: "draining",
					RuntimeDetail: "waiting for dhcpv4 listener",
				}
				continue
			}
			desiredStatus[plan.ID] = managedNetworkRuntimeStatus{
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
			desiredStatus[plan.ID] = managedNetworkRuntimeStatus{
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

func (rt *managedIPv4NetworkRuntime) SnapshotStatus() map[int64]managedNetworkRuntimeStatus {
	if rt == nil {
		return nil
	}

	rt.mu.Lock()
	if len(rt.status) == 0 {
		rt.mu.Unlock()
		return nil
	}
	out := make(map[int64]managedNetworkRuntimeStatus, len(rt.status))
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
			out[id] = managedNetworkRuntimeStatus{
				RuntimeStatus: "draining",
				RuntimeDetail: "waiting for dhcpv4 listener",
			}
			continue
		}
		out[id] = managedNetworkRuntimeStatus{
			RuntimeStatus:    state.Status,
			RuntimeDetail:    state.Detail,
			DHCPv4ReplyCount: state.ReplyCount,
		}
	}
	return out
}

func (rt *managedIPv4NetworkRuntime) Close() error {
	if rt == nil || rt.ops == nil {
		return nil
	}

	rt.mu.Lock()
	preserveAddresses := managedNetworkPreserveStateOnClose()
	dhcpv4 := make([]managedNetworkDHCPv4Config, 0, len(rt.dhcpv4))
	for _, config := range rt.dhcpv4 {
		dhcpv4 = append(dhcpv4, config)
	}
	addresses := make(map[string]managedNetworkIPv4AddressSpec, len(rt.addresses))
	if !preserveAddresses {
		for bridge, spec := range rt.addresses {
			addresses[bridge] = spec
		}
	}
	rt.dhcpv4 = make(map[string]managedNetworkDHCPv4Config)
	rt.addresses = make(map[string]managedNetworkIPv4AddressSpec)
	rt.bridges = make(map[int64]string)
	rt.status = make(map[int64]managedNetworkRuntimeStatus)
	rt.mu.Unlock()

	errs := managedNetworkCloseDHCPv4Configs(rt.ops, dhcpv4)
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

func managedNetworkCloseDHCPv4Configs(ops managedNetworkNetOps, configs []managedNetworkDHCPv4Config) []string {
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
