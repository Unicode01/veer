package managednet

import (
	"fmt"
	"net"
	"strings"
)

type reservationIPv4Plan struct {
	PoolStart string
	PoolEnd   string
	ServerIP  string
	Subnet    *net.IPNet
}

func buildReservationIPv4Plan(network ManagedNetwork) (reservationIPv4Plan, error) {
	_, serverIP, subnet, err := normalizeManagedNetworkIPv4CIDR(network.IPv4CIDR)
	if err != nil {
		return reservationIPv4Plan{}, err
	}
	if _, err := normalizeManagedNetworkIPv4Gateway(network.IPv4Gateway, serverIP); err != nil {
		return reservationIPv4Plan{}, err
	}
	poolStart, poolEnd, err := normalizeManagedNetworkIPv4Pool(network.IPv4PoolStart, network.IPv4PoolEnd, serverIP, subnet)
	if err != nil {
		return reservationIPv4Plan{}, err
	}
	return reservationIPv4Plan{
		PoolStart: poolStart,
		PoolEnd:   poolEnd,
		ServerIP:  serverIP,
		Subnet:    subnet,
	}, nil
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
	if isManagedNetworkIPv4ReservedHost(parseIPLiteral(startIP).To4(), subnet.IP.To4(), subnet.Mask) ||
		isManagedNetworkIPv4ReservedHost(parseIPLiteral(endIP).To4(), subnet.IP.To4(), subnet.Mask) {
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
