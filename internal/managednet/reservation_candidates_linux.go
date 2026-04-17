//go:build linux

package managednet

import (
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func DiscoverReservationCandidates(networks []ManagedNetwork, reservations []ManagedNetworkReservation, opts CandidateDiscoveryOptions) ([]ReservationCandidate, error) {
	if opts.LoadInterfaceInfos == nil {
		return []ReservationCandidate{}, nil
	}
	infos, err := opts.LoadInterfaceInfos()
	if err != nil {
		return nil, err
	}
	discovered, err := DiscoverReservationFDBMACs(networks, infos)
	if err != nil {
		return nil, err
	}
	observedIPv4s, err := DiscoverReservationObservedIPv4s(discovered, networks)
	if err != nil {
		return nil, err
	}
	discovered = AttachDiscoveredMACObservedIPv4s(discovered, observedIPv4s)
	if nics, err := LoadPVEGuestNICs(opts.RepairOptions); err == nil && len(nics) > 0 {
		discovered = EnrichDiscoveredMACsWithPVEGuestNICs(discovered, nics)
	}
	return BuildReservationCandidatesWithInfos(networks, reservations, discovered, infos), nil
}

type observedIPv4Candidate struct {
	IP      string
	Quality int
	Order   int
}

func DiscoverReservationFDBMACs(networks []ManagedNetwork, infos []InterfaceInfo) ([]DiscoveredMAC, error) {
	if len(networks) == 0 || len(infos) == 0 {
		return []DiscoveredMAC{}, nil
	}

	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	linkByIndex := make(map[int]netlink.Link, len(links))
	linkByName := make(map[string]netlink.Link, len(links))
	hostMACs := make(map[string]struct{}, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil || strings.TrimSpace(link.Attrs().Name) == "" {
			continue
		}
		linkByIndex[link.Attrs().Index] = link
		linkByName[strings.TrimSpace(link.Attrs().Name)] = link
		if mac := NormalizeReservationCandidateMAC(link.Attrs().HardwareAddr); mac != "" {
			hostMACs[mac] = struct{}{}
		}
	}

	networkByBridgeIndex := make(map[int][]ManagedNetwork)
	childAllowed := make(map[int64]map[string]struct{})
	for _, network := range networks {
		network = normalizeManagedNetwork(network)
		if !network.Enabled || !network.IPv4Enabled || strings.TrimSpace(network.Bridge) == "" {
			continue
		}
		bridge := linkByName[network.Bridge]
		if bridge == nil || bridge.Attrs() == nil || bridge.Attrs().Index <= 0 {
			continue
		}
		networkByBridgeIndex[bridge.Attrs().Index] = append(networkByBridgeIndex[bridge.Attrs().Index], network)
		children := collectManagedNetworkChildInterfaces(network.Bridge, network.UplinkInterface, infos)
		if len(children) == 0 {
			continue
		}
		current := make(map[string]struct{}, len(children))
		for _, child := range children {
			name := strings.TrimSpace(child.Name)
			if name == "" {
				continue
			}
			current[name] = struct{}{}
		}
		childAllowed[network.ID] = current
	}

	entries, err := netlink.NeighListExecute(netlink.Ndmsg{Family: unix.AF_BRIDGE})
	if err != nil {
		return nil, err
	}

	out := make([]DiscoveredMAC, 0, len(entries))
	for _, entry := range entries {
		if entry.Flags&netlink.NTF_SELF != 0 {
			continue
		}
		if !isValidReservationCandidateMAC(entry.HardwareAddr) {
			continue
		}
		macText := NormalizeReservationCandidateMAC(entry.HardwareAddr)
		if macText == "" {
			continue
		}
		if _, ok := hostMACs[macText]; ok {
			continue
		}
		link := linkByIndex[entry.LinkIndex]
		if link == nil || link.Attrs() == nil {
			continue
		}
		childName := strings.TrimSpace(link.Attrs().Name)
		if childName == "" {
			continue
		}
		bridgeIndex := entry.MasterIndex
		if bridgeIndex <= 0 {
			bridgeIndex = link.Attrs().MasterIndex
		}
		if bridgeIndex <= 0 {
			continue
		}
		networksForBridge := networkByBridgeIndex[bridgeIndex]
		if len(networksForBridge) == 0 {
			continue
		}
		for _, network := range networksForBridge {
			if _, ok := childAllowed[network.ID][childName]; !ok {
				continue
			}
			out = append(out, DiscoveredMAC{
				ManagedNetworkID: network.ID,
				ChildInterface:   childName,
				MACAddress:       macText,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ManagedNetworkID != out[j].ManagedNetworkID {
			return out[i].ManagedNetworkID < out[j].ManagedNetworkID
		}
		if out[i].ChildInterface != out[j].ChildInterface {
			return strings.Compare(out[i].ChildInterface, out[j].ChildInterface) < 0
		}
		return strings.Compare(out[i].MACAddress, out[j].MACAddress) < 0
	})
	return out, nil
}

func DiscoverReservationObservedIPv4s(discovered []DiscoveredMAC, networks []ManagedNetwork) (map[string][]string, error) {
	if len(discovered) == 0 || len(networks) == 0 {
		return nil, nil
	}

	interestedMACsByNetwork := make(map[int64]map[string]struct{})
	for _, item := range discovered {
		if item.ManagedNetworkID <= 0 {
			continue
		}
		macAddress, err := normalizeManagedNetworkReservationMACAddress(item.MACAddress)
		if err != nil {
			continue
		}
		current := interestedMACsByNetwork[item.ManagedNetworkID]
		if current == nil {
			current = make(map[string]struct{})
			interestedMACsByNetwork[item.ManagedNetworkID] = current
		}
		current[macAddress] = struct{}{}
	}
	if len(interestedMACsByNetwork) == 0 {
		return nil, nil
	}

	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	linkByName := make(map[string]netlink.Link, len(links))
	hostMACs := make(map[string]struct{}, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil || strings.TrimSpace(link.Attrs().Name) == "" {
			continue
		}
		linkByName[strings.TrimSpace(link.Attrs().Name)] = link
		if mac := NormalizeReservationCandidateMAC(link.Attrs().HardwareAddr); mac != "" {
			hostMACs[mac] = struct{}{}
		}
	}

	out := make(map[string][]string)
	for _, network := range networks {
		network = normalizeManagedNetwork(network)
		interestedMACs := interestedMACsByNetwork[network.ID]
		if len(interestedMACs) == 0 || !network.Enabled || !network.IPv4Enabled || strings.TrimSpace(network.Bridge) == "" {
			continue
		}
		bridge := linkByName[network.Bridge]
		if bridge == nil || bridge.Attrs() == nil || bridge.Attrs().Index <= 0 {
			continue
		}

		memberIndexes, err := listBridgeMemberIndexes(bridge.Attrs().Index)
		if err != nil {
			return nil, err
		}
		neighbors, err := listBridgeIPv4Neighbors(bridge.Attrs().Index)
		if err != nil {
			return nil, err
		}
		for macAddress, ips := range CollectObservedIPv4sForNetwork(network, bridge.Attrs().Index, memberIndexes, hostMACs, interestedMACs, neighbors) {
			if len(ips) == 0 {
				continue
			}
			out[discoveredMACLookupKey(network.ID, macAddress)] = ips
		}
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func CollectObservedIPv4sForNetwork(network ManagedNetwork, bridgeIndex int, memberIndexes map[int]struct{}, hostMACs map[string]struct{}, interestedMACs map[string]struct{}, neighbors []netlink.Neigh) map[string][]string {
	if bridgeIndex <= 0 || len(interestedMACs) == 0 || len(neighbors) == 0 {
		return nil
	}
	_, gateway, subnet, err := normalizeManagedNetworkIPv4CIDR(network.IPv4CIDR)
	if err != nil || subnet == nil {
		return nil
	}

	candidatesByMAC := make(map[string]map[string]observedIPv4Candidate)
	nextOrder := 0
	for _, neighbor := range neighbors {
		if !reservationNeighborBelongsToBridge(neighbor, bridgeIndex, memberIndexes) {
			continue
		}
		if !reservationNeighborStateUsable(neighbor.State) {
			continue
		}
		macAddress := NormalizeReservationCandidateMAC(neighbor.HardwareAddr)
		if macAddress == "" {
			continue
		}
		if _, ok := interestedMACs[macAddress]; !ok {
			continue
		}
		if _, ok := hostMACs[macAddress]; ok {
			continue
		}

		ip := neighbor.IP.To4()
		if !isVisibleInterfaceIP(ip) || !subnet.Contains(ip) {
			continue
		}
		ipText := canonicalIPLiteral(ip)
		if ipText == gateway || isManagedNetworkIPv4ReservedHost(ip, subnet.IP.To4(), subnet.Mask) {
			continue
		}

		byIP := candidatesByMAC[macAddress]
		if byIP == nil {
			byIP = make(map[string]observedIPv4Candidate)
			candidatesByMAC[macAddress] = byIP
		}
		quality := reservationNeighborStateQuality(neighbor.State)
		if existing, ok := byIP[ipText]; ok {
			if quality > existing.Quality {
				existing.Quality = quality
				byIP[ipText] = existing
			}
			continue
		}
		byIP[ipText] = observedIPv4Candidate{
			IP:      ipText,
			Quality: quality,
			Order:   nextOrder,
		}
		nextOrder++
	}

	if len(candidatesByMAC) == 0 {
		return nil
	}
	out := make(map[string][]string, len(candidatesByMAC))
	for macAddress, byIP := range candidatesByMAC {
		items := make([]observedIPv4Candidate, 0, len(byIP))
		for _, item := range byIP {
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Quality != items[j].Quality {
				return items[i].Quality > items[j].Quality
			}
			if items[i].Order != items[j].Order {
				return items[i].Order < items[j].Order
			}
			return compareManagedNetworkIPv4(items[i].IP, items[j].IP) < 0
		})
		ips := make([]string, 0, len(items))
		for _, item := range items {
			ips = append(ips, item.IP)
		}
		out[macAddress] = ips
	}
	return out
}

func listBridgeIPv4Neighbors(bridgeIndex int) ([]netlink.Neigh, error) {
	neighbors, err := netlink.NeighList(bridgeIndex, unix.AF_INET)
	if err != nil {
		return nil, err
	}
	out := append([]netlink.Neigh(nil), neighbors...)
	if bridgeIndex > 0 {
		if extra, err := netlink.NeighList(0, unix.AF_INET); err == nil {
			out = append(out, extra...)
		}
	}
	return out, nil
}

func reservationNeighborBelongsToBridge(neighbor netlink.Neigh, bridgeIndex int, memberIndexes map[int]struct{}) bool {
	if bridgeIndex <= 0 {
		return false
	}
	if neighbor.LinkIndex == bridgeIndex || neighbor.MasterIndex == bridgeIndex {
		return true
	}
	if neighbor.LinkIndex <= 0 {
		return false
	}
	_, ok := memberIndexes[neighbor.LinkIndex]
	return ok
}

func reservationNeighborStateUsable(state int) bool {
	if state == 0 {
		return true
	}
	if state&unix.NUD_INCOMPLETE != 0 {
		return false
	}
	if state&unix.NUD_FAILED != 0 {
		return false
	}
	return true
}

func reservationNeighborStateQuality(state int) int {
	switch {
	case state&unix.NUD_PERMANENT != 0:
		return 60
	case state&unix.NUD_REACHABLE != 0:
		return 50
	case state&unix.NUD_PROBE != 0:
		return 40
	case state&unix.NUD_DELAY != 0:
		return 30
	case state&unix.NUD_STALE != 0:
		return 20
	case state&unix.NUD_NOARP != 0:
		return 10
	default:
		return 5
	}
}

func listBridgeMemberIndexes(bridgeIndex int) (map[int]struct{}, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	indexes := make(map[int]struct{})
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		if link.Attrs().MasterIndex != bridgeIndex {
			continue
		}
		indexes[link.Attrs().Index] = struct{}{}
	}
	if len(indexes) == 0 {
		return nil, nil
	}
	return indexes, nil
}
