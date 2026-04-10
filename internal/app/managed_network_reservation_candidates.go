package app

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	managedNetworkReservationCandidateStatusAvailable   = "available"
	managedNetworkReservationCandidateStatusReserved    = "reserved"
	managedNetworkReservationCandidateStatusUnavailable = "unavailable"
	managedNetworkReservationCandidateIPv4ChoicesLimit  = 5
)

type managedNetworkDiscoveredMAC struct {
	ManagedNetworkID int64
	ChildInterface   string
	MACAddress       string
	ObservedIPv4s    []string
	PVEVMID          string
	PVEGuestName     string
	PVEGuestNIC      string
}

var loadManagedNetworkReservationCandidatesForTests func([]ManagedNetwork, []ManagedNetworkReservation) ([]ManagedNetworkReservationCandidate, error)

func loadManagedNetworkReservationCandidates(db sqlRuleStore) ([]ManagedNetworkReservationCandidate, error) {
	networks, err := dbGetEnabledManagedNetworks(db)
	if err != nil {
		return nil, err
	}
	if len(networks) == 0 {
		return []ManagedNetworkReservationCandidate{}, nil
	}

	networkIDs := make([]int64, 0, len(networks))
	for _, network := range networks {
		networkIDs = append(networkIDs, network.ID)
	}
	reservations, err := dbGetManagedNetworkReservationsByManagedNetworkIDs(db, networkIDs)
	if err != nil {
		return nil, err
	}
	load := discoverManagedNetworkReservationCandidates
	if loadManagedNetworkReservationCandidatesForTests != nil {
		load = loadManagedNetworkReservationCandidatesForTests
	}
	items, err := load(networks, reservations)
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ManagedNetworkID != items[j].ManagedNetworkID {
			return items[i].ManagedNetworkID < items[j].ManagedNetworkID
		}
		if items[i].ChildInterface != items[j].ChildInterface {
			return strings.Compare(items[i].ChildInterface, items[j].ChildInterface) < 0
		}
		return strings.Compare(items[i].MACAddress, items[j].MACAddress) < 0
	})
	if items == nil {
		return []ManagedNetworkReservationCandidate{}, nil
	}
	return items, nil
}

func buildManagedNetworkReservationCandidates(networks []ManagedNetwork, reservations []ManagedNetworkReservation, discovered []managedNetworkDiscoveredMAC) []ManagedNetworkReservationCandidate {
	return buildManagedNetworkReservationCandidatesWithInfos(networks, reservations, discovered, nil)
}

func buildManagedNetworkReservationCandidatesWithInfos(networks []ManagedNetwork, reservations []ManagedNetworkReservation, discovered []managedNetworkDiscoveredMAC, infos []InterfaceInfo) []ManagedNetworkReservationCandidate {
	if len(discovered) == 0 || len(networks) == 0 {
		return []ManagedNetworkReservationCandidate{}
	}

	networkByID := make(map[int64]ManagedNetwork, len(networks))
	for _, network := range networks {
		network = normalizeManagedNetwork(network)
		networkByID[network.ID] = network
	}

	discovered = dedupeManagedNetworkDiscoveredMACs(discovered)
	candidatesByNetwork := make(map[int64][]managedNetworkDiscoveredMAC)
	for _, item := range discovered {
		network, ok := networkByID[item.ManagedNetworkID]
		if !ok || !network.Enabled || !network.IPv4Enabled {
			continue
		}
		candidatesByNetwork[item.ManagedNetworkID] = append(candidatesByNetwork[item.ManagedNetworkID], item)
	}
	if len(candidatesByNetwork) == 0 {
		return []ManagedNetworkReservationCandidate{}
	}

	reservationsByNetwork := make(map[int64][]ManagedNetworkReservation)
	reservationsByNetworkMAC := make(map[int64]map[string]ManagedNetworkReservation)
	for _, item := range reservations {
		if item.ManagedNetworkID <= 0 {
			continue
		}
		item = normalizeManagedNetworkReservation(item)
		reservationsByNetwork[item.ManagedNetworkID] = append(reservationsByNetwork[item.ManagedNetworkID], item)
		current := reservationsByNetworkMAC[item.ManagedNetworkID]
		if current == nil {
			current = make(map[string]ManagedNetworkReservation)
			reservationsByNetworkMAC[item.ManagedNetworkID] = current
		}
		current[strings.ToLower(strings.TrimSpace(item.MACAddress))] = item
	}

	networkIDs := make([]int64, 0, len(candidatesByNetwork))
	for id := range candidatesByNetwork {
		networkIDs = append(networkIDs, id)
	}
	sort.Slice(networkIDs, func(i, j int) bool { return networkIDs[i] < networkIDs[j] })
	infoByName := make(map[string]InterfaceInfo, len(infos))
	for _, info := range infos {
		name := strings.TrimSpace(info.Name)
		if name == "" {
			continue
		}
		infoByName[name] = info
	}

	out := make([]ManagedNetworkReservationCandidate, 0, len(discovered))
	for _, networkID := range networkIDs {
		network := networkByID[networkID]
		discoveredItems := candidatesByNetwork[networkID]
		sort.Slice(discoveredItems, func(i, j int) bool {
			if discoveredItems[i].ChildInterface != discoveredItems[j].ChildInterface {
				return strings.Compare(discoveredItems[i].ChildInterface, discoveredItems[j].ChildInterface) < 0
			}
			return strings.Compare(discoveredItems[i].MACAddress, discoveredItems[j].MACAddress) < 0
		})

		suggest := newManagedNetworkReservationIPv4Suggester(network, reservationsByNetwork[networkID])
		for _, item := range discoveredItems {
			candidate := ManagedNetworkReservationCandidate{
				ManagedNetworkID:     network.ID,
				ManagedNetworkName:   network.Name,
				ManagedNetworkBridge: network.Bridge,
				ChildInterface:       item.ChildInterface,
				MACAddress:           strings.ToLower(strings.TrimSpace(item.MACAddress)),
				PVEVMID:              strings.TrimSpace(item.PVEVMID),
				PVEGuestName:         strings.TrimSpace(item.PVEGuestName),
				PVEGuestNIC:          strings.TrimSpace(item.PVEGuestNIC),
				SuggestedRemark:      buildManagedNetworkReservationCandidateRemark(item),
			}

			if existing, ok := reservationsByNetworkMAC[networkID][candidate.MACAddress]; ok {
				candidate.Status = managedNetworkReservationCandidateStatusReserved
				candidate.StatusMessage = "already reserved"
				candidate.ExistingReservationID = existing.ID
				candidate.ExistingReservationIPv4 = existing.IPv4Address
				candidate.ExistingReservationRemark = existing.Remark
				candidate.SuggestedIPv4 = existing.IPv4Address
				candidate.IPv4Candidates = []string{existing.IPv4Address}
				out = append(out, candidate)
				continue
			}

			preferredIPv4 := suggestManagedNetworkReservationCandidateIPv4(network, item.ObservedIPv4s, infoByName[item.ChildInterface])
			suggested, reason := suggest.NextPreferred(preferredIPv4)
			candidate.SuggestedIPv4 = suggested
			if suggested != "" {
				candidate.Status = managedNetworkReservationCandidateStatusAvailable
				candidate.IPv4Candidates = buildManagedNetworkReservationCandidateIPv4Choices(
					network,
					reservationsByNetwork[networkID],
					item.ObservedIPv4s,
					infoByName[item.ChildInterface],
					suggested,
					managedNetworkReservationCandidateIPv4ChoicesLimit,
				)
			} else {
				candidate.Status = managedNetworkReservationCandidateStatusUnavailable
				candidate.StatusMessage = reason
			}
			out = append(out, candidate)
		}
	}

	if len(out) == 0 {
		return []ManagedNetworkReservationCandidate{}
	}
	return out
}

func suggestManagedNetworkReservationCandidateIPv4(network ManagedNetwork, observedIPv4s []string, info InterfaceInfo) string {
	candidates := managedNetworkReservationPreferredIPv4s(network, observedIPv4s, info)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func managedNetworkReservationPreferredIPv4s(network ManagedNetwork, observedIPv4s []string, info InterfaceInfo) []string {
	_, gateway, subnet, err := normalizeManagedNetworkIPv4CIDR(network.IPv4CIDR)
	if err != nil || subnet == nil {
		return nil
	}
	out := make([]string, 0, len(observedIPv4s)+len(info.Addrs))
	seen := make(map[string]struct{}, len(observedIPv4s)+len(info.Addrs))
	appendCandidate := func(raw string) {
		candidate, err := normalizeManagedNetworkIPv4Literal(raw)
		if err != nil {
			return
		}
		ip := parseIPLiteral(candidate).To4()
		if ip == nil || !subnet.Contains(ip) {
			return
		}
		if candidate == gateway {
			return
		}
		if isManagedNetworkIPv4ReservedHost(ip, subnet.IP.To4(), subnet.Mask) {
			return
		}
		if _, ok := seen[candidate]; ok {
			return
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	for _, raw := range observedIPv4s {
		appendCandidate(raw)
	}
	if strings.TrimSpace(info.Name) != "" {
		for _, raw := range info.Addrs {
			appendCandidate(raw)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildManagedNetworkReservationCandidateIPv4Choices(network ManagedNetwork, reservations []ManagedNetworkReservation, observedIPv4s []string, info InterfaceInfo, suggested string, limit int) []string {
	if limit <= 0 {
		limit = 1
	}

	suggest := newManagedNetworkReservationIPv4Suggester(network, reservations)
	out := make([]string, 0, limit)
	appendChoice := func(value string) {
		if len(out) >= limit {
			return
		}
		current, ok := suggest.reservePreferred(value)
		if !ok {
			return
		}
		for _, existing := range out {
			if existing == current {
				return
			}
		}
		out = append(out, current)
	}

	appendChoice(suggested)
	for _, candidate := range managedNetworkReservationPreferredIPv4s(network, observedIPv4s, info) {
		appendChoice(candidate)
	}

	for len(out) < limit {
		current, _ := suggest.Next()
		if current == "" {
			break
		}
		duplicate := false
		for _, existing := range out {
			if existing == current {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		out = append(out, current)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupeManagedNetworkDiscoveredMACs(items []managedNetworkDiscoveredMAC) []managedNetworkDiscoveredMAC {
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ManagedNetworkID != items[j].ManagedNetworkID {
			return items[i].ManagedNetworkID < items[j].ManagedNetworkID
		}
		if items[i].ChildInterface != items[j].ChildInterface {
			return strings.Compare(items[i].ChildInterface, items[j].ChildInterface) < 0
		}
		return strings.Compare(items[i].MACAddress, items[j].MACAddress) < 0
	})
	out := make([]managedNetworkDiscoveredMAC, 0, len(items))
	seen := make(map[string]int, len(items))
	for _, item := range items {
		item.ChildInterface = strings.TrimSpace(item.ChildInterface)
		item.MACAddress = strings.ToLower(strings.TrimSpace(item.MACAddress))
		item.ObservedIPv4s = normalizeManagedNetworkDiscoveredMACIPv4s(item.ObservedIPv4s)
		item.PVEVMID = strings.TrimSpace(item.PVEVMID)
		item.PVEGuestName = strings.TrimSpace(item.PVEGuestName)
		item.PVEGuestNIC = strings.TrimSpace(item.PVEGuestNIC)
		if item.ManagedNetworkID <= 0 || item.ChildInterface == "" || item.MACAddress == "" {
			continue
		}
		key := managedNetworkDiscoveredMACLookupKey(item.ManagedNetworkID, item.MACAddress)
		if index, ok := seen[key]; ok {
			mergedObservedIPv4s := mergeManagedNetworkDiscoveredMACIPv4s(out[index].ObservedIPv4s, item.ObservedIPv4s)
			if managedNetworkDiscoveredMACQuality(item) > managedNetworkDiscoveredMACQuality(out[index]) {
				item.ObservedIPv4s = mergedObservedIPv4s
				out[index] = item
			} else {
				out[index].ObservedIPv4s = mergedObservedIPv4s
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func managedNetworkDiscoveredMACLookupKey(networkID int64, macAddress string) string {
	networkIDText := strconv.FormatInt(networkID, 10)
	macAddress = strings.ToLower(strings.TrimSpace(macAddress))
	if networkIDText == "0" || macAddress == "" {
		return ""
	}
	return networkIDText + "|" + macAddress
}

func normalizeManagedNetworkDiscoveredMACIPv4s(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		candidate, err := normalizeManagedNetworkIPv4Literal(raw)
		if err != nil {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeManagedNetworkDiscoveredMACIPv4s(left []string, right []string) []string {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	merged := append([]string(nil), left...)
	merged = append(merged, right...)
	return normalizeManagedNetworkDiscoveredMACIPv4s(merged)
}

func managedNetworkDiscoveredMACQuality(item managedNetworkDiscoveredMAC) int {
	score := 0
	if strings.TrimSpace(item.PVEGuestName) != "" {
		score += 4
	}
	if strings.TrimSpace(item.PVEVMID) != "" {
		score += 2
	}
	if strings.TrimSpace(item.PVEGuestNIC) != "" {
		score++
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(item.ChildInterface)), "tap") {
		score++
	}
	return score
}

func buildManagedNetworkReservationCandidateRemark(item managedNetworkDiscoveredMAC) string {
	guestName := strings.TrimSpace(item.PVEGuestName)
	vmid := strings.TrimSpace(item.PVEVMID)
	guestNIC := strings.TrimSpace(item.PVEGuestNIC)
	switch {
	case guestName != "" && guestNIC != "":
		return guestName + " / " + guestNIC
	case guestName != "" && vmid != "":
		return guestName + " / vm" + vmid
	case guestName != "":
		return guestName
	case vmid != "" && guestNIC != "":
		return "vm" + vmid + " / " + guestNIC
	case vmid != "":
		return "vm" + vmid
	default:
		return strings.TrimSpace(item.ChildInterface)
	}
}

type managedNetworkReservationIPv4Suggester struct {
	active bool
	next   uint64
	end    uint64
	used   map[uint32]struct{}
	subnet *net.IPNet
	server uint32
	reason string
}

func newManagedNetworkReservationIPv4Suggester(network ManagedNetwork, reservations []ManagedNetworkReservation) managedNetworkReservationIPv4Suggester {
	plan, err := buildManagedNetworkIPv4Plan(network, reservations)
	if err != nil {
		return managedNetworkReservationIPv4Suggester{reason: err.Error()}
	}
	_, serverIP, subnet, err := normalizeManagedNetworkIPv4CIDR(network.IPv4CIDR)
	if err != nil {
		return managedNetworkReservationIPv4Suggester{reason: err.Error()}
	}
	start := uint64(managedNetworkIPv4LiteralToUint32(plan.DHCPv4.PoolStart))
	end := uint64(managedNetworkIPv4LiteralToUint32(plan.DHCPv4.PoolEnd))
	used := make(map[uint32]struct{}, len(reservations))
	for _, item := range reservations {
		if ip := strings.TrimSpace(item.IPv4Address); ip != "" {
			used[managedNetworkIPv4LiteralToUint32(ip)] = struct{}{}
		}
	}
	return managedNetworkReservationIPv4Suggester{
		active: true,
		next:   start,
		end:    end,
		used:   used,
		subnet: subnet,
		server: managedNetworkIPv4LiteralToUint32(serverIP),
	}
}

func (s *managedNetworkReservationIPv4Suggester) Next() (string, string) {
	if !s.active {
		if strings.TrimSpace(s.reason) == "" {
			return "", "no free ipv4 remains inside dhcp pool"
		}
		return "", s.reason
	}
	for value := s.next; value <= s.end; value++ {
		current := uint32(value)
		if _, ok := s.used[current]; ok {
			continue
		}
		s.used[current] = struct{}{}
		s.next = value + 1
		return uint32ToIPv4(current).String(), ""
	}
	s.reason = "no free ipv4 remains inside dhcp pool"
	return "", s.reason
}

func (s *managedNetworkReservationIPv4Suggester) NextPreferred(preferred string) (string, string) {
	if preferred = strings.TrimSpace(preferred); preferred != "" {
		if current, ok := s.reservePreferred(preferred); ok {
			return current, ""
		}
	}
	return s.Next()
}

func (s *managedNetworkReservationIPv4Suggester) reservePreferred(preferred string) (string, bool) {
	if !s.active {
		return "", false
	}
	ip := parseIPLiteral(preferred).To4()
	if ip == nil || s.subnet == nil || !s.subnet.Contains(ip) {
		return "", false
	}
	if isManagedNetworkIPv4ReservedHost(ip, s.subnet.IP.To4(), s.subnet.Mask) {
		return "", false
	}
	value := managedNetworkIPv4ToUint32(ip)
	if value == s.server {
		return "", false
	}
	if _, ok := s.used[value]; ok {
		return "", false
	}
	s.used[value] = struct{}{}
	return uint32ToIPv4(value).String(), true
}
