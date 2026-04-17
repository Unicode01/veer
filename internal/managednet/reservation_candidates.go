package managednet

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

func BuildReservationCandidates(networks []ManagedNetwork, reservations []ManagedNetworkReservation, discovered []DiscoveredMAC) []ReservationCandidate {
	return BuildReservationCandidatesWithInfos(networks, reservations, discovered, nil)
}

func BuildReservationCandidatesWithInfos(networks []ManagedNetwork, reservations []ManagedNetworkReservation, discovered []DiscoveredMAC, infos []InterfaceInfo) []ReservationCandidate {
	if len(discovered) == 0 || len(networks) == 0 {
		return []ReservationCandidate{}
	}

	networkByID := make(map[int64]ManagedNetwork, len(networks))
	for _, network := range networks {
		network = normalizeManagedNetwork(network)
		networkByID[network.ID] = network
	}

	discovered = DedupeDiscoveredMACs(discovered)
	candidatesByNetwork := make(map[int64][]DiscoveredMAC)
	for _, item := range discovered {
		network, ok := networkByID[item.ManagedNetworkID]
		if !ok || !network.Enabled || !network.IPv4Enabled {
			continue
		}
		candidatesByNetwork[item.ManagedNetworkID] = append(candidatesByNetwork[item.ManagedNetworkID], item)
	}
	if len(candidatesByNetwork) == 0 {
		return []ReservationCandidate{}
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

	out := make([]ReservationCandidate, 0, len(discovered))
	for _, networkID := range networkIDs {
		network := networkByID[networkID]
		discoveredItems := candidatesByNetwork[networkID]
		sort.Slice(discoveredItems, func(i, j int) bool {
			if discoveredItems[i].ChildInterface != discoveredItems[j].ChildInterface {
				return strings.Compare(discoveredItems[i].ChildInterface, discoveredItems[j].ChildInterface) < 0
			}
			return strings.Compare(discoveredItems[i].MACAddress, discoveredItems[j].MACAddress) < 0
		})

		suggest := newReservationIPv4Suggester(network, reservationsByNetwork[networkID])
		for _, item := range discoveredItems {
			candidate := ReservationCandidate{
				ManagedNetworkID:     network.ID,
				ManagedNetworkName:   network.Name,
				ManagedNetworkBridge: network.Bridge,
				ChildInterface:       item.ChildInterface,
				MACAddress:           strings.ToLower(strings.TrimSpace(item.MACAddress)),
				PVEVMID:              strings.TrimSpace(item.PVEVMID),
				PVEGuestName:         strings.TrimSpace(item.PVEGuestName),
				PVEGuestNIC:          strings.TrimSpace(item.PVEGuestNIC),
				SuggestedRemark:      buildReservationCandidateRemark(item),
			}

			if existing, ok := reservationsByNetworkMAC[networkID][candidate.MACAddress]; ok {
				candidate.Status = ReservationCandidateStatusReserved
				candidate.StatusMessage = "already reserved"
				candidate.ExistingReservationID = existing.ID
				candidate.ExistingReservationIPv4 = existing.IPv4Address
				candidate.ExistingReservationRemark = existing.Remark
				candidate.SuggestedIPv4 = existing.IPv4Address
				candidate.IPv4Candidates = []string{existing.IPv4Address}
				out = append(out, candidate)
				continue
			}

			preferredIPv4 := suggestReservationCandidateIPv4(network, item.ObservedIPv4s, infoByName[item.ChildInterface])
			suggested, reason := suggest.NextPreferred(preferredIPv4)
			candidate.SuggestedIPv4 = suggested
			if suggested != "" {
				candidate.Status = ReservationCandidateStatusAvailable
				candidate.IPv4Candidates = buildReservationCandidateIPv4Choices(
					network,
					reservationsByNetwork[networkID],
					item.ObservedIPv4s,
					infoByName[item.ChildInterface],
					suggested,
					ReservationCandidateIPv4ChoicesLimit,
				)
			} else {
				candidate.Status = ReservationCandidateStatusUnavailable
				candidate.StatusMessage = reason
			}
			out = append(out, candidate)
		}
	}

	if len(out) == 0 {
		return []ReservationCandidate{}
	}
	return out
}

func suggestReservationCandidateIPv4(network ManagedNetwork, observedIPv4s []string, info InterfaceInfo) string {
	candidates := reservationPreferredIPv4s(network, observedIPv4s, info)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func reservationPreferredIPv4s(network ManagedNetwork, observedIPv4s []string, info InterfaceInfo) []string {
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

func buildReservationCandidateIPv4Choices(network ManagedNetwork, reservations []ManagedNetworkReservation, observedIPv4s []string, info InterfaceInfo, suggested string, limit int) []string {
	if limit <= 0 {
		limit = 1
	}

	suggest := newReservationIPv4Suggester(network, reservations)
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
	for _, candidate := range reservationPreferredIPv4s(network, observedIPv4s, info) {
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

func DedupeDiscoveredMACs(items []DiscoveredMAC) []DiscoveredMAC {
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
	out := make([]DiscoveredMAC, 0, len(items))
	seen := make(map[string]int, len(items))
	for _, item := range items {
		item.ChildInterface = strings.TrimSpace(item.ChildInterface)
		item.MACAddress = strings.ToLower(strings.TrimSpace(item.MACAddress))
		item.ObservedIPv4s = normalizeDiscoveredMACIPv4s(item.ObservedIPv4s)
		item.PVEVMID = strings.TrimSpace(item.PVEVMID)
		item.PVEGuestName = strings.TrimSpace(item.PVEGuestName)
		item.PVEGuestNIC = strings.TrimSpace(item.PVEGuestNIC)
		if item.ManagedNetworkID <= 0 || item.ChildInterface == "" || item.MACAddress == "" {
			continue
		}
		key := discoveredMACLookupKey(item.ManagedNetworkID, item.MACAddress)
		if index, ok := seen[key]; ok {
			mergedObservedIPv4s := mergeDiscoveredMACIPv4s(out[index].ObservedIPv4s, item.ObservedIPv4s)
			if discoveredMACQuality(item) > discoveredMACQuality(out[index]) {
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

func discoveredMACLookupKey(networkID int64, macAddress string) string {
	networkIDText := strconv.FormatInt(networkID, 10)
	macAddress = strings.ToLower(strings.TrimSpace(macAddress))
	if networkIDText == "0" || macAddress == "" {
		return ""
	}
	return networkIDText + "|" + macAddress
}

func normalizeDiscoveredMACIPv4s(values []string) []string {
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

func mergeDiscoveredMACIPv4s(left []string, right []string) []string {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	merged := append([]string(nil), left...)
	merged = append(merged, right...)
	return normalizeDiscoveredMACIPv4s(merged)
}

func discoveredMACQuality(item DiscoveredMAC) int {
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

func buildReservationCandidateRemark(item DiscoveredMAC) string {
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

type reservationIPv4Suggester struct {
	active bool
	next   uint64
	end    uint64
	used   map[uint32]struct{}
	subnet *net.IPNet
	server uint32
	reason string
}

func newReservationIPv4Suggester(network ManagedNetwork, reservations []ManagedNetworkReservation) reservationIPv4Suggester {
	plan, err := buildReservationIPv4Plan(network)
	if err != nil {
		return reservationIPv4Suggester{reason: err.Error()}
	}
	start := uint64(managedNetworkIPv4LiteralToUint32(plan.PoolStart))
	end := uint64(managedNetworkIPv4LiteralToUint32(plan.PoolEnd))
	used := make(map[uint32]struct{}, len(reservations))
	for _, item := range reservations {
		if ip := strings.TrimSpace(item.IPv4Address); ip != "" {
			used[managedNetworkIPv4LiteralToUint32(ip)] = struct{}{}
		}
	}
	return reservationIPv4Suggester{
		active: true,
		next:   start,
		end:    end,
		used:   used,
		subnet: plan.Subnet,
		server: managedNetworkIPv4LiteralToUint32(plan.ServerIP),
	}
}

func (s *reservationIPv4Suggester) Next() (string, string) {
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

func (s *reservationIPv4Suggester) NextPreferred(preferred string) (string, string) {
	if preferred = strings.TrimSpace(preferred); preferred != "" {
		if current, ok := s.reservePreferred(preferred); ok {
			return current, ""
		}
	}
	return s.Next()
}

func (s *reservationIPv4Suggester) reservePreferred(preferred string) (string, bool) {
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

func AttachDiscoveredMACObservedIPv4s(items []DiscoveredMAC, observedByKey map[string][]string) []DiscoveredMAC {
	if len(items) == 0 || len(observedByKey) == 0 {
		return items
	}
	out := append([]DiscoveredMAC(nil), items...)
	for i := range out {
		key := discoveredMACLookupKey(out[i].ManagedNetworkID, out[i].MACAddress)
		if key == "" {
			continue
		}
		out[i].ObservedIPv4s = mergeDiscoveredMACIPv4s(out[i].ObservedIPv4s, observedByKey[key])
	}
	return out
}

func NormalizeReservationCandidateMAC(hw net.HardwareAddr) string {
	if !isValidReservationCandidateMAC(hw) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(hw.String()))
}

func isValidReservationCandidateMAC(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}
	if strings.EqualFold(hw.String(), net.HardwareAddr{0, 0, 0, 0, 0, 0}.String()) {
		return false
	}
	return hw[0]&1 == 0
}
