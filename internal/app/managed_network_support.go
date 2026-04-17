package app

import (
	"net"

	"forward/internal/managednet"

	"github.com/vishvananda/netlink"
)

const (
	managedNetworkReservationCandidateStatusAvailable   = managednet.ReservationCandidateStatusAvailable
	managedNetworkReservationCandidateStatusReserved    = managednet.ReservationCandidateStatusReserved
	managedNetworkReservationCandidateStatusUnavailable = managednet.ReservationCandidateStatusUnavailable
	managedNetworkReservationCandidateIPv4ChoicesLimit  = managednet.ReservationCandidateIPv4ChoicesLimit
)

type managedNetworkPVEBridgeBinding = managednet.PVEBridgeBinding
type managedNetworkRepairResult = managednet.RepairResult
type managedNetworkRepairLinkOps = managednet.RepairLinkOps
type managedNetworkPVEGuestNIC = managednet.PVEGuestNIC
type managedNetworkDiscoveredMAC = managednet.DiscoveredMAC
type managedNetworkPersistBridgeResult = managednet.PersistBridgeResult
type managedNetworkPersistBridgeIssue = managednet.PersistBridgeIssue
type managedNetworkPersistedBridgeSpec = managednet.PersistedBridgeSpec

const managedNetworkHostInterfacesConfigPath = managednet.ManagedNetworkHostInterfacesConfigPath

var repairManagedNetworkHostStateForTests func([]ManagedNetwork) (managedNetworkRepairResult, error)
var loadManagedNetworkPVEConfigsForTests func() (map[string]string, error)
var managedNetworkRepairLinkOpsForTests managedNetworkRepairLinkOps
var loadManagedNetworkReservationCandidatesForTests func([]ManagedNetwork, []ManagedNetworkReservation) ([]ManagedNetworkReservationCandidate, error)
var persistManagedNetworkBridgeForTests func(ManagedNetwork) (managedNetworkPersistBridgeResult, error)

func repairManagedNetworkHostStateWithHook(items []ManagedNetwork) (managedNetworkRepairResult, error) {
	if repairManagedNetworkHostStateForTests != nil {
		return repairManagedNetworkHostStateForTests(items)
	}
	return repairManagedNetworkHostState(items)
}

func repairManagedNetworkHostState(items []ManagedNetwork) (managedNetworkRepairResult, error) {
	return managednet.RepairHostState(toManagedNetManagedNetworks(items), managednet.RepairOptions{
		LoadPVEConfigs: loadManagedNetworkPVEConfigsForTests,
		LinkOps:        managedNetworkRepairLinkOpsForTests,
	})
}

func summarizeManagedNetworkRepairResult(result managedNetworkRepairResult) string {
	return managednet.SummarizeRepairResult(result)
}

func persistManagedNetworkBridgeWithHook(item ManagedNetwork) (managedNetworkPersistBridgeResult, error) {
	if persistManagedNetworkBridgeForTests != nil {
		return persistManagedNetworkBridgeForTests(item)
	}
	return persistManagedNetworkBridge(item)
}

func persistManagedNetworkBridge(item ManagedNetwork) (managedNetworkPersistBridgeResult, error) {
	return managednet.PersistBridge(toManagedNetManagedNetwork(item))
}

func buildManagedNetworkPersistedBridgeBlock(spec managedNetworkPersistedBridgeSpec) (string, error) {
	return managednet.BuildPersistedBridgeBlock(spec)
}

func managedNetworkInterfacesDirectivePaths(basePath string, content string) []string {
	return managednet.InterfacesDirectivePaths(basePath, content)
}

func appendManagedNetworkBridgeBlock(content string, spec managedNetworkPersistedBridgeSpec) (string, bool, error) {
	return managednet.AppendBridgeBlock(content, spec)
}

func managedNetworkRepairResultInterfaceNames(result managedNetworkRepairResult) []string {
	return managednet.RepairResultInterfaceNames(result)
}

func parseManagedNetworkPVEBridgeBindings(vmid string, content string) []managedNetworkPVEBridgeBinding {
	return managednet.ParsePVEBridgeBindings(vmid, content)
}

func buildManagedNetworkRepairInterfaceParentMap(infos []InterfaceInfo) map[string]string {
	return managednet.BuildRepairInterfaceParentMap(toManagedNetInterfaceInfos(infos))
}

func buildManagedNetworkRepairIssueMap(items []ManagedNetwork, ifaceParentByName map[string]string) map[int64][]string {
	bindings, _ := loadManagedNetworkPVEBridgeBindings()
	return managednet.BuildRepairIssueMap(toManagedNetManagedNetworks(items), ifaceParentByName, bindings)
}

func detectManagedNetworkDetachedPVEGuestLink(binding managedNetworkPVEBridgeBinding, bridge string, ifaceParentByName map[string]string) (bool, string) {
	return managednet.DetectDetachedPVEGuestLink(binding, bridge, ifaceParentByName)
}

func managedNetworkPVEGuestLinkCandidates(binding managedNetworkPVEBridgeBinding) []string {
	return managednet.PVEGuestLinkCandidates(binding)
}

func loadManagedNetworkPVEBridgeBindings() ([]managedNetworkPVEBridgeBinding, error) {
	return managednet.LoadPVEBridgeBindings(managednet.RepairOptions{
		LoadPVEConfigs: loadManagedNetworkPVEConfigsForTests,
	})
}

func loadManagedNetworkPVEGuestNICs() ([]managedNetworkPVEGuestNIC, error) {
	return managednet.LoadPVEGuestNICs(managednet.RepairOptions{
		LoadPVEConfigs: loadManagedNetworkPVEConfigsForTests,
	})
}

func loadManagedNetworkPVEConfigsFromGlobs(patterns []string) (map[string]string, error) {
	return managednet.LoadPVEConfigsFromGlobs(patterns)
}

func repairManagedNetworkPVEBridgeLinks(networks map[string]ManagedNetwork, bindings []managedNetworkPVEBridgeBinding, ops managedNetworkRepairLinkOps) (managedNetworkRepairResult, error) {
	return managednet.RepairPVEBridgeLinks(toManagedNetNetworkMap(networks), bindings, ops)
}

func ensureManagedNetworkGuestLinkAttached(link netlink.Link, bridge netlink.Link, ops managedNetworkRepairLinkOps) (bool, error) {
	return managednet.EnsureGuestLinkAttached(link, bridge, ops)
}

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
	if loadManagedNetworkReservationCandidatesForTests != nil {
		return loadManagedNetworkReservationCandidatesForTests(networks, reservations)
	}
	return discoverManagedNetworkReservationCandidates(networks, reservations)
}

func discoverManagedNetworkReservationCandidates(networks []ManagedNetwork, reservations []ManagedNetworkReservation) ([]ManagedNetworkReservationCandidate, error) {
	items, err := managednet.DiscoverReservationCandidates(
		toManagedNetManagedNetworks(networks),
		toManagedNetManagedNetworkReservations(reservations),
		managednet.CandidateDiscoveryOptions{
			LoadInterfaceInfos: loadManagedNetPreviewInterfaceInfos,
			RepairOptions: managednet.RepairOptions{
				LoadPVEConfigs: loadManagedNetworkPVEConfigsForTests,
			},
		},
	)
	if err != nil {
		return nil, err
	}
	return fromManagedNetReservationCandidates(items), nil
}

func buildManagedNetworkReservationCandidates(networks []ManagedNetwork, reservations []ManagedNetworkReservation, discovered []managedNetworkDiscoveredMAC) []ManagedNetworkReservationCandidate {
	return buildManagedNetworkReservationCandidatesWithInfos(networks, reservations, discovered, nil)
}

func buildManagedNetworkReservationCandidatesWithInfos(networks []ManagedNetwork, reservations []ManagedNetworkReservation, discovered []managedNetworkDiscoveredMAC, infos []InterfaceInfo) []ManagedNetworkReservationCandidate {
	return fromManagedNetReservationCandidates(
		managednet.BuildReservationCandidatesWithInfos(
			toManagedNetManagedNetworks(networks),
			toManagedNetManagedNetworkReservations(reservations),
			discovered,
			toManagedNetInterfaceInfos(infos),
		),
	)
}

func dedupeManagedNetworkDiscoveredMACs(items []managedNetworkDiscoveredMAC) []managedNetworkDiscoveredMAC {
	return managednet.DedupeDiscoveredMACs(items)
}

func parseManagedNetworkPVEGuestNICs(vmid string, content string) []managedNetworkPVEGuestNIC {
	return managednet.ParsePVEGuestNICs(vmid, content)
}

func enrichManagedNetworkDiscoveredMACsWithPVEGuestNICs(items []managedNetworkDiscoveredMAC, nics []managedNetworkPVEGuestNIC) []managedNetworkDiscoveredMAC {
	return managednet.EnrichDiscoveredMACsWithPVEGuestNICs(items, nics)
}

func discoverManagedNetworkReservationFDBMACs(networks []ManagedNetwork, infos []InterfaceInfo) ([]managedNetworkDiscoveredMAC, error) {
	return managednet.DiscoverReservationFDBMACs(toManagedNetManagedNetworks(networks), toManagedNetInterfaceInfos(infos))
}

func discoverManagedNetworkReservationObservedIPv4s(discovered []managedNetworkDiscoveredMAC, networks []ManagedNetwork) (map[string][]string, error) {
	return managednet.DiscoverReservationObservedIPv4s(discovered, toManagedNetManagedNetworks(networks))
}

func collectManagedNetworkObservedIPv4sForNetwork(network ManagedNetwork, bridgeIndex int, memberIndexes map[int]struct{}, hostMACs map[string]struct{}, interestedMACs map[string]struct{}, neighbors []netlink.Neigh) map[string][]string {
	return managednet.CollectObservedIPv4sForNetwork(toManagedNetManagedNetwork(network), bridgeIndex, memberIndexes, hostMACs, interestedMACs, neighbors)
}

func normalizeManagedNetworkReservationCandidateMAC(hw net.HardwareAddr) string {
	return managednet.NormalizeReservationCandidateMAC(hw)
}

func loadManagedNetPreviewInterfaceInfos() ([]managednet.InterfaceInfo, error) {
	infos, err := loadManagedNetworkPreviewInterfaceInfos()
	if err != nil {
		return nil, err
	}
	return toManagedNetInterfaceInfos(infos), nil
}

func toManagedNetManagedNetwork(item ManagedNetwork) managednet.ManagedNetwork {
	return managednet.ManagedNetwork{
		ID:                  item.ID,
		Name:                item.Name,
		BridgeMode:          item.BridgeMode,
		Bridge:              item.Bridge,
		BridgeMTU:           item.BridgeMTU,
		BridgeVLANAware:     item.BridgeVLANAware,
		UplinkInterface:     item.UplinkInterface,
		IPv4Enabled:         item.IPv4Enabled,
		IPv4CIDR:            item.IPv4CIDR,
		IPv4Gateway:         item.IPv4Gateway,
		IPv4PoolStart:       item.IPv4PoolStart,
		IPv4PoolEnd:         item.IPv4PoolEnd,
		IPv4DNSServers:      item.IPv4DNSServers,
		IPv6Enabled:         item.IPv6Enabled,
		IPv6ParentInterface: item.IPv6ParentInterface,
		IPv6ParentPrefix:    item.IPv6ParentPrefix,
		IPv6AssignmentMode:  item.IPv6AssignmentMode,
		AutoEgressNAT:       item.AutoEgressNAT,
		Remark:              item.Remark,
		Enabled:             item.Enabled,
	}
}

func toManagedNetManagedNetworks(items []ManagedNetwork) []managednet.ManagedNetwork {
	if len(items) == 0 {
		return nil
	}
	out := make([]managednet.ManagedNetwork, 0, len(items))
	for _, item := range items {
		out = append(out, toManagedNetManagedNetwork(item))
	}
	return out
}

func toManagedNetManagedNetworkReservations(items []ManagedNetworkReservation) []managednet.ManagedNetworkReservation {
	if len(items) == 0 {
		return nil
	}
	out := make([]managednet.ManagedNetworkReservation, 0, len(items))
	for _, item := range items {
		out = append(out, managednet.ManagedNetworkReservation{
			ID:               item.ID,
			ManagedNetworkID: item.ManagedNetworkID,
			MACAddress:       item.MACAddress,
			IPv4Address:      item.IPv4Address,
			Remark:           item.Remark,
		})
	}
	return out
}

func toManagedNetInterfaceInfos(items []InterfaceInfo) []managednet.InterfaceInfo {
	if len(items) == 0 {
		return nil
	}
	out := make([]managednet.InterfaceInfo, 0, len(items))
	for _, item := range items {
		out = append(out, managednet.InterfaceInfo{
			Name:   item.Name,
			Addrs:  append([]string(nil), item.Addrs...),
			Parent: item.Parent,
			Kind:   item.Kind,
		})
	}
	return out
}

func toManagedNetNetworkMap(items map[string]ManagedNetwork) map[string]managednet.ManagedNetwork {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]managednet.ManagedNetwork, len(items))
	for key, item := range items {
		out[key] = toManagedNetManagedNetwork(item)
	}
	return out
}

func fromManagedNetReservationCandidates(items []managednet.ReservationCandidate) []ManagedNetworkReservationCandidate {
	if len(items) == 0 {
		return []ManagedNetworkReservationCandidate{}
	}
	out := make([]ManagedNetworkReservationCandidate, 0, len(items))
	for _, item := range items {
		out = append(out, fromManagedNetReservationCandidate(item))
	}
	return out
}

func fromManagedNetReservationCandidate(item managednet.ReservationCandidate) ManagedNetworkReservationCandidate {
	return ManagedNetworkReservationCandidate{
		ManagedNetworkID:          item.ManagedNetworkID,
		ManagedNetworkName:        item.ManagedNetworkName,
		ManagedNetworkBridge:      item.ManagedNetworkBridge,
		PVEVMID:                   item.PVEVMID,
		PVEGuestName:              item.PVEGuestName,
		PVEGuestNIC:               item.PVEGuestNIC,
		ChildInterface:            item.ChildInterface,
		MACAddress:                item.MACAddress,
		SuggestedIPv4:             item.SuggestedIPv4,
		IPv4Candidates:            append([]string(nil), item.IPv4Candidates...),
		SuggestedRemark:           item.SuggestedRemark,
		Status:                    item.Status,
		StatusMessage:             item.StatusMessage,
		ExistingReservationID:     item.ExistingReservationID,
		ExistingReservationIPv4:   item.ExistingReservationIPv4,
		ExistingReservationRemark: item.ExistingReservationRemark,
	}
}
