package app

import (
	"encoding/json"

	"github.com/Unicode01/veer/internal/store"
)

// Only the current, owned peer of a WAN boundary is an internal pipe. Names
// alone cannot distinguish our devices from an administrator's own veths.
func internalWANPipelineNames(db store.RuleStore, get func(string) (pluginControlNetLinkInfo, error)) map[string]bool {
	records, err := store.GetPluginRecords(db, "wan_core", "status")
	if err != nil || len(records) == 0 {
		return nil
	}
	owned, err := store.GetPluginOwnedResources(db, "wan_core")
	if err != nil {
		return nil
	}
	claims := map[string]pluginOwnedLinkClaim{}
	for _, item := range owned {
		var claim pluginOwnedLinkClaim
		if item.ResourceType == pluginOwnedResourceTypeLink && json.Unmarshal([]byte(item.MetadataJSON), &claim) == nil &&
			normalizePluginControlNamespace(claim.Namespace) == "host" && claim.BootID == pluginOwnershipBootID {
			claims[claim.Name] = claim
		}
	}
	hidden := map[string]bool{}
	for _, record := range records {
		var status struct {
			Mode  string `json:"handoff_mode"`
			Local string `json:"local_interface"`
			Peer  string `json:"pipeline_interface"`
		}
		if json.Unmarshal([]byte(record.DataJSON), &status) != nil || status.Mode != "segmented_veth" || status.Local == status.Peer {
			continue
		}
		local, lok := claims[status.Local]
		peer, pok := claims[status.Peer]
		if !lok || !pok || local.Peer != peer.Name || peer.Peer != local.Name || local.Kind != "veth" || peer.Kind != "veth" || local.IfIndex <= 0 || peer.IfIndex <= 0 || local.MAC == "" || peer.MAC == "" {
			continue
		}
		l, le := get(local.Name)
		p, pe := get(peer.Name)
		if le == nil && pe == nil && pluginOwnedLinkIdentityMatches(l, local.IfIndex, local.Kind, local.MAC) &&
			pluginOwnedLinkIdentityMatches(p, peer.IfIndex, peer.Kind, peer.MAC) && l.PeerIfIndex == p.IfIndex && p.PeerIfIndex == l.IfIndex {
			hidden[peer.Name] = true
		}
	}
	return hidden
}

func userInterfaceInfos(db store.RuleStore, infos []InterfaceInfo, get func(string) (pluginControlNetLinkInfo, error)) []InterfaceInfo {
	hidden := internalWANPipelineNames(db, get)
	visible := make([]InterfaceInfo, 0, len(infos))
	for _, info := range infos {
		if !hidden[info.Name] {
			visible = append(visible, info)
		}
	}
	return visible
}

func userHostNetworkInterfaces(db store.RuleStore, infos []HostNetworkInterface, get func(string) (pluginControlNetLinkInfo, error)) []HostNetworkInterface {
	hidden := internalWANPipelineNames(db, get)
	visible := make([]HostNetworkInterface, 0, len(infos))
	for _, info := range infos {
		if !hidden[info.Name] {
			visible = append(visible, info)
		}
	}
	return visible
}
