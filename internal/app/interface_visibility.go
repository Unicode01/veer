package app

import (
	"encoding/json"

	"github.com/Unicode01/veer/internal/store"
)

// Plugins mark the links they own as internal plumbing (for example the
// pipeline end of a WAN boundary). Names alone cannot distinguish those from an
// administrator's own devices, so a link is hidden only while its claim still
// matches the live device on this boot, and a veth only while its peer is the
// one the same plugin owns.
func internalPluginLinkNames(db store.RuleStore, get func(string) (pluginControlNetLinkInfo, error)) map[string]bool {
	owned, err := store.GetPluginOwnedResources(db, "")
	if err != nil {
		return nil
	}
	type ownedLink struct {
		plugin string
		claim  pluginOwnedLinkClaim
	}
	links := map[string]ownedLink{}
	for _, item := range owned {
		var claim pluginOwnedLinkClaim
		if item.ResourceType == pluginOwnedResourceTypeLink && json.Unmarshal([]byte(item.MetadataJSON), &claim) == nil &&
			normalizePluginControlNamespace(claim.Namespace) == "host" && claim.BootID == pluginOwnershipBootID {
			links[claim.Name] = ownedLink{plugin: item.PluginID, claim: claim}
		}
	}
	hidden := map[string]bool{}
	for name, link := range links {
		claim := link.claim
		if !claim.Internal || claim.IfIndex <= 0 || claim.MAC == "" {
			continue
		}
		info, err := get(name)
		if err != nil || !pluginOwnedLinkIdentityMatches(info, claim.IfIndex, claim.Kind, claim.MAC) {
			continue
		}
		if claim.Kind == "veth" {
			peer, ok := links[claim.Peer]
			if !ok || peer.plugin != link.plugin || peer.claim.Peer != name || peer.claim.Kind != "veth" || peer.claim.IfIndex <= 0 || peer.claim.MAC == "" {
				continue
			}
			peerInfo, err := get(peer.claim.Name)
			if err != nil || !pluginOwnedLinkIdentityMatches(peerInfo, peer.claim.IfIndex, peer.claim.Kind, peer.claim.MAC) ||
				info.PeerIfIndex != peerInfo.IfIndex || peerInfo.PeerIfIndex != info.IfIndex {
				continue
			}
		}
		hidden[name] = true
	}
	return hidden
}

func userInterfaceInfos(db store.RuleStore, infos []InterfaceInfo, get func(string) (pluginControlNetLinkInfo, error)) []InterfaceInfo {
	hidden := internalPluginLinkNames(db, get)
	visible := make([]InterfaceInfo, 0, len(infos))
	for _, info := range infos {
		if !hidden[info.Name] {
			visible = append(visible, info)
		}
	}
	return visible
}

func userHostNetworkInterfaces(db store.RuleStore, infos []HostNetworkInterface, get func(string) (pluginControlNetLinkInfo, error)) []HostNetworkInterface {
	hidden := internalPluginLinkNames(db, get)
	visible := make([]HostNetworkInterface, 0, len(infos))
	for _, info := range infos {
		if !hidden[info.Name] {
			visible = append(visible, info)
		}
	}
	return visible
}
