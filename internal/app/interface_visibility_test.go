package app

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestUserInterfaceInfosHidesOnlyCurrentOwnedWANPipeline(t *testing.T) {
	for _, fault := range []string{"", "index", "mac", "peer", "boot", "namespace", "owner", "missing", "direct"} {
		t.Run(fault, func(t *testing.T) {
			db := openTestDB(t)
			links := map[string]pluginControlNetLinkInfo{
				"wan0":  {Name: "wan0", IfIndex: 10, Kind: "veth", MAC: "02:00:00:00:00:01", PeerIfIndex: 11},
				"pipe0": {Name: "pipe0", IfIndex: 11, Kind: "veth", MAC: "02:00:00:00:00:02", PeerIfIndex: 10},
			}
			for _, name := range []string{"wan0", "pipe0"} {
				link := links[name]
				peer := "wan0"
				if name == "wan0" {
					peer = "pipe0"
				}
				claim := pluginOwnedLinkClaim{Name: name, Kind: "veth", IfIndex: link.IfIndex, MAC: link.MAC, Peer: peer, BootID: pluginOwnershipBootID}
				owner := "wan_core"
				if name == "pipe0" {
					switch fault {
					case "index":
						link.IfIndex++
					case "mac":
						link.MAC = "02:00:00:00:99:99"
					case "peer":
						link.PeerIfIndex++
					case "boot":
						claim.BootID = "previous-boot"
					case "namespace":
						claim.Namespace = "other"
					case "owner":
						owner = "other"
					}
					links[name] = link
				}
				data, _ := json.Marshal(claim)
				if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: owner, ResourceType: pluginOwnedResourceTypeLink, ResourceKey: name, MetadataJSON: string(data)}); err != nil {
					t.Fatal(err)
				}
			}
			mode := "segmented_veth"
			if fault == "direct" {
				mode = "direct"
			}
			data, _ := json.Marshal(map[string]any{"handoff_mode": mode, "local_interface": "wan0", "pipeline_interface": "pipe0"})
			if _, err := store.AddPluginRecord(db, &store.PluginRecord{PluginID: "wan_core", ResourceID: "status", RecordKey: "wan", DataJSON: string(data), Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if fault == "missing" {
				delete(links, "pipe0")
			}
			infos := []InterfaceInfo{{Name: "eth0"}, {Name: "wan0"}, {Name: "pipe0"}, {Name: "veervpnp9"}}
			got := userInterfaceInfos(db, infos, func(name string) (pluginControlNetLinkInfo, error) {
				link, ok := links[name]
				if !ok {
					return link, fmt.Errorf("missing")
				}
				return link, nil
			})
			want := 4
			if fault == "" {
				want = 3
			}
			if len(got) != want || got[len(got)-1].Name != "veervpnp9" {
				t.Fatalf("visible interfaces: %+v", got)
			}
		})
	}
}
