package app

import (
	"strings"
	"testing"
)

// parsePluginControlOffloadFeatures reads the legacy group states out of
// `ethtool -k` output. The host sets and reads offloads with ioctls; tests
// compare them with what ethtool itself reports.
func parsePluginControlOffloadFeatures(output string) map[string]bool {
	aliases := map[string]string{
		"rx-checksumming":              "rx",
		"tx-checksumming":              "tx",
		"scatter-gather":               "sg",
		"tcp-segmentation-offload":     "tso",
		"udp-fragmentation-offload":    "ufo",
		"generic-segmentation-offload": "gso",
		"generic-receive-offload":      "gro",
		"large-receive-offload":        "lro",
	}
	out := make(map[string]bool, len(aliases))
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		feature, ok := aliases[strings.TrimSpace(strings.ToLower(parts[0]))]
		if !ok {
			continue
		}
		state := strings.Fields(strings.TrimSpace(strings.ToLower(parts[1])))
		if len(state) == 0 || (state[0] != "on" && state[0] != "off") {
			continue
		}
		out[feature] = state[0] == "on"
	}
	return out
}

func TestPluginControlNetLinkInfoPreservesOwnershipAndTUNCapabilities(t *testing.T) {
	info := pluginControlNetLinkInfo{Name: "tun0", Alias: "veer:vpn_core:default", Kind: "tuntap", TunMode: "tun", TunVNetHeader: true}
	got := pluginControlNetLinkInfoMap(info)
	if got["alias"] != info.Alias || got["tun_mode"] != "tun" || got["tun_vnet_hdr"] != true {
		t.Fatalf("link details lost: %+v", got)
	}
}

func TestParsePluginControlOffloadFeatures(t *testing.T) {
	features := parsePluginControlOffloadFeatures(`Features for eth0:
rx-checksumming: on
tx-checksumming: off [fixed]
scatter-gather: on
tcp-segmentation-offload: on
udp-fragmentation-offload: off [fixed]
generic-segmentation-offload: on
generic-receive-offload: off
large-receive-offload: off [fixed]
	tx-scatter-gather: on
`)
	want := map[string]bool{
		"rx": true, "tx": false, "sg": true, "tso": true,
		"ufo": false, "gso": true, "gro": false, "lro": false,
	}
	if len(features) != len(want) {
		t.Fatalf("feature count = %d, want %d: %+v", len(features), len(want), features)
	}
	for feature, enabled := range want {
		if actual, ok := features[feature]; !ok || actual != enabled {
			t.Fatalf("feature %s = %t (present=%t), want %t", feature, actual, ok, enabled)
		}
	}
}
