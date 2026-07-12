package app

import "testing"

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
