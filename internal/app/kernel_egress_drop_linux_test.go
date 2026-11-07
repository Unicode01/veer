//go:build linux

package app

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestProtocolWANDropPreparationDoesNotResolveMissingExit(t *testing.T) {
	ctx := newKernelPrepareContext(false, true, false)
	ctx.links["lan0"] = cachedKernelLink{link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name: "lan0", Index: 10, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1},
	}}}
	rule := buildEgressNATSyntheticRule(EgressNAT{
		OutInterface: "missing-vpn", RedirectMode: egressNATRedirectModePreparedL2, Enabled: true,
	}, "lan0", 7, "udp")
	rule.kernelUnavailable = true
	items, err := prepareKernelRule(ctx, rule)
	if err != nil || len(items) != 1 {
		t.Fatalf("prepare drop = %+v, %v", items, err)
	}
	if _, resolved := ctx.links["missing-vpn"]; resolved {
		t.Fatal("drop selector tried to resolve the unavailable exit")
	}
	item := items[0]
	if item.key.IfIndex != 10 || item.key.Proto != 17 || item.value.Flags&kernelRuleFlagDrop == 0 || item.value.NATAddr != 0 {
		t.Fatalf("invalid drop selector: %+v", item)
	}
	if item.value.SrcMAC != [6]byte{2, 0, 0, 0, 0, 1} {
		t.Fatalf("drop selector lost the local destination-MAC guard: %v", item.value.SrcMAC)
	}
}

func TestEgressNATPreparationGuardsExitLostAfterPreflight(t *testing.T) {
	// The public NAT API has no plugin-only redirect metadata. The exit may
	// disappear after the planner accepted it but before map preparation.
	rule := buildEgressNATSyntheticRule(EgressNAT{
		OutInterface: "missing-vpn", Enabled: true,
	}, "lo", 7, "udp")
	prepared, forward, reply, _, results, _ := prepareKernelRules([]Rule{rule}, nil, false, false, true, false)
	if len(prepared) != 1 || len(forward) != 1 || len(reply) != 1 || len(results) != 0 {
		t.Fatalf("missing exit lost the ingress guard: prepared=%+v forward=%v reply=%v results=%v", prepared, forward, reply, results)
	}
	if prepared[0].value.Flags&kernelRuleFlagDrop == 0 {
		t.Fatal("missing exit did not produce a drop selector")
	}
}
