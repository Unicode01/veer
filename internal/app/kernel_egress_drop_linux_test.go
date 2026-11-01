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
