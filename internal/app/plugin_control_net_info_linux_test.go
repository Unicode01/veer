//go:build linux

package app

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestPluginControlNetLinkInfoTUNMetadata(t *testing.T) {
	// Address lookup is read-only; use the real loopback index while exercising
	// each decoded netlink TUN attribute combination without CAP_NET_ADMIN.
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mode netlink.TuntapMode
		vnet bool
	}{
		{"tun", netlink.TUNTAP_MODE_TUN, true},
		{"tun", netlink.TUNTAP_MODE_TUN, false},
		{"tap", netlink.TUNTAP_MODE_TAP, true},
	} {
		link := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "testtun", Index: lo.Index, Alias: "veer:wireguard_mesh:test"}, Mode: tc.mode}
		if tc.vnet {
			link.Flags = netlink.TUNTAP_VNET_HDR
		}
		info, err := pluginControlNetLinkInfoFromLink(link)
		if err != nil {
			t.Fatal(err)
		}
		if info.Kind != "tuntap" || info.TunMode != tc.name || info.TunVNetHeader != tc.vnet || info.Alias != link.Alias {
			t.Fatalf("TUN metadata lost: %+v", info)
		}
	}
}
