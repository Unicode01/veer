//go:build linux

package kernelcap

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func TestNetdevDevGetDumpRequestKeepsTheReservedFieldZero(t *testing.T) {
	for i := 0; i < 1000; i++ {
		// Interleave small allocations, which is where the reserved field
		// of nl.Genlmsg picked up stray bytes.
		_ = []byte{0xff, 0xff, 0xff}
		msg := netdevDevGetDumpRequest(20).Serialize()
		if len(msg) != 20 {
			t.Fatalf("request is %d bytes, want a 16-byte header and a 4-byte genl header", len(msg))
		}
		if got := msg[16:]; got[0] != netdevCmdDevGet || got[1] != netdevFamilyVersion || got[2] != 0 || got[3] != 0 {
			t.Fatalf("genl header = % x, want %02x %02x 00 00", got, netdevCmdDevGet, netdevFamilyVersion)
		}
	}
}

func netdevDevGetReply(attrs ...*nl.RtAttr) []byte {
	msg := []byte{netdevCmdDevGet, netdevFamilyVersion, 0, 0}
	for _, attr := range attrs {
		msg = append(msg, attr.Serialize()...)
	}
	return msg
}

func TestParseNetdevXDPFeaturesReadsEachDevice(t *testing.T) {
	u32 := func(v uint32) []byte { b := make([]byte, 4); nl.NativeEndian().PutUint32(b, v); return b }
	u64 := func(v uint64) []byte { b := make([]byte, 8); nl.NativeEndian().PutUint64(b, v); return b }
	msgs := [][]byte{
		netdevDevGetReply(
			nl.NewRtAttr(netdevAttrDevIfindex, u32(2)),
			nl.NewRtAttr(2, nil), // NETDEV_A_DEV_PAD
			nl.NewRtAttr(netdevAttrDevXDPFeatures, u64(0xb)),
			nl.NewRtAttr(4, u32(1)), // NETDEV_A_DEV_XDP_ZC_MAX_SEGS
		),
		netdevDevGetReply(nl.NewRtAttr(netdevAttrDevIfindex, u32(7))),
		netdevDevGetReply(nl.NewRtAttr(netdevAttrDevXDPFeatures, u64(0x7))),
	}
	got, err := parseNetdevXDPFeatures(msgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[2] != 0xb || got[7] != 0 {
		t.Fatalf("features = %v, want map[2:0xb 7:0]", got)
	}
	if _, err := parseNetdevXDPFeatures([][]byte{{1}}); err == nil {
		t.Fatal("a reply shorter than the genl header must fail")
	}
}

// TestDetectXDPNativeDevicesReadsTheHost runs against this host's kernel; it
// only checks the report holds together, since devices differ per host.
func TestDetectXDPNativeDevicesReadsTheHost(t *testing.T) {
	report := DetectXDPNativeDevices()
	if !report.Available {
		if report.Reason == "" {
			t.Fatal("an unavailable report must say why")
		}
		t.Skipf("no per-device XDP features here: %s", report.Reason)
	}
	// The netdev family on 6.12 marks dump replies as single messages; a
	// reader that stops at the first one sees loopback alone.
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	others := 0
	for _, link := range links {
		if link.Attrs().Flags&net.FlagLoopback == 0 {
			others++
		}
	}
	if len(report.Devices) != others {
		t.Fatalf("report lists %d devices, the host has %d besides loopback", len(report.Devices), others)
	}
	for _, device := range report.Devices {
		if device.Name == "" || device.Index <= 0 {
			t.Fatalf("device %+v lacks a name or index", device)
		}
		if device.Name == "lo" {
			t.Fatal("loopback must be left out")
		}
		t.Logf("%s (%s): native=%v redirect_target=%v %v", device.Name, device.Type, device.Native, device.RedirectTarget, device.Features)
	}
}
