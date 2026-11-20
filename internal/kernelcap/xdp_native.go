package kernelcap

import "sort"

// XDPNativeDevice is what one device's driver reports about running XDP
// programs itself (driver mode). Every device can run XDP in generic mode,
// on the skb path.
type XDPNativeDevice struct {
	Name  string `json:"name"`
	Index int    `json:"ifindex"`
	Type  string `json:"type,omitempty"`
	// Native: the driver runs XDP programs (NETDEV_XDP_ACT_BASIC).
	Native bool `json:"native"`
	// RedirectTarget: XDP programs on other devices can redirect frames out
	// of this one (NETDEV_XDP_ACT_NDO_XMIT). Some drivers, Intel's igb,
	// ixgbe and i40e among them, report it only while an XDP program is
	// attached to the device.
	RedirectTarget bool `json:"redirect_target"`
	// Features names every flag the driver reports, as the kernel's netdev
	// netlink spec names them.
	Features []string `json:"features,omitempty"`
}

// XDPNativeReport lists what each device's driver reports. Available is
// false when the kernel has no per-device XDP feature report (it came with
// Linux 6.3); an XDP runtime then learns a device's mode only by attaching.
type XDPNativeReport struct {
	Available bool              `json:"available"`
	Reason    string            `json:"reason,omitempty"`
	Devices   []XDPNativeDevice `json:"devices,omitempty"`
}

// The netdev_xdp_act bits of include/uapi/linux/netdev.h, in bit order.
var xdpNativeFeatureNames = [...]string{
	"basic",
	"redirect",
	"ndo-xmit",
	"xsk-zerocopy",
	"hw-offload",
	"rx-sg",
	"ndo-xmit-sg",
}

const (
	xdpFeatureBasic   = 1 << 0
	xdpFeatureNDOXmit = 1 << 2
)

func xdpNativeDeviceFromFeatures(name string, index int, kind string, features uint64) XDPNativeDevice {
	device := XDPNativeDevice{
		Name:           name,
		Index:          index,
		Type:           kind,
		Native:         features&xdpFeatureBasic != 0,
		RedirectTarget: features&xdpFeatureNDOXmit != 0,
	}
	for bit, feature := range xdpNativeFeatureNames {
		if features&(1<<bit) != 0 {
			device.Features = append(device.Features, feature)
		}
	}
	return device
}

// sortXDPNativeDevices puts physical devices first, since those are the
// ones a reader looks for among bridges, taps and veths, then sorts by name.
func sortXDPNativeDevices(devices []XDPNativeDevice) {
	sort.Slice(devices, func(i, j int) bool {
		iPhysical, jPhysical := devices[i].Type == "device", devices[j].Type == "device"
		if iPhysical != jPhysical {
			return iPhysical
		}
		return devices[i].Name < devices[j].Name
	})
}
