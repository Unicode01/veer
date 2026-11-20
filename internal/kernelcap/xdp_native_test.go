package kernelcap

import (
	"reflect"
	"testing"
)

func TestXDPNativeDeviceFromFeaturesNamesEveryFlag(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features uint64
		want     XDPNativeDevice
	}{
		{
			// igb without an XDP program: it reports ndo-xmit only once one
			// is attached.
			name:     "igb",
			features: 0xb,
			want: XDPNativeDevice{Name: "igb", Index: 2, Type: "device", Native: true,
				Features: []string{"basic", "redirect", "xsk-zerocopy"}},
		},
		{
			name:     "tun",
			features: 0x7,
			want: XDPNativeDevice{Name: "tun", Index: 2, Type: "device", Native: true, RedirectTarget: true,
				Features: []string{"basic", "redirect", "ndo-xmit"}},
		},
		{
			name: "bridge",
			want: XDPNativeDevice{Name: "bridge", Index: 2, Type: "device"},
		},
		{
			// Bits the kernel may add later are left out.
			name:     "future",
			features: 1<<6 | 1<<40,
			want:     XDPNativeDevice{Name: "future", Index: 2, Type: "device", Features: []string{"ndo-xmit-sg"}},
		},
	} {
		got := xdpNativeDeviceFromFeatures(tc.name, 2, "device", tc.features)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestSortXDPNativeDevicesPutsPhysicalDevicesFirst(t *testing.T) {
	devices := []XDPNativeDevice{
		{Name: "vmbr0", Type: "bridge"},
		{Name: "enp6s0f1", Type: "device"},
		{Name: "fwpr100p0", Type: "veth"},
		{Name: "enp6s0f0", Type: "device"},
		{Name: "tap100i0", Type: "tuntap"},
	}
	sortXDPNativeDevices(devices)
	var got []string
	for _, device := range devices {
		got = append(got, device.Name)
	}
	want := []string{"enp6s0f0", "enp6s0f1", "fwpr100p0", "tap100i0", "vmbr0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
