//go:build linux

package app

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func ethtoolOffloads(t *testing.T, name string) (map[string]bool, error) {
	t.Helper()
	out, err := exec.Command("ethtool", "-k", name).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ethtool -k %s: %v: %s", name, err, out)
	}
	return parsePluginControlOffloadFeatures(string(out)), nil
}

func hasPluginOffload(features map[string]bool, name string) bool {
	_, ok := features[name]
	return ok
}

func ioctlOffloads(name string) (map[string]bool, error) {
	dev, err := openPluginOffloadDevice(name)
	if err != nil {
		return nil, err
	}
	defer dev.Close()
	return dev.read()
}

// Every link the namespace has reads the same through the ioctls as through
// `ethtool -k`, whatever its driver.
func TestPluginOffloadReadMatchesEthtool(t *testing.T) {
	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Skip("ethtool not installed")
	}
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	compared := 0
	for _, link := range links {
		name := link.Attrs().Name
		want, err := ethtoolOffloads(t, name)
		if err != nil {
			t.Logf("%s: %v", name, err)
			continue
		}
		got, err := ioctlOffloads(name)
		if err != nil {
			t.Fatalf("%s (%s): ioctl read: %v", name, link.Type(), err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s (%s): ioctl %v, ethtool %v", name, link.Type(), got, want)
		}
		compared++
	}
	if compared == 0 {
		t.Skip("no link ethtool could read")
	}
}

// Setting through the ioctls ends in the same device state, and fails in the
// same cases, as `ethtool -K` given the same requests.
func TestPluginOffloadSetMatchesEthtool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace")
	}
	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Skip("ethtool not installed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origin, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	ns, err := netns.New()
	if err != nil {
		t.Skipf("cannot create a network namespace: %v", err)
	}
	defer func() {
		_ = netns.Set(origin)
		ns.Close()
	}()
	// Children forked from this locked thread start in the new namespace.
	for _, pair := range [][2]string{{"offa0", "offa1"}, {"offb0", "offb1"}} {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: pair[0]}, PeerName: pair[1]}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"offd0", "offd1"} {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}

	requests := []map[string]bool{
		{"gro": false},
		{"gro": true},
		{"tso": false, "gso": false},
		{"tx": false},
		{"tx": true, "sg": true, "tso": true, "gso": true},
		{"rx": false},
		{"rx": true},
		{"lro": true},
		{"ufo": true},
		{"ufo": false},
		{"tx": false, "tso": false, "gso": false, "gro": false, "sg": false},
		{"tx": true, "sg": true, "tso": true, "gso": true, "gro": true},
	}
	for _, devices := range [][2]string{{"offa0", "offb0"}, {"offd0", "offd1"}} {
		ioctlDev, ethtoolDev := devices[0], devices[1]
		for i, req := range requests {
			ioctlErr := (linuxPluginControlNetAdmin{}).LinkSetOffloads(pluginControlNetOffloadRequest{Interface: ioctlDev, Features: req})
			args := []string{"-K", ethtoolDev}
			names := make([]string, 0, len(req))
			for name := range req {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				state := "off"
				if req[name] {
					state = "on"
				}
				args = append(args, name, state)
			}
			out, ethtoolErr := exec.Command("ethtool", args...).CombinedOutput()
			got, err := ioctlOffloads(ioctlDev)
			if err != nil {
				t.Fatal(err)
			}
			want, err := ethtoolOffloads(t, ethtoolDev)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("request %d %v on %s: ioctl state %v, ethtool state %v", i, req, ioctlDev, got, want)
			}
			if value, asked := req["ufo"]; asked && !value && len(req) == 1 && !hasPluginOffload(got, "ufo") {
				// No UFO in this kernel: off already holds. ethtool -K
				// reports that it could not change anything.
				if ioctlErr != nil {
					t.Errorf("request %d %v on %s: %v; want success, UFO is absent", i, req, ioctlDev, ioctlErr)
				}
				continue
			}
			if (ioctlErr != nil) != (ethtoolErr != nil) {
				t.Errorf("request %d %v on %s: ioctl error %v, ethtool error %v (%s)", i, req, ioctlDev, ioctlErr, ethtoolErr, out)
			}
		}
	}
}
