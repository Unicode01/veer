//go:build linux

package app

import (
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/vishvananda/netlink"
)

// The generic-mode offload guard turns offloads off on a veth and its peer.
// A peer in another namespace has an index that counts there; looked up in
// this namespace, it named an unrelated interface (on the test machine, the
// uplink) and that interface lost its offloads.
func TestXDPGenericOffloadTargetsFindPeerInItsNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for network namespaces")
	}
	suffix := strconv.Itoa(os.Getpid() % 100000)
	ns := "xofft" + suffix
	host := truncateIfName("xoffh" + suffix)
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run("ip", "link", "add", host, "type", "veth", "peer", "name", "c0", "netns", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", host).Run() })

	link, err := netlink.LinkByName(host)
	if err != nil {
		t.Fatal(err)
	}
	peerIndex, err := netlink.VethPeerIndex(&netlink.Veth{LinkAttrs: *link.Attrs()})
	if err != nil {
		t.Fatal(err)
	}
	if other, err := netlink.LinkByIndex(peerIndex); err == nil && other != nil {
		t.Logf("index %d of the peer names %s in this namespace", peerIndex, other.Attrs().Name)
	}
	targets, err := xdpGenericOffloadTargets(link)
	if err != nil {
		t.Fatalf("xdpGenericOffloadTargets() error = %v", err)
	}
	want := []xdpGenericOffloadTarget{{ifName: host}, {namespace: ns, ifName: "c0"}}
	if len(targets) != len(want) {
		t.Fatalf("targets = %+v, want %+v", targets, want)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("targets = %+v, want %+v", targets, want)
		}
	}
}
