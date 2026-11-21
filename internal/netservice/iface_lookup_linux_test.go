//go:build linux

package netservice

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// The ioctl lookup returns what net.InterfaceByName returns for every
// interface the namespace has: the index, and the ethernet address or nil.
func TestInterfaceByNameMatchesTheStandardLibrary(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range ifaces {
		got, err := interfaceByName(want.Name)
		if err != nil {
			t.Fatalf("%s: %v", want.Name, err)
		}
		if got.Index != want.Index || got.Name != want.Name {
			t.Fatalf("%s: got index %d name %q, want %d %q", want.Name, got.Index, got.Name, want.Index, want.Name)
		}
		if len(want.HardwareAddr) > 6 {
			continue // not ethernet; the servers never look these up
		}
		if !bytes.Equal(got.HardwareAddr, want.HardwareAddr) {
			t.Fatalf("%s: got address %v, want %v", want.Name, got.HardwareAddr, want.HardwareAddr)
		}
	}
	if _, err := interfaceByName("veer-no-such0"); err == nil {
		t.Fatal("a missing interface was found")
	}
}

// benchmarkInNamespaceWithLinks runs b in a fresh network namespace that
// holds count dummy links, about what a host with guest taps has.
func benchmarkInNamespaceWithLinks(b *testing.B, count int, run func(b *testing.B)) {
	if os.Geteuid() != 0 {
		b.Skip("needs root for a network namespace")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origin, err := netns.Get()
	if err != nil {
		b.Fatal(err)
	}
	defer origin.Close()
	ns, err := netns.New()
	if err != nil {
		b.Skipf("cannot create a network namespace: %v", err)
	}
	defer func() {
		_ = netns.Set(origin)
		ns.Close()
	}()
	for i := 0; i < count; i++ {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("bench%d", i)}}); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	run(b)
}

func BenchmarkInterfaceLookupIoctl(b *testing.B) {
	benchmarkInNamespaceWithLinks(b, 60, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := interfaceByName("bench30"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkInterfaceLookupStandardLibrary(b *testing.B) {
	benchmarkInNamespaceWithLinks(b, 60, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := net.InterfaceByName("bench30"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
