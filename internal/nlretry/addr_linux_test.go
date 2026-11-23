//go:build linux

package nlretry

import (
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func sameAddrs(t *testing.T, label string, got, want []netlink.Addr) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: per-link dump\n%+v\nlibrary dump\n%+v", label, got, want)
	}
}

func TestAddrListMatchesTheLibraryOnLoopback(t *testing.T) {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	for _, family := range []int{netlink.FAMILY_ALL, netlink.FAMILY_V4, netlink.FAMILY_V6} {
		want, err := netlink.AddrList(lo, family)
		if err != nil {
			t.Fatalf("library dump: %v", err)
		}
		got, err := AddrList(lo, family)
		if err != nil {
			t.Fatalf("AddrList: %v", err)
		}
		sameAddrs(t, "lo", got, want)
	}
	if strictAddrDumpRefused.Load() {
		t.Logf("kernel refused the strict per-link dump; the library dump was used")
	}
}

func TestLinkAddrListOfAMissingLinkIsEmpty(t *testing.T) {
	addrs, err := linkAddrList(1<<30, netlink.FAMILY_ALL)
	if _, refused := err.(errStrictAddrDump); refused {
		t.Skipf("kernel refused the strict dump: %v", err)
	}
	if err != nil || len(addrs) != 0 {
		t.Fatalf("linkAddrList(missing) = %v, %v; want nothing", addrs, err)
	}
}

// The per-link dump must return what the library returns for every address
// shape the parser distinguishes: a plain IPv4 prefix, an IPv4 address with
// a peer, a label, an IPv6 prefix and an IPv6 address with a peer, while the
// addresses of other links stay out.
func TestAddrListMatchesTheLibraryOnEveryAddressShape(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace")
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

	add := func(name string) netlink.Link {
		t.Helper()
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		return link
	}
	addr := func(link netlink.Link, cidr, peer, label string) {
		t.Helper()
		a, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if peer != "" {
			_, p, err := net.ParseCIDR(peer)
			if err != nil {
				t.Fatal(err)
			}
			a.Peer = p
		}
		a.Label = label
		a.Flags = 0x02 // IFA_F_NODAD: no tentative IPv6 addresses
		if err := netlink.AddrAdd(link, a); err != nil {
			t.Fatalf("add %s on %s: %v", cidr, link.Attrs().Name, err)
		}
	}
	first := add("nlrtest0")
	second := add("nlrtest1")
	addr(first, "192.0.2.1/24", "", "nlrtest0:a")
	addr(first, "198.51.100.1/32", "198.51.100.2/32", "")
	addr(first, "2001:db8::1/64", "", "")
	addr(first, "2001:db8:1::1/128", "2001:db8:1::2/128", "")
	addr(second, "203.0.113.1/24", "", "")
	addr(second, "2001:db8:2::1/64", "", "")

	for _, link := range []netlink.Link{first, second} {
		for _, family := range []int{netlink.FAMILY_ALL, netlink.FAMILY_V4, netlink.FAMILY_V6} {
			want, err := netlink.AddrList(link, family)
			if err != nil {
				t.Fatal(err)
			}
			got, err := AddrList(link, family)
			if err != nil {
				t.Fatal(err)
			}
			sameAddrs(t, link.Attrs().Name, got, want)
			for _, a := range got {
				if a.LinkIndex != link.Attrs().Index {
					t.Fatalf("%s got an address of link %d: %+v", link.Attrs().Name, a.LinkIndex, a)
				}
			}
		}
	}
	if strictAddrDumpRefused.Load() {
		t.Fatalf("kernel refused the strict per-link dump")
	}

	byIndex, err := AddrsByLinkIndex(netlink.FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []netlink.Link{first, second} {
		want, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		sameAddrs(t, "grouped "+link.Attrs().Name, byIndex[link.Attrs().Index], want)
	}
}

// benchmarkAddrNamespace runs b in a fresh network namespace with count
// dummy links, each with an IPv4 and an IPv6 address.
func benchmarkAddrNamespace(b *testing.B, count int, run func(b *testing.B, links []netlink.Link)) {
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
	links := make([]netlink.Link, 0, count)
	for i := 0; i < count; i++ {
		name := "bench" + strconv.Itoa(i)
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			b.Fatal(err)
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			b.Fatal(err)
		}
		for _, cidr := range []string{"10.77." + strconv.Itoa(i) + ".1/24", "2001:db8:77:" + strconv.Itoa(i) + "::1/64"} {
			a, _ := netlink.ParseAddr(cidr)
			a.Flags = 0x02 // IFA_F_NODAD
			if err := netlink.AddrAdd(link, a); err != nil {
				b.Fatal(err)
			}
		}
		links = append(links, link)
	}
	b.ResetTimer()
	run(b, links)
}

func BenchmarkAddrListOneLinkStrict(b *testing.B) {
	benchmarkAddrNamespace(b, 60, func(b *testing.B, links []netlink.Link) {
		for i := 0; i < b.N; i++ {
			if _, err := AddrList(links[30], netlink.FAMILY_ALL); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAddrListOneLinkLibrary(b *testing.B) {
	benchmarkAddrNamespace(b, 60, func(b *testing.B, links []netlink.Link) {
		for i := 0; i < b.N; i++ {
			if _, err := netlink.AddrList(links[30], netlink.FAMILY_ALL); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAddrsOfEveryLinkGrouped(b *testing.B) {
	benchmarkAddrNamespace(b, 60, func(b *testing.B, links []netlink.Link) {
		for i := 0; i < b.N; i++ {
			if _, err := AddrsByLinkIndex(netlink.FAMILY_ALL); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAddrsOfEveryLinkOneDumpEach(b *testing.B) {
	benchmarkAddrNamespace(b, 60, func(b *testing.B, links []netlink.Link) {
		for i := 0; i < b.N; i++ {
			for _, link := range links {
				if _, err := netlink.AddrList(link, netlink.FAMILY_ALL); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}
