package managednet

import (
	"net"
	"testing"

	"github.com/Unicode01/veer/internal/netutil"
)

func mustAllocatorPrefix(t *testing.T, text string) *net.IPNet {
	t.Helper()
	_, prefix, err := netutil.NormalizeIPv6Prefix(text)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func TestAllocateSingleIPv6PreservesParentBits(t *testing.T) {
	parent := mustAllocatorPrefix(t, "2001:db8:100:200::/80")
	text, prefix, err := AllocateSingleIPv6(parent, 0x1122334455667788)
	if err != nil {
		t.Fatal(err)
	}
	if want := "2001:db8:100:200:0:3344:5566:7788/128"; text != want || prefix.String() != want {
		t.Fatalf("AllocateSingleIPv6() = %q, %v, want %q", text, prefix, want)
	}
}

func TestIPv6PrefixIndexTracksBroaderAndNarrowerPrefixes(t *testing.T) {
	broader := mustAllocatorPrefix(t, "2001:db8:100::/56")
	exact := mustAllocatorPrefix(t, "2001:db8:100:1::/64")
	narrower := mustAllocatorPrefix(t, "2001:db8:100:2::1/128")
	other := mustAllocatorPrefix(t, "2001:db8:101:1::/64")
	used := []*net.IPNet{broader, exact, narrower}
	index := NewIPv6PrefixIndex(IPv6AssignmentModePrefix64, used)
	if !index.Overlaps(exact, used) || !index.Overlaps(mustAllocatorPrefix(t, "2001:db8:100:2::/64"), used) {
		t.Fatal("IPv6PrefixIndex did not detect exact or narrower overlap")
	}
	if index.Overlaps(other, used) {
		t.Fatal("IPv6PrefixIndex reported unrelated overlap")
	}
}
