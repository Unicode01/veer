package netutil

import (
	"net"
	"testing"
)

func mustIPv6PrefixForTest(t *testing.T, text string) *net.IPNet {
	t.Helper()
	_, prefix, err := NormalizeIPv6Prefix(text)
	if err != nil {
		t.Fatalf("NormalizeIPv6Prefix(%q) error = %v", text, err)
	}
	return prefix
}

func TestNormalizeIPv6Prefix(t *testing.T) {
	text, prefix, err := NormalizeIPv6Prefix(" 2001:db8:1::1234/64 ")
	if err != nil {
		t.Fatalf("NormalizeIPv6Prefix() error = %v", err)
	}
	if text != "2001:db8:1::/64" || prefix.String() != text {
		t.Fatalf("NormalizeIPv6Prefix() = %q, %v", text, prefix)
	}
	if _, _, err := NormalizeIPv6Prefix("192.0.2.0/24"); err == nil {
		t.Fatal("NormalizeIPv6Prefix() accepted IPv4")
	}
}

func TestIPv6PrefixRelations(t *testing.T) {
	parent := mustIPv6PrefixForTest(t, "2001:db8:1::/48")
	child := mustIPv6PrefixForTest(t, "2001:db8:1:42::/64")
	outside := mustIPv6PrefixForTest(t, "2001:db9::/48")
	if !IPv6PrefixContains(parent, child) {
		t.Fatal("IPv6PrefixContains() rejected child")
	}
	if IPv6PrefixContains(child, parent) {
		t.Fatal("IPv6PrefixContains() accepted shorter child")
	}
	if !IPv6PrefixesOverlap(parent, child) || IPv6PrefixesOverlap(parent, outside) {
		t.Fatal("IPv6PrefixesOverlap() returned unexpected result")
	}
}

func TestRebaseIPv6PrefixWithinParent(t *testing.T) {
	stored := mustIPv6PrefixForTest(t, "2001:db8:1000::/48")
	current := mustIPv6PrefixForTest(t, "2001:db8:2000::/48")
	assigned := mustIPv6PrefixForTest(t, "2001:db8:1000:42::/64")
	rebased, err := RebaseIPv6PrefixWithinParent(stored, current, assigned)
	if err != nil {
		t.Fatalf("RebaseIPv6PrefixWithinParent() error = %v", err)
	}
	if got, want := rebased.String(), "2001:db8:2000:42::/64"; got != want {
		t.Fatalf("RebaseIPv6PrefixWithinParent() = %q, want %q", got, want)
	}
}
