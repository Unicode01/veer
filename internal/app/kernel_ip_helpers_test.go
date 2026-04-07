package app

import (
	"net"
	"strings"
	"testing"
)

func TestParseKernelExplicitIPAllowsIPv6(t *testing.T) {
	ip, err := parseKernelExplicitIP("2001:db8::10", ipFamilyIPv6)
	if err != nil {
		t.Fatalf("parseKernelExplicitIP() error = %v", err)
	}
	if got := canonicalIPLiteral(ip); got != "2001:db8::10" {
		t.Fatalf("canonicalIPLiteral() = %q, want %q", got, "2001:db8::10")
	}
}

func TestParseKernelExplicitIPRejectsWildcardIPv6(t *testing.T) {
	_, err := parseKernelExplicitIP("::", ipFamilyIPv6)
	if err == nil {
		t.Fatal("parseKernelExplicitIP() error = nil, want wildcard rejection")
	}
	if err.Error() != "must be an explicit IPv6 address" {
		t.Fatalf("parseKernelExplicitIP() error = %q, want %q", err.Error(), "must be an explicit IPv6 address")
	}
}

func TestParseKernelInboundIPAllowsWildcardIPv6(t *testing.T) {
	ip, wildcard, err := parseKernelInboundIP("::", ipFamilyIPv6)
	if err != nil {
		t.Fatalf("parseKernelInboundIP() error = %v", err)
	}
	if !wildcard {
		t.Fatal("parseKernelInboundIP() wildcard = false, want true")
	}
	if !ip.Equal(net.IPv6zero) {
		t.Fatalf("parseKernelInboundIP() ip = %v, want %v", ip, net.IPv6zero)
	}
}

func TestSplitKernelUsableSourceIPsSeparatesIPv6LinkLocal(t *testing.T) {
	usable, linkLocal := splitKernelUsableSourceIPs([]net.IP{
		net.ParseIP("2001:db8::10"),
		net.ParseIP("fe80::1"),
		net.ParseIP("fe80::1"),
		net.IPv6loopback,
		net.ParseIP("192.0.2.10"),
		nil,
	}, ipFamilyIPv6)

	if len(usable) != 1 {
		t.Fatalf("len(usable) = %d, want 1", len(usable))
	}
	if got := canonicalIPLiteral(usable[0]); got != "2001:db8::10" {
		t.Fatalf("usable[0] = %q, want %q", got, "2001:db8::10")
	}
	if len(linkLocal) != 1 {
		t.Fatalf("len(linkLocal) = %d, want 1", len(linkLocal))
	}
	if got := canonicalIPLiteral(linkLocal[0]); got != "fe80::1" {
		t.Fatalf("linkLocal[0] = %q, want %q", got, "fe80::1")
	}
}

func TestSelectKernelAutoSourceIPIPv6(t *testing.T) {
	selected, err := selectKernelAutoSourceIP("eno1", ipFamilyIPv6, []net.IP{net.ParseIP("2001:db8::10")}, nil)
	if err != nil {
		t.Fatalf("selectKernelAutoSourceIP() error = %v", err)
	}
	if got := canonicalIPLiteral(selected); got != "2001:db8::10" {
		t.Fatalf("selected = %q, want %q", got, "2001:db8::10")
	}

	selected, err = selectKernelAutoSourceIP("eno1", ipFamilyIPv6, nil, []net.IP{net.ParseIP("fe80::1")})
	if err != nil {
		t.Fatalf("selectKernelAutoSourceIP() link-local error = %v", err)
	}
	if got := canonicalIPLiteral(selected); got != "fe80::1" {
		t.Fatalf("selected link-local = %q, want %q", got, "fe80::1")
	}

	_, err = selectKernelAutoSourceIP("eno1", ipFamilyIPv6, []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::11")}, nil)
	if err == nil {
		t.Fatal("selectKernelAutoSourceIP() error = nil, want ambiguous usable IPv6 rejection")
	}
	if !strings.Contains(err.Error(), "ambiguous (2 IPv6 addresses assigned)") {
		t.Fatalf("selectKernelAutoSourceIP() error = %q, want usable IPv6 ambiguity", err.Error())
	}

	_, err = selectKernelAutoSourceIP("eno1", ipFamilyIPv6, nil, []net.IP{net.ParseIP("fe80::1"), net.ParseIP("fe80::2")})
	if err == nil {
		t.Fatal("selectKernelAutoSourceIP() error = nil, want ambiguous link-local IPv6 rejection")
	}
	if !strings.Contains(err.Error(), "ambiguous (2 link-local IPv6 addresses assigned)") {
		t.Fatalf("selectKernelAutoSourceIP() error = %q, want link-local IPv6 ambiguity", err.Error())
	}
}
