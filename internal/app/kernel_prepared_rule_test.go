//go:build linux

package app

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func kernelPreparedAddrString(addr kernelPreparedAddr, family string) string {
	if addr.isZero() {
		if family == ipFamilyIPv6 {
			return net.IPv6zero.String()
		}
		return net.IPv4zero.String()
	}
	if family == ipFamilyIPv6 {
		return net.IP(addr[:]).String()
	}
	return net.IPv4(addr[12], addr[13], addr[14], addr[15]).String()
}

func TestBuildKernelPreparedForwardRuleSpecIPv4(t *testing.T) {
	rule := Rule{
		InIP:        "198.51.100.10",
		OutIP:       "192.0.2.20",
		OutSourceIP: "203.0.113.30",
		Transparent: false,
	}

	spec, err := buildKernelPreparedForwardRuleSpec(rule, func(family string) (net.IP, error) {
		if family != ipFamilyIPv4 {
			t.Fatalf("family = %q, want %q", family, ipFamilyIPv4)
		}
		return net.ParseIP("203.0.113.30"), nil
	})
	if err != nil {
		t.Fatalf("buildKernelPreparedForwardRuleSpec() error = %v", err)
	}
	if spec.Family != ipFamilyIPv4 {
		t.Fatalf("Family = %q, want %q", spec.Family, ipFamilyIPv4)
	}
	if got := kernelPreparedAddrString(spec.DstAddr, spec.Family); got != "198.51.100.10" {
		t.Fatalf("DstAddr = %q, want %q", got, "198.51.100.10")
	}
	if got := kernelPreparedAddrString(spec.BackendAddr, spec.Family); got != "192.0.2.20" {
		t.Fatalf("BackendAddr = %q, want %q", got, "192.0.2.20")
	}
	if got := kernelPreparedAddrString(spec.NATAddr, spec.Family); got != "203.0.113.30" {
		t.Fatalf("NATAddr = %q, want %q", got, "203.0.113.30")
	}
}

func TestBuildKernelPreparedForwardRuleSpecIPv6(t *testing.T) {
	rule := Rule{
		InIP:        "2001:db8::10",
		OutIP:       "2001:db8::20",
		OutSourceIP: "2001:db8::30",
		Transparent: false,
	}

	spec, err := buildKernelPreparedForwardRuleSpec(rule, func(family string) (net.IP, error) {
		if family != ipFamilyIPv6 {
			t.Fatalf("family = %q, want %q", family, ipFamilyIPv6)
		}
		return net.ParseIP("2001:db8::30"), nil
	})
	if err != nil {
		t.Fatalf("buildKernelPreparedForwardRuleSpec() error = %v", err)
	}
	if spec.Family != ipFamilyIPv6 {
		t.Fatalf("Family = %q, want %q", spec.Family, ipFamilyIPv6)
	}
	if got := kernelPreparedAddrString(spec.DstAddr, spec.Family); got != "2001:db8::10" {
		t.Fatalf("DstAddr = %q, want %q", got, "2001:db8::10")
	}
	if got := kernelPreparedAddrString(spec.BackendAddr, spec.Family); got != "2001:db8::20" {
		t.Fatalf("BackendAddr = %q, want %q", got, "2001:db8::20")
	}
	if got := kernelPreparedAddrString(spec.NATAddr, spec.Family); got != "2001:db8::30" {
		t.Fatalf("NATAddr = %q, want %q", got, "2001:db8::30")
	}
}

func TestBuildKernelPreparedForwardRuleSpecRejectsMixedFamily(t *testing.T) {
	_, err := buildKernelPreparedForwardRuleSpec(Rule{
		InIP:        "2001:db8::10",
		OutIP:       "192.0.2.20",
		Transparent: false,
	}, func(family string) (net.IP, error) {
		return net.ParseIP("192.0.2.30"), nil
	})
	if err == nil {
		t.Fatal("buildKernelPreparedForwardRuleSpec() error = nil, want mixed-family rejection")
	}
	if err.Error() != "kernel dataplane does not support mixed IPv4/IPv6 forwarding" {
		t.Fatalf("buildKernelPreparedForwardRuleSpec() error = %q, want mixed-family rejection", err.Error())
	}
}

func TestBuildKernelPreparedForwardRuleSpecRejectsTransparentIPv6(t *testing.T) {
	_, err := buildKernelPreparedForwardRuleSpec(Rule{
		InIP:        "2001:db8::10",
		OutIP:       "2001:db8::20",
		Transparent: true,
	}, nil)
	if err == nil {
		t.Fatal("buildKernelPreparedForwardRuleSpec() error = nil, want transparent IPv6 rejection")
	}
	if err.Error() != "kernel dataplane currently does not support transparent IPv6 rules" {
		t.Fatalf("buildKernelPreparedForwardRuleSpec() error = %q, want transparent IPv6 rejection", err.Error())
	}
}

func TestPrepareKernelRuleAllowsIPv6FullNAT(t *testing.T) {
	ctx := newKernelPrepareContext(false)
	ctx.links["eno1"] = cachedKernelLink{
		link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eno1", Index: 1}},
	}
	ctx.links["eno2"] = cachedKernelLink{
		link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eno2", Index: 2}},
	}
	ctx.snatIPs["v6|2|2001:db8::20|2001:db8::30"] = cachedKernelSNATIP{
		addr: net.ParseIP("2001:db8::30"),
	}

	items, err := prepareKernelRule(ctx, Rule{
		ID:           1,
		InInterface:  "eno1",
		InIP:         "2001:db8::10",
		InPort:       443,
		OutInterface: "eno2",
		OutIP:        "2001:db8::20",
		OutPort:      8443,
		OutSourceIP:  "2001:db8::30",
		Protocol:     "tcp",
	})
	if err != nil {
		t.Fatalf("prepareKernelRule() error = %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("prepareKernelRule() items = %d, want 1", len(items))
	}
	if got := kernelPreparedRuleFamily(items[0]); got != ipFamilyIPv6 {
		t.Fatalf("kernelPreparedRuleFamily() = %q, want %q", got, ipFamilyIPv6)
	}
	if got := kernelPreparedAddrString(items[0].spec.NATAddr, ipFamilyIPv6); got != "2001:db8::30" {
		t.Fatalf("prepared NATAddr = %q, want %q", got, "2001:db8::30")
	}
}
