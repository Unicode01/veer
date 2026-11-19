package app

import (
	"net"
	"strings"
	"testing"
)

func TestUserspaceListenerNeedsInterface(t *testing.T) {
	tcp := ruleProtocolMask("tcp")
	udp := ruleProtocolMask("udp")
	wildcardOnLAN := userspaceListenerFootprint{iface: "vmbr1", ip: "0.0.0.0", startPort: 443, endPort: 443, protocolMask: tcp}
	cases := []struct {
		name   string
		iface  string
		ip     string
		port   int
		mask   int
		others []userspaceListenerFootprint
		want   bool
	}{
		{name: "specific address alone", iface: "vmbr0", ip: "203.0.113.10", port: 443, mask: tcp, want: false},
		{name: "wildcard address", iface: "vmbr0", ip: "0.0.0.0", port: 443, mask: tcp, want: true},
		{name: "no interface", iface: "", ip: "203.0.113.10", port: 443, mask: tcp, want: false},
		{name: "wildcard on another interface, same port", iface: "vmbr0", ip: "203.0.113.10", port: 443, mask: tcp, others: []userspaceListenerFootprint{wildcardOnLAN}, want: true},
		{name: "wildcard on another interface, other port", iface: "vmbr0", ip: "203.0.113.10", port: 8443, mask: tcp, others: []userspaceListenerFootprint{wildcardOnLAN}, want: false},
		{name: "wildcard on another interface, other protocol", iface: "vmbr0", ip: "203.0.113.10", port: 443, mask: udp, others: []userspaceListenerFootprint{wildcardOnLAN}, want: false},
		{name: "same address on another interface", iface: "vmbr0", ip: "203.0.113.10", port: 443, mask: tcp, others: []userspaceListenerFootprint{{iface: "vmbr1", ip: "203.0.113.10", startPort: 400, endPort: 500, protocolMask: tcp}}, want: true},
		{name: "other address on another interface", iface: "vmbr0", ip: "203.0.113.10", port: 443, mask: tcp, others: []userspaceListenerFootprint{{iface: "vmbr1", ip: "198.51.100.1", startPort: 443, endPort: 443, protocolMask: tcp}}, want: false},
		{name: "wildcard on the same interface", iface: "vmbr0", ip: "203.0.113.10", port: 443, mask: tcp, others: []userspaceListenerFootprint{{iface: "vmbr0", ip: "0.0.0.0", startPort: 443, endPort: 443, protocolMask: tcp}}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := userspaceListenerNeedsInterface(tc.iface, tc.ip, tc.port, tc.port, tc.mask, tc.others); got != tc.want {
				t.Fatalf("userspaceListenerNeedsInterface() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A site listening on every address of one interface keeps a rule on the
// same port of another interface bound to its own, and disabled entries do
// not count.
func TestReleaseUserspaceListenInterfaces(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, InInterface: "vmbr0", InIP: "203.0.113.10", InPort: 8080, Protocol: "tcp"},
		{ID: 2, Enabled: true, InInterface: "vmbr0", InIP: "203.0.113.10", InPort: 443, Protocol: "tcp"},
		{ID: 3, Enabled: true, InInterface: "vmbr0", InIP: "0.0.0.0", InPort: 9090, Protocol: "tcp"},
		{ID: 4, Enabled: false, InInterface: "vmbr2", InIP: "0.0.0.0", InPort: 8080, Protocol: "tcp"},
	}
	ranges := []PortRange{
		{ID: 5, Enabled: true, InInterface: "vmbr0", InIP: "203.0.113.10", StartPort: 30000, EndPort: 30010, Protocol: "udp"},
		{ID: 6, Enabled: true, InInterface: "vmbr1", InIP: "0.0.0.0", StartPort: 30005, EndPort: 30005, Protocol: "tcp+udp"},
	}
	sites := []Site{{ID: 7, Enabled: true, Domain: "example.test", ListenIface: "vmbr1", ListenIP: "0.0.0.0", BackendHTTPS: 443}}

	ruleAssignments := [][]Rule{{rules[0], rules[1]}, {rules[2]}}
	rangeAssignments := [][]PortRange{{ranges[0]}}
	releaseUserspaceListenInterfaces(ruleAssignments, rangeAssignments, rules, ranges, sites)

	if got := ruleAssignments[0][0].InInterface; got != "" {
		t.Fatalf("rule 1 interface = %q, want it released", got)
	}
	if got := ruleAssignments[0][1].InInterface; got != "vmbr0" {
		t.Fatalf("rule 2 interface = %q, want vmbr0 kept: the site listens on 443 of vmbr1", got)
	}
	if got := ruleAssignments[1][0].InInterface; got != "vmbr0" {
		t.Fatalf("rule 3 interface = %q, want vmbr0 kept for a wildcard address", got)
	}
	if got := rangeAssignments[0][0].InInterface; got != "vmbr0" {
		t.Fatalf("range 5 interface = %q, want vmbr0 kept: range 6 shares port 30005 on vmbr1", got)
	}
	if rules[0].InInterface != "vmbr0" {
		t.Fatal("releaseUserspaceListenInterfaces() changed the rule it was given instead of the assigned copy")
	}
}

func withUserspaceDialLookups(t *testing.T, routes map[string]string, prefixes map[string][]string) {
	t.Helper()
	oldRoute, oldPrefix, oldCache := userspaceRouteIfaceLookup, userspaceIfacePrefixLookup, userspaceDialLookups
	userspaceRouteIfaceLookup = func(ip net.IP) string { return routes[ip.String()] }
	userspaceIfacePrefixLookup = func(name string) []*net.IPNet {
		var nets []*net.IPNet
		for _, cidr := range prefixes[name] {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("parse %s: %v", cidr, err)
			}
			nets = append(nets, ipNet)
		}
		return nets
	}
	userspaceDialLookups = newUserspaceDialLookupCache()
	t.Cleanup(func() {
		userspaceRouteIfaceLookup, userspaceIfacePrefixLookup, userspaceDialLookups = oldRoute, oldPrefix, oldCache
	})
}

func TestPlanUserspaceTransparentDial(t *testing.T) {
	withUserspaceDialLookups(t,
		map[string]string{"198.18.0.3": "vmbr1", "10.9.0.3": "wg0"},
		map[string][]string{"vmbr1": {"198.18.0.0/24"}, "wg0": {"10.9.0.0/24"}},
	)
	cases := []struct {
		name     string
		client   string
		backend  string
		outIface string
		want     userspaceTransparentDialPlan
	}{
		{name: "outside client, route by the outbound interface", client: "203.0.113.7", backend: "198.18.0.3", outIface: "vmbr1", want: userspaceTransparentDialPlan{transparent: true}},
		{name: "outside client, route by another interface", client: "203.0.113.7", backend: "10.9.0.3", outIface: "vmbr1", want: userspaceTransparentDialPlan{transparent: true, bindIface: "vmbr1"}},
		{name: "client in the backend's network", client: "198.18.0.2", backend: "198.18.0.3", outIface: "vmbr1", want: userspaceTransparentDialPlan{transparent: false, bindIface: "vmbr1"}},
		{name: "client in the backend's network, no outbound interface", client: "198.18.0.2", backend: "198.18.0.3", outIface: "", want: userspaceTransparentDialPlan{transparent: false}},
		{name: "outside client, no outbound interface", client: "203.0.113.7", backend: "198.18.0.3", outIface: "", want: userspaceTransparentDialPlan{transparent: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planUserspaceTransparentDial(net.ParseIP(tc.client).To4(), net.ParseIP(tc.backend).To4(), tc.outIface)
			if got != tc.want {
				t.Fatalf("planUserspaceTransparentDial() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestConfigureTransparentTCPDialerDialsSameNetworkClientsFromTheHost(t *testing.T) {
	withUserspaceDialLookups(t, map[string]string{"198.18.0.3": "vmbr1"}, map[string][]string{"vmbr1": {"198.18.0.0/24"}})

	var dialer net.Dialer
	network, err := configureTransparentTCPDialer(&dialer, net.ParseIP("198.18.0.2"), "198.18.0.3:22", "vmbr1")
	if err != nil {
		t.Fatalf("configureTransparentTCPDialer() error = %v", err)
	}
	if network != "tcp" || dialer.LocalAddr != nil {
		t.Fatalf("same-network client: network %q local %v, want tcp from the host's own address", network, dialer.LocalAddr)
	}

	dialer = net.Dialer{}
	network, err = configureTransparentTCPDialer(&dialer, net.ParseIP("203.0.113.7"), "198.18.0.3:22", "vmbr1")
	if err != nil {
		t.Fatalf("configureTransparentTCPDialer() error = %v", err)
	}
	local, _ := dialer.LocalAddr.(*net.TCPAddr)
	if network != "tcp4" || local == nil || !local.IP.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("outside client: network %q local %v, want tcp4 from the client's address", network, dialer.LocalAddr)
	}
}

type staticKernelRuleDataplane struct{}

func (staticKernelRuleDataplane) Name() string                     { return ruleEngineKernel }
func (staticKernelRuleDataplane) Available() (bool, string)        { return true, "" }
func (staticKernelRuleDataplane) SupportsRule(Rule) (bool, string) { return true, "" }

func TestPlannerKeepsLocalBackendsOutOfTheKernel(t *testing.T) {
	planner := &ruleDataplanePlanner{
		userspace:       userspaceRuleDataplane{},
		kernel:          staticKernelRuleDataplane{},
		defaultEngine:   ruleEngineKernel,
		kernelAvailable: true,
		hostAddrs:       hostInterfaceAddrs{"vmbr1": {"198.18.0.1": {}}, "lo": {"127.0.0.1": {}}},
	}
	for _, backend := range []string{"127.0.0.1", "127.0.0.53", "198.18.0.1", "::1"} {
		plan := planner.Plan(Rule{ID: 1, InIP: "203.0.113.10", InPort: 80, OutIP: backend, OutPort: 8080, Protocol: "tcp", EnginePreference: ruleEngineKernel})
		if plan.EffectiveEngine != ruleEngineUserspace || plan.FallbackReason != kernelLocalBackendFallbackReason {
			if backend == "::1" && strings.Contains(plan.FallbackReason, "mixed IPv4/IPv6") {
				continue
			}
			t.Fatalf("backend %s: plan = %+v, want user space for a local backend", backend, plan)
		}
	}
	plan := planner.Plan(Rule{ID: 2, InIP: "203.0.113.10", InPort: 80, OutIP: "198.18.0.3", OutPort: 8080, Protocol: "tcp", EnginePreference: ruleEngineKernel})
	if plan.EffectiveEngine != ruleEngineKernel {
		t.Fatalf("guest backend: plan = %+v, want kernel", plan)
	}
}

func TestValidationRejectsTransparentForwardsToThisHost(t *testing.T) {
	hostAddrs := hostInterfaceAddrs{"vmbr1": {"198.18.0.1": {}}}
	ifaces := map[string]struct{}{"vmbr0": {}, "vmbr1": {}}
	for _, backend := range []string{"127.0.0.1", "198.18.0.1"} {
		rule := Rule{InIP: "203.0.113.10", InPort: 80, OutIP: backend, OutPort: 8080, Protocol: "tcp", Transparent: true}
		_, issues := normalizeAndValidateRule(rule, "create", 0, false, ifaces, hostAddrs)
		if !ruleIssuesMention(issues, "out_ip", transparentLocalBackendMessage) {
			t.Fatalf("transparent rule to %s: issues = %+v, want out_ip rejected", backend, issues)
		}
		rule.Transparent = false
		if _, issues := normalizeAndValidateRule(rule, "create", 0, false, ifaces, hostAddrs); ruleIssuesMention(issues, "out_ip", transparentLocalBackendMessage) {
			t.Fatalf("full NAT rule to %s rejected: %+v", backend, issues)
		}

		pr := PortRange{InIP: "203.0.113.10", StartPort: 80, EndPort: 81, OutIP: backend, Protocol: "tcp", Transparent: true}
		if _, msg := normalizeAndValidateRange(pr, false, ifaces, hostAddrs); !strings.Contains(msg, transparentLocalBackendMessage) {
			t.Fatalf("transparent range to %s: %q, want it rejected", backend, msg)
		}
		site := Site{Domain: "example.test", BackendIP: backend, BackendHTTP: 80, Transparent: true}
		if _, msg := normalizeAndValidateSite(site, false, ifaces, hostAddrs); !strings.Contains(msg, transparentLocalBackendMessage) {
			t.Fatalf("transparent site to %s: %q, want it rejected", backend, msg)
		}
	}
	rule := Rule{InIP: "203.0.113.10", InPort: 80, OutIP: "198.18.0.3", OutPort: 8080, Protocol: "tcp", Transparent: true}
	if _, issues := normalizeAndValidateRule(rule, "create", 0, false, ifaces, hostAddrs); len(issues) != 0 {
		t.Fatalf("transparent rule to a guest: issues = %+v, want none", issues)
	}
}

func ruleIssuesMention(issues []ruleValidationIssue, field string, message string) bool {
	for _, issue := range issues {
		if issue.Field == field && strings.Contains(issue.Message, message) {
			return true
		}
	}
	return false
}
