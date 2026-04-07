package app

import (
	"net"
	"testing"
)

func TestNormalizeAndValidateRuleAllowsUserspaceIPv6TCP(t *testing.T) {
	tests := []struct {
		name  string
		inIP  string
		outIP string
	}{
		{name: "v4-to-v6", inIP: "0.0.0.0", outIP: "2001:db8::10"},
		{name: "v6-to-v4", inIP: "::", outIP: "192.0.2.10"},
		{name: "v6-to-v6", inIP: "2001:db8::1", outIP: "2001:db8::10"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule, issues := normalizeAndValidateRule(Rule{
				InIP:     tc.inIP,
				InPort:   8080,
				OutIP:    tc.outIP,
				OutPort:  80,
				Protocol: "tcp",
			}, "create", 1, false, map[string]struct{}{}, hostInterfaceAddrs{})
			if len(issues) != 0 {
				t.Fatalf("normalizeAndValidateRule() issues = %#v, want none", issues)
			}
			if rule.InIP != tc.inIP && !(tc.inIP == "::" && rule.InIP == "::") {
				t.Fatalf("InIP = %q, want canonical %q", rule.InIP, tc.inIP)
			}
			if rule.OutIP != tc.outIP {
				t.Fatalf("OutIP = %q, want canonical %q", rule.OutIP, tc.outIP)
			}
		})
	}
}

func TestNormalizeAndValidateRuleRejectsTransparentIPv6(t *testing.T) {
	_, issues := normalizeAndValidateRule(Rule{
		InIP:        "::",
		InPort:      8080,
		OutIP:       "2001:db8::20",
		OutPort:     80,
		Protocol:    "tcp",
		Transparent: true,
	}, "create", 1, false, map[string]struct{}{}, hostInterfaceAddrs{})
	if !hasValidationMessage(issues, "transparent mode currently supports only IPv4 rules") {
		t.Fatalf("normalizeAndValidateRule() issues = %#v, want transparent IPv6 rejection", issues)
	}
}

func TestNormalizeAndValidateRuleAllowsIPv6UDP(t *testing.T) {
	rule, issues := normalizeAndValidateRule(Rule{
		InIP:     "::",
		InPort:   5353,
		OutIP:    "2001:db8::20",
		OutPort:  5353,
		Protocol: "udp",
	}, "create", 1, false, map[string]struct{}{}, hostInterfaceAddrs{})
	if len(issues) != 0 {
		t.Fatalf("normalizeAndValidateRule() issues = %#v, want none", issues)
	}
	if rule.InIP != "::" || rule.OutIP != "2001:db8::20" {
		t.Fatalf("normalizeAndValidateRule() canonical IPs = (%q, %q), want (::, 2001:db8::20)", rule.InIP, rule.OutIP)
	}
}

func TestNormalizeAndValidateRulePreservesEnginePreference(t *testing.T) {
	rule, issues := normalizeAndValidateRule(Rule{
		InIP:             "0.0.0.0",
		InPort:           8080,
		OutIP:            "192.0.2.10",
		OutPort:          80,
		Protocol:         "tcp",
		EnginePreference: ruleEngineUserspace,
	}, "create", 1, false, map[string]struct{}{}, hostInterfaceAddrs{})
	if len(issues) != 0 {
		t.Fatalf("normalizeAndValidateRule() issues = %#v, want none", issues)
	}
	if rule.EnginePreference != ruleEngineUserspace {
		t.Fatalf("EnginePreference = %q, want %q", rule.EnginePreference, ruleEngineUserspace)
	}
}

func TestNormalizeAndValidateRuleRejectsInvalidEnginePreference(t *testing.T) {
	_, issues := normalizeAndValidateRule(Rule{
		InIP:             "0.0.0.0",
		InPort:           8080,
		OutIP:            "192.0.2.10",
		OutPort:          80,
		Protocol:         "tcp",
		EnginePreference: "invalid",
	}, "create", 1, false, map[string]struct{}{}, hostInterfaceAddrs{})
	if !hasValidationMessage(issues, "must be auto, userspace, or kernel") {
		t.Fatalf("normalizeAndValidateRule() issues = %#v, want engine_preference rejection", issues)
	}
}

func TestNormalizeAndValidateSiteAllowsIPv6ListenAndBackend(t *testing.T) {
	site, errText := normalizeAndValidateSite(Site{
		Domain:      "example.com",
		ListenIP:    "::",
		BackendIP:   "2001:db8::30",
		BackendHTTP: 8080,
	}, false, map[string]struct{}{}, hostInterfaceAddrs{})
	if errText != "" {
		t.Fatalf("normalizeAndValidateSite() error = %q, want empty", errText)
	}
	if site.ListenIP != "::" {
		t.Fatalf("ListenIP = %q, want ::", site.ListenIP)
	}
	if site.BackendIP != "2001:db8::30" {
		t.Fatalf("BackendIP = %q, want 2001:db8::30", site.BackendIP)
	}
}

func TestNormalizeAndValidateRangeAllowsIPv6TCPAndUDP(t *testing.T) {
	t.Run("tcp allowed", func(t *testing.T) {
		_, errText := normalizeAndValidateRange(PortRange{
			InIP:         "::",
			StartPort:    10000,
			EndPort:      10010,
			OutIP:        "2001:db8::40",
			OutStartPort: 20000,
			Protocol:     "tcp",
		}, false, map[string]struct{}{}, hostInterfaceAddrs{})
		if errText != "" {
			t.Fatalf("normalizeAndValidateRange() error = %q, want empty", errText)
		}
	})

	t.Run("udp allowed", func(t *testing.T) {
		pr, errText := normalizeAndValidateRange(PortRange{
			InIP:         "::",
			StartPort:    10000,
			EndPort:      10010,
			OutIP:        "2001:db8::40",
			OutStartPort: 20000,
			Protocol:     "udp",
		}, false, map[string]struct{}{}, hostInterfaceAddrs{})
		if errText != "" {
			t.Fatalf("normalizeAndValidateRange() error = %q, want empty", errText)
		}
		if pr.InIP != "::" || pr.OutIP != "2001:db8::40" {
			t.Fatalf("normalizeAndValidateRange() canonical IPs = (%q, %q), want (::, 2001:db8::40)", pr.InIP, pr.OutIP)
		}
	})
}

func TestNormalizeAndValidateRuleAllowsIPv6OutboundSourceIP(t *testing.T) {
	hostAddrs := hostInterfaceAddrs{
		"eth1": {
			"2001:db8::2": {},
		},
	}
	rule, issues := normalizeAndValidateRule(Rule{
		InInterface:  "eth0",
		InIP:         "0.0.0.0",
		InPort:       8080,
		OutInterface: "eth1",
		OutIP:        "2001:db8::20",
		OutSourceIP:  "2001:db8::2",
		OutPort:      80,
		Protocol:     "tcp",
	}, "create", 1, false, map[string]struct{}{"eth0": {}, "eth1": {}}, hostAddrs)
	if len(issues) != 0 {
		t.Fatalf("normalizeAndValidateRule() issues = %#v, want none", issues)
	}
	if rule.OutSourceIP != "2001:db8::2" {
		t.Fatalf("OutSourceIP = %q, want 2001:db8::2", rule.OutSourceIP)
	}
}

func TestNormalizeAndValidateRuleRejectsMismatchedOutboundSourceIPFamily(t *testing.T) {
	_, issues := normalizeAndValidateRule(Rule{
		InIP:        "0.0.0.0",
		InPort:      8080,
		OutIP:       "2001:db8::20",
		OutSourceIP: "192.0.2.10",
		OutPort:     80,
		Protocol:    "tcp",
	}, "create", 1, false, map[string]struct{}{}, hostInterfaceAddrs{})
	if !hasValidationMessage(issues, "must match outbound IP address family") {
		t.Fatalf("normalizeAndValidateRule() issues = %#v, want outbound family rejection", issues)
	}
}

func TestNormalizeAndValidateSiteAllowsIPv6BackendSourceIP(t *testing.T) {
	hostAddrs := hostInterfaceAddrs{
		"eth1": {
			"2001:db8::2": {},
		},
	}
	site, errText := normalizeAndValidateSite(Site{
		Domain:          "example.com",
		ListenIP:        "0.0.0.0",
		BackendIP:       "2001:db8::30",
		BackendSourceIP: "2001:db8::2",
		BackendHTTP:     8080,
	}, false, map[string]struct{}{"eth1": {}}, hostAddrs)
	if errText != "" {
		t.Fatalf("normalizeAndValidateSite() error = %q, want empty", errText)
	}
	if site.BackendSourceIP != "2001:db8::2" {
		t.Fatalf("BackendSourceIP = %q, want 2001:db8::2", site.BackendSourceIP)
	}
}

func TestNormalizeAndValidateRangeAllowsIPv6OutboundSourceIP(t *testing.T) {
	hostAddrs := hostInterfaceAddrs{
		"eth1": {
			"2001:db8::2": {},
		},
	}
	pr, errText := normalizeAndValidateRange(PortRange{
		InIP:         "::",
		StartPort:    10000,
		EndPort:      10010,
		OutInterface: "eth1",
		OutIP:        "2001:db8::40",
		OutSourceIP:  "2001:db8::2",
		OutStartPort: 20000,
		Protocol:     "tcp",
	}, false, map[string]struct{}{"eth1": {}}, hostAddrs)
	if errText != "" {
		t.Fatalf("normalizeAndValidateRange() error = %q, want empty", errText)
	}
	if pr.OutSourceIP != "2001:db8::2" {
		t.Fatalf("OutSourceIP = %q, want 2001:db8::2", pr.OutSourceIP)
	}
}

func TestConfigureOutboundTCPDialerAcceptsIPv6SourceIP(t *testing.T) {
	dialer := &net.Dialer{}
	if err := configureOutboundTCPDialer(dialer, "", "2001:db8::2"); err != nil {
		t.Fatalf("configureOutboundTCPDialer() error = %v", err)
	}
	addr, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok || addr == nil {
		t.Fatalf("LocalAddr = %T, want *net.TCPAddr", dialer.LocalAddr)
	}
	if got := addr.IP.String(); got != "2001:db8::2" {
		t.Fatalf("LocalAddr.IP = %q, want 2001:db8::2", got)
	}
}

func TestRuleIPsOverlapSeparatesIPv4AndIPv6(t *testing.T) {
	if ruleIPsOverlap("0.0.0.0", "::") {
		t.Fatal("ruleIPsOverlap(0.0.0.0, ::) = true, want false")
	}
	if !ruleIPsOverlap("::", "2001:db8::1") {
		t.Fatal("ruleIPsOverlap(::, 2001:db8::1) = false, want true")
	}
	if !ruleIPsOverlap("0.0.0.0", "192.0.2.10") {
		t.Fatal("ruleIPsOverlap(0.0.0.0, 192.0.2.10) = false, want true")
	}
}

func TestPrepareRuleBatchAllowsSeparateIPv4AndIPv6Listeners(t *testing.T) {
	db := openValidationTestDB(t)

	if _, err := dbAddSite(db, &Site{
		Domain:      "example.com",
		ListenIP:    "::",
		BackendIP:   "2001:db8::10",
		BackendHTTP: 8080,
		Enabled:     true,
	}); err != nil {
		t.Fatalf("dbAddSite() error = %v", err)
	}

	_, issues, err := prepareRuleBatch(db, ruleBatchRequest{
		Create: []Rule{{
			InIP:     "0.0.0.0",
			InPort:   80,
			OutIP:    "192.0.2.20",
			OutPort:  80,
			Protocol: "tcp",
		}},
	})
	if err != nil {
		t.Fatalf("prepareRuleBatch() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("prepareRuleBatch() issues = %#v, want no cross-family listener conflict", issues)
	}
}

func TestRuleDataplanePlannerHandlesIPv6KernelEligibility(t *testing.T) {
	planner := newRuleDataplanePlanner(stubKernelSupportRuntime{
		available: true,
		supported: true,
	}, ruleEngineKernel)

	tests := []struct {
		name       string
		rule       Rule
		wantKernel bool
		wantEngine string
		wantReason string
	}{
		{
			name: "ipv6 fullnat",
			rule: Rule{
				ID:               1,
				InInterface:      "eno1",
				InIP:             "::",
				InPort:           8080,
				OutInterface:     "eno2",
				OutIP:            "2001:db8::20",
				OutPort:          80,
				Protocol:         "tcp",
				EnginePreference: ruleEngineKernel,
			},
			wantKernel: true,
			wantEngine: ruleEngineKernel,
		},
		{
			name: "transparent ipv6",
			rule: Rule{
				ID:               2,
				InInterface:      "eno1",
				InIP:             "::",
				InPort:           8081,
				OutInterface:     "eno2",
				OutIP:            "2001:db8::20",
				OutPort:          80,
				Protocol:         "tcp",
				Transparent:      true,
				EnginePreference: ruleEngineKernel,
			},
			wantKernel: false,
			wantEngine: ruleEngineUserspace,
			wantReason: "kernel dataplane currently does not support transparent IPv6 rules",
		},
		{
			name: "mixed family",
			rule: Rule{
				ID:               3,
				InInterface:      "eno1",
				InIP:             "::",
				InPort:           8082,
				OutInterface:     "eno2",
				OutIP:            "192.0.2.20",
				OutPort:          80,
				Protocol:         "tcp",
				EnginePreference: ruleEngineKernel,
			},
			wantKernel: false,
			wantEngine: ruleEngineUserspace,
			wantReason: "kernel dataplane does not support mixed IPv4/IPv6 forwarding",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := planner.Plan(tc.rule)
			if plan.KernelEligible != tc.wantKernel {
				t.Fatalf("KernelEligible = %t, want %t", plan.KernelEligible, tc.wantKernel)
			}
			if plan.KernelReason != tc.wantReason {
				t.Fatalf("KernelReason = %q, want %q", plan.KernelReason, tc.wantReason)
			}
			if plan.EffectiveEngine != tc.wantEngine {
				t.Fatalf("EffectiveEngine = %q, want %q", plan.EffectiveEngine, tc.wantEngine)
			}
			if plan.FallbackReason != tc.wantReason {
				t.Fatalf("FallbackReason = %q, want %q", plan.FallbackReason, tc.wantReason)
			}
		})
	}
}
