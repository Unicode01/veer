package app

import (
	"testing"
)

func TestPortRangeTargetBounds(t *testing.T) {
	for _, tc := range []struct {
		name            string
		start, end, out int
		valid           bool
	}{
		{"last port", 100, 101, 65534, true},
		{"one port", 65535, 65535, 65535, true},
		{"overflow", 100, 101, 65535, false},
		{"full range", 1, 65535, 1, true},
		{"full range shifted", 1, 65535, 2, false},
		{"reversed", 2, 1, 1, false},
		{"negative", -1, 1, 1, false},
		{"integer overflow", 1, int(^uint(0) >> 1), 65535, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pr := PortRange{ID: 1, InIP: "127.0.0.1", OutIP: "127.0.0.1", Protocol: "udp", StartPort: tc.start, EndPort: tc.end, OutStartPort: tc.out, Enabled: true}
			if got := validatePortRangePorts(pr); (got == "") != tc.valid {
				t.Fatalf("validation = %q, valid = %v", got, tc.valid)
			}
			if _, got := normalizeAndValidateRange(pr, false, nil, nil); (got == "") != tc.valid {
				t.Fatalf("API validation = %q, valid = %v", got, tc.valid)
			}
			if tc.valid {
				return
			}
			rt := &countingKernelSupportRuntime{}
			candidates, _, plans := buildKernelCandidateRules(nil, []PortRange{pr}, newRuleDataplanePlanner(rt, ruleEngineKernel), 65536)
			if len(candidates) != 0 || rt.supportCalls != 0 || plans[pr.ID].FallbackReason == "" {
				t.Fatalf("invalid persisted range reached kernel: candidates=%d, plans=%+v", len(candidates), plans)
			}
			binding, _, err := startRangeBindingWithDegradedState(0, pr, &ruleStats{})
			if binding != nil {
				binding.Stop()
			}
			if err == nil {
				t.Fatal("invalid persisted range started userspace listeners")
			}
		})
	}
}

func TestRangeUDPInvalidTargetDoesNotReportBound(t *testing.T) {
	pr := PortRange{InIP: "127.0.0.1", StartPort: 12345, EndPort: 12345, OutIP: "invalid address", OutStartPort: 9, Protocol: "udp"}
	binding, _, err := startRangeBindingWithDegradedState(0, pr, &ruleStats{})
	if binding != nil {
		binding.Stop()
	}
	if err == nil {
		t.Fatal("invalid UDP target reported a successful bind")
	}
}
