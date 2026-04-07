//go:build linux

package app

import (
	"strings"
	"testing"
)

func TestPrepareXDPKernelRulesDoesNotPreRejectFullNAT(t *testing.T) {
	rule := Rule{
		ID:           1,
		InInterface:  "missing-in",
		InIP:         "192.0.2.10",
		InPort:       8443,
		OutInterface: "missing-out",
		OutIP:        "198.51.100.20",
		OutPort:      443,
		OutSourceIP:  "198.51.100.30",
		Protocol:     "tcp",
		Transparent:  false,
	}

	_, _, _, results, _ := prepareXDPKernelRules([]Rule{rule}, xdpPrepareOptions{}, nil, false)
	result, ok := results[rule.ID]
	if !ok {
		t.Fatalf("missing prepare result for rule %d", rule.ID)
	}
	if result.Error == "" {
		t.Fatalf("prepare result error = empty, want failure from interface resolution")
	}
	if strings.Contains(result.Error, "supports only transparent rules") {
		t.Fatalf("prepare result error = %q, want non-transparent XDP preparation to continue past the old hard gate", result.Error)
	}
	if !strings.Contains(result.Error, `resolve inbound interface "missing-in"`) {
		t.Fatalf("prepare result error = %q, want inbound interface resolution failure", result.Error)
	}
}
