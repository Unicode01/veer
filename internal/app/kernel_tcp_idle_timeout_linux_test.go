//go:build linux

package app

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelTCPIdleTimeoutAutoTiersAndHysteresis(t *testing.T) {
	state := newKernelTCPIdleTimeoutState(0)
	assertKernelTCPIdleTimeoutState(t, state, kernelTCPEstablishedIdleTimeoutModeAuto, "low", 24*time.Hour)

	tests := []struct {
		name        string
		entries     int
		wantTier    string
		wantTimeout time.Duration
	}{
		{name: "below moderate watermark", entries: 49, wantTier: "low", wantTimeout: 24 * time.Hour},
		{name: "enter moderate", entries: 50, wantTier: "moderate", wantTimeout: 6 * time.Hour},
		{name: "moderate hysteresis", entries: 46, wantTier: "moderate", wantTimeout: 6 * time.Hour},
		{name: "release moderate", entries: 44, wantTier: "low", wantTimeout: 24 * time.Hour},
		{name: "jump to critical", entries: 85, wantTier: "critical", wantTimeout: 10 * time.Minute},
		{name: "critical hysteresis", entries: 84, wantTier: "critical", wantTimeout: 10 * time.Minute},
		{name: "release critical to high", entries: 79, wantTier: "high", wantTimeout: time.Hour},
		{name: "high hysteresis", entries: 66, wantTier: "high", wantTimeout: time.Hour},
		{name: "release high to moderate", entries: 64, wantTier: "moderate", wantTimeout: 6 * time.Hour},
		{name: "release moderate to low", entries: 44, wantTier: "low", wantTimeout: 24 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state.observeFlowUsage(tc.entries, 100)
			assertKernelTCPIdleTimeoutState(t, state, kernelTCPEstablishedIdleTimeoutModeAuto, tc.wantTier, tc.wantTimeout)
		})
	}

	state.observeFlowUsage(90, 100)
	state.observeFlowUsage(0, 0)
	assertKernelTCPIdleTimeoutState(t, state, kernelTCPEstablishedIdleTimeoutModeAuto, "low", 24*time.Hour)
}

func TestKernelTCPIdleTimeoutFixedValueIgnoresFlowUsage(t *testing.T) {
	state := newKernelTCPIdleTimeoutState(1234)
	state.observeFlowUsage(99, 100)
	assertKernelTCPIdleTimeoutState(t, state, kernelTCPEstablishedIdleTimeoutModeFixed, "", 1234*time.Second)
}

func TestKernelTCPIdleTimeoutUsesHighestFamilyUtilization(t *testing.T) {
	pressure := buildKernelRuntimePressureStateFromSamples(
		kernelRuntimePressureLevelNone,
		[]kernelRuntimePressureUsageSample{
			{label: "flows ipv4", entries: 40, capacity: 100},
			{label: "flows ipv6", entries: 85, capacity: 100},
		},
		nil,
	)
	state := newKernelTCPIdleTimeoutState(0)
	state.observeFlowUsage(pressure.flowsEntries, pressure.flowsCapacity)
	assertKernelTCPIdleTimeoutState(t, state, kernelTCPEstablishedIdleTimeoutModeAuto, "critical", 10*time.Minute)
}

func TestKernelRuntimeConstructorsPropagateFixedTCPIdleTimeout(t *testing.T) {
	cfg := &Config{KernelTCPEstablishedIdleTimeoutSeconds: 7200}
	tc := newTCKernelRuleRuntime(cfg)
	assertKernelTCPIdleTimeoutState(t, tc.tcpIdleTimeout, kernelTCPEstablishedIdleTimeoutModeFixed, "", 2*time.Hour)

	xdp, ok := newXDPKernelRuleRuntime(cfg).(*xdpKernelRuleRuntime)
	if !ok {
		t.Fatal("newXDPKernelRuleRuntime() did not return xdp runtime")
	}
	assertKernelTCPIdleTimeoutState(t, xdp.tcpIdleTimeout, kernelTCPEstablishedIdleTimeoutModeFixed, "", 2*time.Hour)
}

func TestKernelFlowExpiryUsesEffectiveTCPIdleTimeoutForIPv4AndIPv6(t *testing.T) {
	timeoutNS := uint64(time.Hour)
	nowNS := timeoutNS + 1
	v4Key := tcFlowKeyV4{Proto: unix.IPPROTO_TCP}
	v4Value := tcFlowValueV4{
		RuleID:     1,
		Flags:      kernelFlowFlagFullNAT | kernelFlowFlagReplySeen,
		NATAddr:    1,
		NATPort:    1,
		LastSeenNS: 1,
	}
	if reason := kernelFlowDeleteReasonWithTCPIdleTimeout(v4Key, v4Value, nowNS, true, timeoutNS); reason != "" {
		t.Fatalf("IPv4 flow at timeout boundary reason = %q, want none", reason)
	}
	if reason := kernelFlowDeleteReasonWithTCPIdleTimeout(v4Key, v4Value, nowNS+1, true, timeoutNS); reason != "tcp_idle_timeout" {
		t.Fatalf("IPv4 flow after timeout reason = %q, want tcp_idle_timeout", reason)
	}

	v6Key := tcFlowKeyV6{Proto: unix.IPPROTO_TCP}
	v6Value := tcFlowValueV6{
		RuleID:     1,
		Flags:      kernelFlowFlagFullNAT | kernelFlowFlagReplySeen,
		NATAddr:    [16]byte{15: 1},
		NATPort:    1,
		LastSeenNS: 1,
	}
	if kernelFlowShouldDeleteV6WithTCPIdleTimeout(v6Key, v6Value, nowNS, true, timeoutNS) {
		t.Fatal("IPv6 flow at timeout boundary was deleted")
	}
	if !kernelFlowShouldDeleteV6WithTCPIdleTimeout(v6Key, v6Value, nowNS+1, true, timeoutNS) {
		t.Fatal("IPv6 flow after timeout was retained")
	}
}

func assertKernelTCPIdleTimeoutState(t *testing.T, state kernelTCPIdleTimeoutState, wantMode string, wantTier string, wantTimeout time.Duration) {
	t.Helper()
	if state.mode() != wantMode {
		t.Fatalf("mode = %q, want %q", state.mode(), wantMode)
	}
	if state.autoTierName() != wantTier {
		t.Fatalf("auto tier = %q, want %q", state.autoTierName(), wantTier)
	}
	if got := time.Duration(state.effectiveTimeoutNS()); got != wantTimeout {
		t.Fatalf("effective timeout = %s, want %s", got, wantTimeout)
	}
}
