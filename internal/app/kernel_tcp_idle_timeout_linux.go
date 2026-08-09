//go:build linux

package app

import (
	"log"
	"time"
)

const (
	kernelTCPAutoIdleTimeoutTierLow      = 0
	kernelTCPAutoIdleTimeoutTierModerate = 1
	kernelTCPAutoIdleTimeoutTierHigh     = 2
	kernelTCPAutoIdleTimeoutTierCritical = 3
)

type kernelTCPAutoIdleTimeoutTier struct {
	name             string
	enterWatermark   int
	releaseWatermark int
	timeoutNS        uint64
}

var kernelTCPAutoIdleTimeoutTiers = [...]kernelTCPAutoIdleTimeoutTier{
	{
		name:      "low",
		timeoutNS: kernelTCPFlowIdleTimeout,
	},
	{
		name:             "moderate",
		enterWatermark:   50,
		releaseWatermark: 45,
		timeoutNS:        6 * 60 * 60 * 1_000_000_000,
	},
	{
		name:             "high",
		enterWatermark:   70,
		releaseWatermark: 65,
		timeoutNS:        60 * 60 * 1_000_000_000,
	},
	{
		name:             "critical",
		enterWatermark:   85,
		releaseWatermark: 80,
		timeoutNS:        10 * 60 * 1_000_000_000,
	},
}

type kernelTCPIdleTimeoutState struct {
	configuredSeconds int64
	autoTier          int
	flowsEntries      int
	flowsCapacity     int
}

func newKernelTCPIdleTimeoutState(configuredSeconds int64) kernelTCPIdleTimeoutState {
	if validateKernelTCPEstablishedIdleTimeoutSeconds(configuredSeconds) != nil {
		configuredSeconds = 0
	}
	return kernelTCPIdleTimeoutState{configuredSeconds: configuredSeconds}
}

func (state kernelTCPIdleTimeoutState) mode() string {
	return kernelTCPEstablishedIdleTimeoutMode(state.configuredSeconds)
}

func (state kernelTCPIdleTimeoutState) auto() bool {
	return state.configuredSeconds == 0
}

func (state kernelTCPIdleTimeoutState) effectiveTimeoutNS() uint64 {
	if state.configuredSeconds > 0 {
		return uint64(state.configuredSeconds) * uint64(time.Second)
	}
	tier := state.autoTier
	if tier < 0 || tier >= len(kernelTCPAutoIdleTimeoutTiers) {
		tier = kernelTCPAutoIdleTimeoutTierLow
	}
	return kernelTCPAutoIdleTimeoutTiers[tier].timeoutNS
}

func (state kernelTCPIdleTimeoutState) effectiveTimeoutSeconds() int64 {
	return int64(state.effectiveTimeoutNS() / uint64(time.Second))
}

func (state kernelTCPIdleTimeoutState) autoTierName() string {
	if !state.auto() {
		return ""
	}
	tier := state.autoTier
	if tier < 0 || tier >= len(kernelTCPAutoIdleTimeoutTiers) {
		tier = kernelTCPAutoIdleTimeoutTierLow
	}
	return kernelTCPAutoIdleTimeoutTiers[tier].name
}

func (state *kernelTCPIdleTimeoutState) observeFlowUsage(entries int, capacity int) bool {
	if state == nil {
		return false
	}
	state.flowsEntries = max(entries, 0)
	state.flowsCapacity = max(capacity, 0)
	if !state.auto() {
		return false
	}

	previousTier := state.autoTier
	if state.autoTier < 0 || state.autoTier >= len(kernelTCPAutoIdleTimeoutTiers) || capacity <= 0 {
		state.autoTier = kernelTCPAutoIdleTimeoutTierLow
		return state.autoTier != previousTier
	}

	for state.autoTier+1 < len(kernelTCPAutoIdleTimeoutTiers) {
		next := kernelTCPAutoIdleTimeoutTiers[state.autoTier+1]
		if entries < kernelRuntimePressureThreshold(capacity, next.enterWatermark) {
			break
		}
		state.autoTier++
	}
	for state.autoTier > kernelTCPAutoIdleTimeoutTierLow {
		current := kernelTCPAutoIdleTimeoutTiers[state.autoTier]
		if entries >= kernelRuntimePressureThreshold(capacity, current.releaseWatermark) {
			break
		}
		state.autoTier--
	}
	return state.autoTier != previousTier
}

func logKernelTCPIdleTimeoutTransition(engine string, previous kernelTCPIdleTimeoutState, next kernelTCPIdleTimeoutState) {
	if previous.effectiveTimeoutNS() == next.effectiveTimeoutNS() {
		return
	}
	log.Printf(
		"%s dataplane TCP established idle timeout auto-adjusted: %s (%s) -> %s (%s), flows=%s",
		engine,
		previous.autoTierName(),
		time.Duration(previous.effectiveTimeoutNS()),
		next.autoTierName(),
		time.Duration(next.effectiveTimeoutNS()),
		kernelRuntimePressureUsage(next.flowsEntries, next.flowsCapacity),
	)
}
