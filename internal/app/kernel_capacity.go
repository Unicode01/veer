package app

import (
	"sync"

	"github.com/Unicode01/veer/internal/kernelcap"
)

const (
	kernelRulesMapBaseLimit         = kernelcap.RulesMapBaseLimit
	kernelRulesMapAdaptiveMaxLimit  = kernelcap.RulesMapAdaptiveMaxLimit
	kernelFlowsMapBaseLimit         = kernelcap.FlowsMapBaseLimit
	kernelFlowsMapAdaptiveMaxLimit  = kernelcap.FlowsMapAdaptiveMaxLimit
	kernelFlowsMapPerEntryFactor    = kernelcap.FlowsMapPerEntryFactor
	kernelNATMapBaseLimit           = kernelcap.NATMapBaseLimit
	kernelNATMapAdaptiveMaxLimit    = kernelcap.NATMapAdaptiveMaxLimit
	kernelNATMapPerEntryFactor      = kernelcap.NATMapPerEntryFactor
	kernelEgressNATAutoMapFloor     = kernelcap.EgressNATAutoMapFloor
	kernelAdaptiveMapTargetUsagePct = kernelcap.AdaptiveMapTargetUsagePct
)

type kernelAdaptiveMapProfile struct {
	totalMemoryBytes   uint64
	flowsBaseLimit     int
	natBaseLimit       int
	egressNATAutoFloor int
}

const (
	kernelAdaptiveMapProfileDefault = kernelcap.AdaptiveMapProfileDefault
	kernelAdaptiveMapProfileSmall   = kernelcap.AdaptiveMapProfileSmall
	kernelAdaptiveMapProfileMedium  = kernelcap.AdaptiveMapProfileMedium
	kernelAdaptiveMapProfileLarge   = kernelcap.AdaptiveMapProfileLarge
	kernelAdaptiveMapProfileCustom  = kernelcap.AdaptiveMapProfileCustom
)

var (
	kernelAdaptiveMapProfileOnce        sync.Once
	kernelAdaptiveMapProfileCached      kernelAdaptiveMapProfile
	kernelAdaptiveMapProfileOverride    kernelAdaptiveMapProfile
	kernelAdaptiveMapProfileOverrideSet bool
)

func defaultKernelAdaptiveMapProfile() kernelAdaptiveMapProfile {
	return fromKernelCapAdaptiveMapProfile(kernelcap.DefaultAdaptiveMapProfile())
}

func kernelAdaptiveMapProfileForTotalMemory(totalMemoryBytes uint64) kernelAdaptiveMapProfile {
	return fromKernelCapAdaptiveMapProfile(kernelcap.AdaptiveMapProfileForTotalMemory(totalMemoryBytes))
}

func currentKernelAdaptiveMapProfile() kernelAdaptiveMapProfile {
	if kernelAdaptiveMapProfileOverrideSet {
		return kernelAdaptiveMapProfileOverride
	}
	kernelAdaptiveMapProfileOnce.Do(func() {
		kernelAdaptiveMapProfileCached = kernelAdaptiveMapProfileForTotalMemory(detectKernelAdaptiveMapTotalMemory())
	})
	return kernelAdaptiveMapProfileCached
}

func kernelAdaptiveMapProfileName(profile kernelAdaptiveMapProfile) string {
	return kernelcap.AdaptiveMapProfileName(toKernelCapAdaptiveMapProfile(profile))
}

func kernelAdaptiveMapProfileLogFields(profile kernelAdaptiveMapProfile) string {
	return kernelcap.AdaptiveMapProfileLogFields(toKernelCapAdaptiveMapProfile(profile))
}

func kernelAdaptiveEgressNATAutoMapFloor() int {
	return currentKernelAdaptiveMapProfile().egressNATAutoFloor
}

func normalizeKernelRulesMapLimit(limit int) int {
	return kernelcap.NormalizeRulesMapLimit(limit)
}

func normalizeKernelFlowsMapLimit(limit int) int {
	return kernelcap.NormalizeFlowsMapLimit(limit)
}

func normalizeKernelNATMapLimit(limit int) int {
	return kernelcap.NormalizeNATMapLimit(limit)
}

func kernelEgressNATAutoMapFloors(flowsConfiguredLimit int, natConfiguredLimit int, enabled bool) (int, int) {
	return kernelcap.EgressNATAutoMapFloors(flowsConfiguredLimit, natConfiguredLimit, enabled, toKernelCapAdaptiveMapProfile(currentKernelAdaptiveMapProfile()))
}

func effectiveKernelRulesMapLimit(configuredLimit int, requestedEntries int) int {
	return kernelcap.EffectiveRulesMapLimit(configuredLimit, requestedEntries)
}

func effectiveKernelFlowsMapLimit(configuredLimit int, requestedEntries int) int {
	return kernelcap.EffectiveFlowsMapLimit(configuredLimit, requestedEntries, toKernelCapAdaptiveMapProfile(currentKernelAdaptiveMapProfile()))
}

func effectiveKernelNATMapLimit(configuredLimit int, requestedEntries int) int {
	return kernelcap.EffectiveNATMapLimit(configuredLimit, requestedEntries, toKernelCapAdaptiveMapProfile(currentKernelAdaptiveMapProfile()))
}

func adaptiveKernelMapLimitForLiveEntries(entries int, base int, max int) int {
	return kernelcap.AdaptiveMapLimitForLiveEntries(entries, base, max)
}

func kernelRulesMapCapacityMode(configuredLimit int) string {
	return kernelcap.RulesMapCapacityMode(configuredLimit)
}

func kernelFlowsMapCapacityMode(configuredLimit int) string {
	return kernelcap.FlowsMapCapacityMode(configuredLimit)
}

func kernelNATMapCapacityMode(configuredLimit int) string {
	return kernelcap.NATMapCapacityMode(configuredLimit)
}

func kernelRulesCapacityReason(configuredLimit int, requestedEntries int) string {
	return kernelcap.RulesCapacityReason(configuredLimit, requestedEntries)
}

func detectKernelAdaptiveMapTotalMemory() uint64 {
	return kernelcap.DetectAdaptiveMapTotalMemory()
}

func toKernelCapAdaptiveMapProfile(profile kernelAdaptiveMapProfile) kernelcap.AdaptiveMapProfile {
	return kernelcap.AdaptiveMapProfile{
		TotalMemoryBytes:   profile.totalMemoryBytes,
		FlowsBaseLimit:     profile.flowsBaseLimit,
		NATBaseLimit:       profile.natBaseLimit,
		EgressNATAutoFloor: profile.egressNATAutoFloor,
	}
}

func fromKernelCapAdaptiveMapProfile(profile kernelcap.AdaptiveMapProfile) kernelAdaptiveMapProfile {
	return kernelAdaptiveMapProfile{
		totalMemoryBytes:   profile.TotalMemoryBytes,
		flowsBaseLimit:     profile.FlowsBaseLimit,
		natBaseLimit:       profile.NATBaseLimit,
		egressNATAutoFloor: profile.EgressNATAutoFloor,
	}
}
