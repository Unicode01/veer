package app

import (
	"fmt"
	"sync"
)

const (
	kernelRulesMapBaseLimit         = 16384
	kernelRulesMapAdaptiveMaxLimit  = 262144
	kernelFlowsMapBaseLimit         = 262144
	kernelFlowsMapAdaptiveMaxLimit  = 1048576
	kernelFlowsMapPerEntryFactor    = 4
	kernelNATMapBaseLimit           = 262144
	kernelNATMapAdaptiveMaxLimit    = 1048576
	kernelNATMapPerEntryFactor      = 4
	kernelEgressNATAutoMapFloor     = 262144
	kernelAdaptiveMapTargetUsagePct = 75
)

const (
	kernelAdaptiveMapMemoryTierSmall = 2 << 30
	kernelAdaptiveMapMemoryTierLarge = 8 << 30
)

type kernelAdaptiveMapProfile struct {
	totalMemoryBytes   uint64
	flowsBaseLimit     int
	natBaseLimit       int
	egressNATAutoFloor int
}

const (
	kernelAdaptiveMapProfileDefault = "default"
	kernelAdaptiveMapProfileSmall   = "small"
	kernelAdaptiveMapProfileMedium  = "medium"
	kernelAdaptiveMapProfileLarge   = "large"
	kernelAdaptiveMapProfileCustom  = "custom"
)

var (
	kernelAdaptiveMapProfileOnce        sync.Once
	kernelAdaptiveMapProfileCached      kernelAdaptiveMapProfile
	kernelAdaptiveMapProfileOverride    kernelAdaptiveMapProfile
	kernelAdaptiveMapProfileOverrideSet bool
)

func defaultKernelAdaptiveMapProfile() kernelAdaptiveMapProfile {
	return kernelAdaptiveMapProfile{
		flowsBaseLimit:     kernelFlowsMapBaseLimit,
		natBaseLimit:       kernelNATMapBaseLimit,
		egressNATAutoFloor: kernelEgressNATAutoMapFloor,
	}
}

func kernelAdaptiveMapProfileForTotalMemory(totalMemoryBytes uint64) kernelAdaptiveMapProfile {
	profile := defaultKernelAdaptiveMapProfile()
	profile.totalMemoryBytes = totalMemoryBytes
	switch {
	case totalMemoryBytes > 0 && totalMemoryBytes < kernelAdaptiveMapMemoryTierSmall:
		profile.flowsBaseLimit = 65536
		profile.natBaseLimit = 65536
		profile.egressNATAutoFloor = 65536
	case totalMemoryBytes > 0 && totalMemoryBytes < kernelAdaptiveMapMemoryTierLarge:
		profile.flowsBaseLimit = 131072
		profile.natBaseLimit = 131072
		profile.egressNATAutoFloor = 131072
	}
	return profile
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
	switch {
	case profile.totalMemoryBytes > 0 && profile.totalMemoryBytes < kernelAdaptiveMapMemoryTierSmall:
		return kernelAdaptiveMapProfileSmall
	case profile.totalMemoryBytes > 0 && profile.totalMemoryBytes < kernelAdaptiveMapMemoryTierLarge:
		return kernelAdaptiveMapProfileMedium
	case profile.totalMemoryBytes >= kernelAdaptiveMapMemoryTierLarge:
		return kernelAdaptiveMapProfileLarge
	}

	switch {
	case profile.flowsBaseLimit <= 65536 && profile.natBaseLimit <= 65536 && profile.egressNATAutoFloor <= 65536:
		return kernelAdaptiveMapProfileSmall
	case profile.flowsBaseLimit <= 131072 && profile.natBaseLimit <= 131072 && profile.egressNATAutoFloor <= 131072:
		return kernelAdaptiveMapProfileMedium
	}

	defaultProfile := defaultKernelAdaptiveMapProfile()
	if profile.flowsBaseLimit == defaultProfile.flowsBaseLimit &&
		profile.natBaseLimit == defaultProfile.natBaseLimit &&
		profile.egressNATAutoFloor == defaultProfile.egressNATAutoFloor {
		return kernelAdaptiveMapProfileDefault
	}
	return kernelAdaptiveMapProfileCustom
}

func formatKernelAdaptiveMapTotalMemory(total uint64) string {
	if total == 0 {
		return "unknown"
	}

	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(total)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if value >= 10 || unit == 0 {
		return fmt.Sprintf("%.0f%s", value, units[unit])
	}
	return fmt.Sprintf("%.1f%s", value, units[unit])
}

func kernelAdaptiveMapProfileLogFields(profile kernelAdaptiveMapProfile) string {
	return fmt.Sprintf(
		"map_profile=%s mem=%s flows_base=%d nat_base=%d egress_nat_floor=%d",
		kernelAdaptiveMapProfileName(profile),
		formatKernelAdaptiveMapTotalMemory(profile.totalMemoryBytes),
		profile.flowsBaseLimit,
		profile.natBaseLimit,
		profile.egressNATAutoFloor,
	)
}

func kernelAdaptiveFlowsMapBaseLimit() int {
	return currentKernelAdaptiveMapProfile().flowsBaseLimit
}

func kernelAdaptiveNATMapBaseLimit() int {
	return currentKernelAdaptiveMapProfile().natBaseLimit
}

func kernelAdaptiveEgressNATAutoMapFloor() int {
	return currentKernelAdaptiveMapProfile().egressNATAutoFloor
}

func normalizeKernelRulesMapLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	return limit
}

func normalizeKernelFlowsMapLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	return limit
}

func normalizeKernelNATMapLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	return limit
}

func kernelEgressNATAutoMapFloors(flowsConfiguredLimit int, natConfiguredLimit int, enabled bool) (int, int) {
	flowsConfiguredLimit = normalizeKernelFlowsMapLimit(flowsConfiguredLimit)
	natConfiguredLimit = normalizeKernelNATMapLimit(natConfiguredLimit)
	if !enabled {
		return flowsConfiguredLimit, natConfiguredLimit
	}
	autoFloor := kernelAdaptiveEgressNATAutoMapFloor()
	if flowsConfiguredLimit == 0 {
		flowsConfiguredLimit = autoFloor
	}
	if natConfiguredLimit == 0 {
		natConfiguredLimit = autoFloor
	}
	return flowsConfiguredLimit, natConfiguredLimit
}

func effectiveKernelRulesMapLimit(configuredLimit int, requestedEntries int) int {
	configuredLimit = normalizeKernelRulesMapLimit(configuredLimit)
	if configuredLimit > 0 {
		return configuredLimit
	}
	return adaptiveKernelMapLimit(requestedEntries, kernelRulesMapBaseLimit, kernelRulesMapAdaptiveMaxLimit)
}

func effectiveKernelFlowsMapLimit(configuredLimit int, requestedEntries int) int {
	configuredLimit = normalizeKernelFlowsMapLimit(configuredLimit)
	if configuredLimit > 0 {
		return configuredLimit
	}
	baseLimit := kernelAdaptiveFlowsMapBaseLimit()
	target := scaleKernelRequestedEntries(requestedEntries, kernelFlowsMapPerEntryFactor, kernelFlowsMapAdaptiveMaxLimit)
	if target < baseLimit {
		target = baseLimit
	}
	return adaptiveKernelMapLimit(target, baseLimit, kernelFlowsMapAdaptiveMaxLimit)
}

func effectiveKernelNATMapLimit(configuredLimit int, requestedEntries int) int {
	configuredLimit = normalizeKernelNATMapLimit(configuredLimit)
	if configuredLimit > 0 {
		return configuredLimit
	}
	baseLimit := kernelAdaptiveNATMapBaseLimit()
	target := scaleKernelRequestedEntries(requestedEntries, kernelNATMapPerEntryFactor, kernelNATMapAdaptiveMaxLimit)
	if target < baseLimit {
		target = baseLimit
	}
	return adaptiveKernelMapLimit(target, baseLimit, kernelNATMapAdaptiveMaxLimit)
}

func adaptiveKernelRulesMapLimit(requestedEntries int) int {
	return adaptiveKernelMapLimit(requestedEntries, kernelRulesMapBaseLimit, kernelRulesMapAdaptiveMaxLimit)
}

func adaptiveKernelMapLimit(requestedEntries int, base int, max int) int {
	limit := base
	if requestedEntries <= limit {
		return limit
	}
	for limit < requestedEntries && limit < max {
		if limit > max/2 {
			return max
		}
		limit *= 2
	}
	if limit > max {
		return max
	}
	return limit
}

func adaptiveKernelMapLimitForLiveEntries(entries int, base int, max int) int {
	if entries <= 0 {
		return 0
	}
	required := requestedEntriesForTargetUsage(entries, kernelAdaptiveMapTargetUsagePct, max)
	if required < base {
		required = base
	}
	return adaptiveKernelMapLimit(required, base, max)
}

func requestedEntriesForTargetUsage(entries int, targetUsagePct int, max int) int {
	if entries <= 0 || targetUsagePct <= 0 {
		return 0
	}
	if max > 0 && entries >= (max*targetUsagePct)/100 {
		return max
	}
	required := (entries * 100) / targetUsagePct
	if (entries*100)%targetUsagePct != 0 {
		required++
	}
	if max > 0 && required > max {
		return max
	}
	return required
}

func scaleKernelRequestedEntries(requestedEntries int, factor int, max int) int {
	if requestedEntries <= 0 || factor <= 0 {
		return 0
	}
	if requestedEntries > max/factor {
		return max
	}
	return requestedEntries * factor
}

func kernelRulesMapCapacityMode(configuredLimit int) string {
	return kernelMapCapacityMode(normalizeKernelRulesMapLimit(configuredLimit))
}

func kernelFlowsMapCapacityMode(configuredLimit int) string {
	return kernelMapCapacityMode(normalizeKernelFlowsMapLimit(configuredLimit))
}

func kernelNATMapCapacityMode(configuredLimit int) string {
	return kernelMapCapacityMode(normalizeKernelNATMapLimit(configuredLimit))
}

func kernelMapCapacityMode(limit int) string {
	if limit > 0 {
		return "fixed"
	}
	return "adaptive"
}

func kernelRulesCapacityReason(configuredLimit int, requestedEntries int) string {
	limit := effectiveKernelRulesMapLimit(configuredLimit, requestedEntries)
	if kernelRulesMapCapacityMode(configuredLimit) == "fixed" {
		return fmt.Sprintf("kernel rules map capacity %d is lower than requested entries %d", limit, requestedEntries)
	}
	return fmt.Sprintf("adaptive kernel rules map capacity %d is lower than requested entries %d", limit, requestedEntries)
}
