package kernelcap

import "fmt"

const (
	RulesMapBaseLimit         = 16384
	RulesMapAdaptiveMaxLimit  = 262144
	FlowsMapBaseLimit         = 262144
	FlowsMapAdaptiveMaxLimit  = 1048576
	FlowsMapPerEntryFactor    = 4
	NATMapBaseLimit           = 262144
	NATMapAdaptiveMaxLimit    = 1048576
	NATMapPerEntryFactor      = 4
	EgressNATAutoMapFloor     = 262144
	AdaptiveMapTargetUsagePct = 75
)

const (
	AdaptiveMapMemoryTierSmall = 2 << 30
	AdaptiveMapMemoryTierLarge = 8 << 30
)

type AdaptiveMapProfile struct {
	TotalMemoryBytes   uint64
	FlowsBaseLimit     int
	NATBaseLimit       int
	EgressNATAutoFloor int
}

const (
	AdaptiveMapProfileDefault = "default"
	AdaptiveMapProfileSmall   = "small"
	AdaptiveMapProfileMedium  = "medium"
	AdaptiveMapProfileLarge   = "large"
	AdaptiveMapProfileCustom  = "custom"
)

func DefaultAdaptiveMapProfile() AdaptiveMapProfile {
	return AdaptiveMapProfile{
		FlowsBaseLimit:     FlowsMapBaseLimit,
		NATBaseLimit:       NATMapBaseLimit,
		EgressNATAutoFloor: EgressNATAutoMapFloor,
	}
}

func AdaptiveMapProfileForTotalMemory(totalMemoryBytes uint64) AdaptiveMapProfile {
	profile := DefaultAdaptiveMapProfile()
	profile.TotalMemoryBytes = totalMemoryBytes
	switch {
	case totalMemoryBytes > 0 && totalMemoryBytes < AdaptiveMapMemoryTierSmall:
		profile.FlowsBaseLimit = 65536
		profile.NATBaseLimit = 65536
		profile.EgressNATAutoFloor = 65536
	case totalMemoryBytes > 0 && totalMemoryBytes < AdaptiveMapMemoryTierLarge:
		profile.FlowsBaseLimit = 131072
		profile.NATBaseLimit = 131072
		profile.EgressNATAutoFloor = 131072
	}
	return profile
}

func AdaptiveMapProfileName(profile AdaptiveMapProfile) string {
	switch {
	case profile.TotalMemoryBytes > 0 && profile.TotalMemoryBytes < AdaptiveMapMemoryTierSmall:
		return AdaptiveMapProfileSmall
	case profile.TotalMemoryBytes > 0 && profile.TotalMemoryBytes < AdaptiveMapMemoryTierLarge:
		return AdaptiveMapProfileMedium
	case profile.TotalMemoryBytes >= AdaptiveMapMemoryTierLarge:
		return AdaptiveMapProfileLarge
	}

	switch {
	case profile.FlowsBaseLimit <= 65536 && profile.NATBaseLimit <= 65536 && profile.EgressNATAutoFloor <= 65536:
		return AdaptiveMapProfileSmall
	case profile.FlowsBaseLimit <= 131072 && profile.NATBaseLimit <= 131072 && profile.EgressNATAutoFloor <= 131072:
		return AdaptiveMapProfileMedium
	}

	defaultProfile := DefaultAdaptiveMapProfile()
	if profile.FlowsBaseLimit == defaultProfile.FlowsBaseLimit &&
		profile.NATBaseLimit == defaultProfile.NATBaseLimit &&
		profile.EgressNATAutoFloor == defaultProfile.EgressNATAutoFloor {
		return AdaptiveMapProfileDefault
	}
	return AdaptiveMapProfileCustom
}

func FormatAdaptiveMapTotalMemory(total uint64) string {
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

func AdaptiveMapProfileLogFields(profile AdaptiveMapProfile) string {
	return fmt.Sprintf(
		"map_profile=%s mem=%s flows_base=%d nat_base=%d egress_nat_floor=%d",
		AdaptiveMapProfileName(profile),
		FormatAdaptiveMapTotalMemory(profile.TotalMemoryBytes),
		profile.FlowsBaseLimit,
		profile.NATBaseLimit,
		profile.EgressNATAutoFloor,
	)
}

func NormalizeRulesMapLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	return limit
}

func NormalizeFlowsMapLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	return limit
}

func NormalizeNATMapLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	return limit
}

func EgressNATAutoMapFloors(flowsConfiguredLimit int, natConfiguredLimit int, enabled bool, profile AdaptiveMapProfile) (int, int) {
	profile = normalizeAdaptiveMapProfile(profile)
	flowsConfiguredLimit = NormalizeFlowsMapLimit(flowsConfiguredLimit)
	natConfiguredLimit = NormalizeNATMapLimit(natConfiguredLimit)
	if !enabled {
		return flowsConfiguredLimit, natConfiguredLimit
	}
	autoFloor := profile.EgressNATAutoFloor
	if flowsConfiguredLimit == 0 {
		flowsConfiguredLimit = autoFloor
	}
	if natConfiguredLimit == 0 {
		natConfiguredLimit = autoFloor
	}
	return flowsConfiguredLimit, natConfiguredLimit
}

func EffectiveRulesMapLimit(configuredLimit int, requestedEntries int) int {
	configuredLimit = NormalizeRulesMapLimit(configuredLimit)
	if configuredLimit > 0 {
		return configuredLimit
	}
	return AdaptiveMapLimit(requestedEntries, RulesMapBaseLimit, RulesMapAdaptiveMaxLimit)
}

func EffectiveFlowsMapLimit(configuredLimit int, requestedEntries int, profile AdaptiveMapProfile) int {
	profile = normalizeAdaptiveMapProfile(profile)
	configuredLimit = NormalizeFlowsMapLimit(configuredLimit)
	if configuredLimit > 0 {
		return configuredLimit
	}
	baseLimit := profile.FlowsBaseLimit
	target := ScaleRequestedEntries(requestedEntries, FlowsMapPerEntryFactor, FlowsMapAdaptiveMaxLimit)
	if target < baseLimit {
		target = baseLimit
	}
	return AdaptiveMapLimit(target, baseLimit, FlowsMapAdaptiveMaxLimit)
}

func EffectiveNATMapLimit(configuredLimit int, requestedEntries int, profile AdaptiveMapProfile) int {
	profile = normalizeAdaptiveMapProfile(profile)
	configuredLimit = NormalizeNATMapLimit(configuredLimit)
	if configuredLimit > 0 {
		return configuredLimit
	}
	baseLimit := profile.NATBaseLimit
	target := ScaleRequestedEntries(requestedEntries, NATMapPerEntryFactor, NATMapAdaptiveMaxLimit)
	if target < baseLimit {
		target = baseLimit
	}
	return AdaptiveMapLimit(target, baseLimit, NATMapAdaptiveMaxLimit)
}

func AdaptiveMapLimit(requestedEntries int, base int, max int) int {
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

func AdaptiveMapLimitForLiveEntries(entries int, base int, max int) int {
	if entries <= 0 {
		return 0
	}
	required := RequestedEntriesForTargetUsage(entries, AdaptiveMapTargetUsagePct, max)
	if required < base {
		required = base
	}
	return AdaptiveMapLimit(required, base, max)
}

func RequestedEntriesForTargetUsage(entries int, targetUsagePct int, max int) int {
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

func ScaleRequestedEntries(requestedEntries int, factor int, max int) int {
	if requestedEntries <= 0 || factor <= 0 {
		return 0
	}
	if requestedEntries > max/factor {
		return max
	}
	return requestedEntries * factor
}

func RulesMapCapacityMode(configuredLimit int) string {
	return MapCapacityMode(NormalizeRulesMapLimit(configuredLimit))
}

func FlowsMapCapacityMode(configuredLimit int) string {
	return MapCapacityMode(NormalizeFlowsMapLimit(configuredLimit))
}

func NATMapCapacityMode(configuredLimit int) string {
	return MapCapacityMode(NormalizeNATMapLimit(configuredLimit))
}

func MapCapacityMode(limit int) string {
	if limit > 0 {
		return "fixed"
	}
	return "adaptive"
}

func RulesCapacityReason(configuredLimit int, requestedEntries int) string {
	limit := EffectiveRulesMapLimit(configuredLimit, requestedEntries)
	if RulesMapCapacityMode(configuredLimit) == "fixed" {
		return fmt.Sprintf("kernel rules map capacity %d is lower than requested entries %d", limit, requestedEntries)
	}
	return fmt.Sprintf("adaptive kernel rules map capacity %d is lower than requested entries %d", limit, requestedEntries)
}

func normalizeAdaptiveMapProfile(profile AdaptiveMapProfile) AdaptiveMapProfile {
	defaultProfile := DefaultAdaptiveMapProfile()
	if profile.FlowsBaseLimit <= 0 {
		profile.FlowsBaseLimit = defaultProfile.FlowsBaseLimit
	}
	if profile.NATBaseLimit <= 0 {
		profile.NATBaseLimit = defaultProfile.NATBaseLimit
	}
	if profile.EgressNATAutoFloor <= 0 {
		profile.EgressNATAutoFloor = defaultProfile.EgressNATAutoFloor
	}
	return profile
}
