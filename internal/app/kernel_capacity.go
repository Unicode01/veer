package app

import "fmt"

const (
	kernelRulesMapBaseLimit        = 16384
	kernelRulesMapAdaptiveMaxLimit = 262144
	kernelFlowsMapBaseLimit        = 131072
	kernelFlowsMapAdaptiveMaxLimit = 1048576
	kernelFlowsMapPerEntryFactor   = 4
	kernelNATMapBaseLimit          = 131072
	kernelNATMapAdaptiveMaxLimit   = 1048576
	kernelNATMapPerEntryFactor     = 4
)

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
	target := scaleKernelRequestedEntries(requestedEntries, kernelFlowsMapPerEntryFactor, kernelFlowsMapAdaptiveMaxLimit)
	if target < kernelFlowsMapBaseLimit {
		target = kernelFlowsMapBaseLimit
	}
	return adaptiveKernelMapLimit(target, kernelFlowsMapBaseLimit, kernelFlowsMapAdaptiveMaxLimit)
}

func effectiveKernelNATMapLimit(configuredLimit int, requestedEntries int) int {
	configuredLimit = normalizeKernelNATMapLimit(configuredLimit)
	if configuredLimit > 0 {
		return configuredLimit
	}
	target := scaleKernelRequestedEntries(requestedEntries, kernelNATMapPerEntryFactor, kernelNATMapAdaptiveMaxLimit)
	if target < kernelNATMapBaseLimit {
		target = kernelNATMapBaseLimit
	}
	return adaptiveKernelMapLimit(target, kernelNATMapBaseLimit, kernelNATMapAdaptiveMaxLimit)
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
