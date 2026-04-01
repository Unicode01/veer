package app

import "strings"

const (
	kernelEngineXDP = "xdp"
	kernelEngineTC  = "tc"
)

func defaultKernelEngineOrder() []string {
	return []string{kernelEngineXDP, kernelEngineTC}
}

func normalizeKernelEngineOrder(values []string) []string {
	if len(values) == 0 {
		return defaultKernelEngineOrder()
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case kernelEngineXDP, kernelEngineTC:
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}

	if len(out) == 0 {
		return defaultKernelEngineOrder()
	}
	return out
}
