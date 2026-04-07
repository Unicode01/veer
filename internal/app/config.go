package app

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	experimentalFeatureBridgeXDP           = "bridge_xdp"
	experimentalFeatureKernelTraffic       = "kernel_traffic_stats"
	experimentalFeatureKernelTCDiag        = "kernel_tc_diag"
	experimentalFeatureKernelTCDiagVerbose = "kernel_tc_diag_verbose"
	insecureDefaultWebToken                = "change-me-to-a-secure-token"
)

type Config struct {
	WebPort             int             `json:"web_port"`
	WebToken            string          `json:"web_token"`
	MaxWorkers          int             `json:"max_workers"`
	DrainTimeoutHours   int             `json:"drain_timeout_hours"`
	DefaultEngine       string          `json:"default_engine"`
	KernelEngineOrder   []string        `json:"kernel_engine_order"`
	KernelRulesMapLimit int             `json:"kernel_rules_map_limit"`
	KernelFlowsMapLimit int             `json:"kernel_flows_map_limit"`
	KernelNATMapLimit   int             `json:"kernel_nat_ports_map_limit"`
	KernelNATPortMin    int             `json:"kernel_nat_port_min"`
	KernelNATPortMax    int             `json:"kernel_nat_port_max"`
	Experimental        map[string]bool `json:"experimental_features"`
	Tags                []string        `json:"tags"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.WebPort == 0 {
		cfg.WebPort = 8080
	}
	cfg.WebToken = strings.TrimSpace(cfg.WebToken)
	if cfg.WebToken == "" {
		return nil, fmt.Errorf("web_token must not be empty")
	}
	if cfg.WebToken == insecureDefaultWebToken {
		return nil, fmt.Errorf("web_token must not use the example placeholder value")
	}
	if cfg.MaxWorkers < 0 {
		cfg.MaxWorkers = 0
	}
	if cfg.DrainTimeoutHours == 0 {
		cfg.DrainTimeoutHours = 24
	}
	cfg.KernelRulesMapLimit = normalizeKernelRulesMapLimit(cfg.KernelRulesMapLimit)
	cfg.KernelFlowsMapLimit = normalizeKernelFlowsMapLimit(cfg.KernelFlowsMapLimit)
	cfg.KernelNATMapLimit = normalizeKernelNATMapLimit(cfg.KernelNATMapLimit)
	cfg.KernelNATPortMin, cfg.KernelNATPortMax, err = normalizeKernelNATPortRange(cfg.KernelNATPortMin, cfg.KernelNATPortMax)
	if err != nil {
		return nil, err
	}
	cfg.DefaultEngine = normalizeRuleEnginePreference(cfg.DefaultEngine)
	if !isValidRuleEnginePreference(cfg.DefaultEngine) {
		cfg.DefaultEngine = ruleEngineAuto
	}
	cfg.KernelEngineOrder = normalizeKernelEngineOrder(cfg.KernelEngineOrder)
	cfg.Experimental = normalizeExperimentalFeatures(cfg.Experimental)
	return &cfg, nil
}

func (cfg *Config) ExperimentalFeatureEnabled(name string) bool {
	if cfg == nil {
		return false
	}
	name = normalizeExperimentalFeatureName(name)
	if name == "" || cfg.Experimental == nil {
		return false
	}
	return cfg.Experimental[name]
}

func (cfg *Config) EnabledExperimentalFeatures() []string {
	if cfg == nil || len(cfg.Experimental) == 0 {
		return nil
	}

	out := make([]string, 0, len(cfg.Experimental))
	for name, enabled := range cfg.Experimental {
		if enabled {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeExperimentalFeatures(values map[string]bool) map[string]bool {
	if len(values) == 0 {
		return nil
	}

	out := make(map[string]bool, len(values))
	for raw, enabled := range values {
		name := normalizeExperimentalFeatureName(raw)
		if name == "" {
			continue
		}
		out[name] = enabled
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeExperimentalFeatureName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}
