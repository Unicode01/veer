package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	WebPort           int      `json:"web_port"`
	WebToken          string   `json:"web_token"`
	MaxWorkers        int      `json:"max_workers"`
	DrainTimeoutHours int      `json:"drain_timeout_hours"`
	DefaultEngine     string   `json:"default_engine"`
	Tags              []string `json:"tags"`
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
	if cfg.MaxWorkers < 0 {
		cfg.MaxWorkers = 0
	}
	if cfg.DrainTimeoutHours == 0 {
		cfg.DrainTimeoutHours = 24
	}
	cfg.DefaultEngine = normalizeRuleEnginePreference(cfg.DefaultEngine)
	if !isValidRuleEnginePreference(cfg.DefaultEngine) {
		cfg.DefaultEngine = ruleEngineAuto
	}
	return &cfg, nil
}
