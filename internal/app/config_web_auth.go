package app

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Web login realms. "token" is the web_token entered on the login page;
// "system" is a host account checked against /etc/shadow. Bearer requests
// with web_token are API calls, not a realm, and always work.
const (
	webAuthRealmSystem = "system"
	webAuthRealmToken  = "token"

	defaultWebSessionIdleMinutes = 30
	defaultWebSessionMaxHours    = 12
	maxWebSessionIdleMinutes     = 24 * 60
	maxWebSessionMaxHours        = 30 * 24
)

var defaultWebAdminGroups = []string{"sudo", "wheel"}

// normalizeWebAuthConfig validates the login settings of a loaded config.
func normalizeWebAuthConfig(cfg *Config) error {
	if cfg.WebAuthRealmsSetting != nil {
		if len(cfg.WebAuthRealmsSetting) == 0 {
			return fmt.Errorf("web_auth_realms must list at least one of %q, %q", webAuthRealmSystem, webAuthRealmToken)
		}
		seen := make(map[string]bool, len(cfg.WebAuthRealmsSetting))
		realms := make([]string, 0, len(cfg.WebAuthRealmsSetting))
		for _, raw := range cfg.WebAuthRealmsSetting {
			realm := strings.ToLower(strings.TrimSpace(raw))
			if realm != webAuthRealmSystem && realm != webAuthRealmToken {
				return fmt.Errorf("web_auth_realms: unknown realm %q (use %q or %q)", raw, webAuthRealmSystem, webAuthRealmToken)
			}
			if !seen[realm] {
				seen[realm] = true
				realms = append(realms, realm)
			}
		}
		cfg.WebAuthRealmsSetting = realms
	}
	if cfg.WebSessionIdleMinutes < 0 || cfg.WebSessionMaxHours < 0 {
		return fmt.Errorf("web_session_idle_minutes and web_session_max_hours must not be negative")
	}
	cfg.WebSessionIdleMinutes = normalizeBoundedConfigValue(cfg.WebSessionIdleMinutes, defaultWebSessionIdleMinutes, 1, maxWebSessionIdleMinutes)
	cfg.WebSessionMaxHours = normalizeBoundedConfigValue(cfg.WebSessionMaxHours, defaultWebSessionMaxHours, 1, maxWebSessionMaxHours)
	if cfg.WebAdminGroupsSetting != nil {
		groups := make([]string, 0, len(*cfg.WebAdminGroupsSetting))
		for _, raw := range *cfg.WebAdminGroupsSetting {
			group := strings.TrimSpace(raw)
			if !validSystemAccountName(group) {
				return fmt.Errorf("web_admin_groups: invalid group name %q", raw)
			}
			if !containsString(groups, group) {
				groups = append(groups, group)
			}
		}
		*cfg.WebAdminGroupsSetting = groups
	}
	proxies := make([]string, 0, len(cfg.WebTrustedProxies))
	for _, raw := range cfg.WebTrustedProxies {
		value := strings.TrimSpace(raw)
		if _, err := parseTrustedProxy(value); err != nil {
			return fmt.Errorf("web_trusted_proxies: %w", err)
		}
		proxies = append(proxies, value)
	}
	cfg.WebTrustedProxies = proxies
	return nil
}

// WebAuthRealms lists the enabled web login realms. A config without
// web_auth_realms predates system accounts and keeps token login only.
func (cfg *Config) WebAuthRealms() []string {
	if cfg == nil || len(cfg.WebAuthRealmsSetting) == 0 {
		return []string{webAuthRealmToken}
	}
	return append([]string(nil), cfg.WebAuthRealmsSetting...)
}

func (cfg *Config) WebAuthRealmEnabled(realm string) bool {
	return containsString(cfg.WebAuthRealms(), realm)
}

func (cfg *Config) WebSessionIdleTimeout() time.Duration {
	minutes := defaultWebSessionIdleMinutes
	if cfg != nil && cfg.WebSessionIdleMinutes > 0 {
		minutes = cfg.WebSessionIdleMinutes
	}
	return time.Duration(minutes) * time.Minute
}

func (cfg *Config) WebSessionLifetime() time.Duration {
	hours := defaultWebSessionMaxHours
	if cfg != nil && cfg.WebSessionMaxHours > 0 {
		hours = cfg.WebSessionMaxHours
	}
	return time.Duration(hours) * time.Hour
}

// WebAdminGroups are the groups whose members may log in with a system
// account besides uid 0. Unset means sudo and wheel; an empty list means
// uid 0 only.
func (cfg *Config) WebAdminGroups() []string {
	if cfg == nil || cfg.WebAdminGroupsSetting == nil {
		return append([]string(nil), defaultWebAdminGroups...)
	}
	return append([]string(nil), (*cfg.WebAdminGroupsSetting)...)
}

// WebRootLoginAllowed reports whether uid 0 accounts may log in directly.
func (cfg *Config) WebRootLoginAllowed() bool {
	return cfg == nil || cfg.WebRootLoginSetting == nil || *cfg.WebRootLoginSetting
}

// parseTrustedProxy accepts an IP address or a CIDR prefix.
func parseTrustedProxy(value string) (*net.IPNet, error) {
	if value == "" {
		return nil, fmt.Errorf("empty entry")
	}
	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q", value)
		}
		return network, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("invalid address %q", value)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
