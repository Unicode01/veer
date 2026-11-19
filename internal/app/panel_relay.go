package app

import (
	"fmt"
	"log"
	"strings"
)

// A forward of this host whose backend is the panel's own listener relays
// remote clients to it from this host, without saying so, and the panel
// would take them for local clients and serve them plain HTTP (see
// api_listener.go). Each reconcile records the first such forward, and the
// panel's plain HTTP guard treats every local request as relayed while there
// is one.

// findPanelRelayForward names an enabled TCP rule or port range that forwards
// to the panel's listener at an address of this host, or returns "". Only
// web_tls makes it matter: without it the panel serves everyone plain HTTP.
// hostAddrs is called at most once, and only when some forward targets the
// panel port.
func findPanelRelayForward(cfg *Config, rules []Rule, ranges []PortRange, hostAddrs func() hostInterfaceAddrs) string {
	if cfg == nil || !cfg.WebTLSEnabled() || cfg.WebPort <= 0 {
		return ""
	}
	port := cfg.WebPort
	bind := parseIPLiteral(normalizeWebBind(cfg.WebBind))
	tcp := ruleProtocolMask("tcp")
	var addrs hostInterfaceAddrs
	loaded := false
	reachesPanel := func(backend string) bool {
		ip := parseIPLiteral(strings.TrimSpace(backend))
		if ip == nil {
			return false
		}
		// A panel bound to one address is reached only there.
		if bind != nil && !bind.IsUnspecified() && !bind.Equal(ip) {
			return false
		}
		if !loaded {
			loaded = true
			if hostAddrs != nil {
				addrs = hostAddrs()
			}
		}
		return forwardBackendIsLocal(backend, addrs)
	}
	for _, rule := range rules {
		if rule.Enabled && ruleProtocolMask(rule.Protocol)&tcp != 0 && rule.OutPort == port && reachesPanel(rule.OutIP) {
			return fmt.Sprintf("rule #%d", rule.ID)
		}
	}
	for _, pr := range ranges {
		if !pr.Enabled || ruleProtocolMask(pr.Protocol)&tcp == 0 || pr.EndPort < pr.StartPort {
			continue
		}
		last := pr.OutStartPort + (pr.EndPort - pr.StartPort)
		if pr.OutStartPort <= port && port <= last && reachesPanel(pr.OutIP) {
			return fmt.Sprintf("port range #%d", pr.ID)
		}
	}
	return ""
}

// loadHostInterfaceAddrsOrNone returns the host's addresses, or none when
// they cannot be read; loopback backends are recognised either way.
func loadHostInterfaceAddrsOrNone() hostInterfaceAddrs {
	addrs, err := loadHostInterfaceAddrs()
	if err != nil {
		return nil
	}
	return addrs
}

// notePanelRelayForward records the forward that relays clients to the panel
// for the panel's plain HTTP guard, and logs when that changes.
func (pm *ProcessManager) notePanelRelayForward(rules []Rule, ranges []PortRange) {
	if pm == nil {
		return
	}
	relay := findPanelRelayForward(pm.cfg, rules, ranges, loadHostInterfaceAddrsOrNone)
	previous, _ := pm.panelRelay.Swap(relay).(string)
	switch {
	case relay != "" && relay != previous:
		log.Printf("web TLS: %s forwards to the panel port from this host, so plain HTTP from this host is refused except /healthz and /readyz; local clients use https", relay)
	case relay == "" && previous != "":
		log.Printf("web TLS: no forward relays clients to the panel port any more; plain HTTP from this host is served again")
	}
}

// panelRelayForward returns the forward notePanelRelayForward recorded last,
// or "".
func (pm *ProcessManager) panelRelayForward() string {
	if pm == nil {
		return ""
	}
	relay, _ := pm.panelRelay.Load().(string)
	return relay
}
