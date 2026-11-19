package app

// A user space listener on a specific address does not need its inbound
// interface to tell its traffic apart: the address does that. Bound to the
// interface (SO_BINDTODEVICE) it refuses connections that reach the address
// through any other interface, which shuts out guests behind egress NAT
// reaching the host's public address (hairpin), routed networks and VPN
// clients. Such listeners are therefore handed to the workers and the shared
// proxy without their interface, which is what an empty interface means to
// them.
//
// The binding stays where the kernel needs it: on listeners for a wildcard
// address, which it limits to their interface, and on a listener whose port
// another listener on a different interface also uses for an overlapping
// address. The kernel tells those two apart only by their interfaces; without
// the binding one of them could not bind at all. Every enabled rule, range
// and site counts, whatever engine runs it, so the decision does not change
// when a rule moves between the kernel and user space.

type userspaceListenerFootprint struct {
	iface        string
	ip           string
	startPort    int
	endPort      int
	protocolMask int
}

func collectUserspaceListenerFootprints(rules []Rule, ranges []PortRange, sites []Site) []userspaceListenerFootprint {
	footprints := make([]userspaceListenerFootprint, 0, len(rules)+len(ranges)+2*len(sites))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		footprints = append(footprints, userspaceListenerFootprint{
			iface:        rule.InInterface,
			ip:           rule.InIP,
			startPort:    rule.InPort,
			endPort:      rule.InPort,
			protocolMask: ruleProtocolMask(rule.Protocol),
		})
	}
	for _, pr := range ranges {
		if !pr.Enabled {
			continue
		}
		footprints = append(footprints, userspaceListenerFootprint{
			iface:        pr.InInterface,
			ip:           pr.InIP,
			startPort:    pr.StartPort,
			endPort:      pr.EndPort,
			protocolMask: ruleProtocolMask(pr.Protocol),
		})
	}
	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		listenIP := site.ListenIP
		if listenIP == "" {
			listenIP = "0.0.0.0"
		}
		footprints = append(footprints,
			userspaceListenerFootprint{iface: site.ListenIface, ip: listenIP, startPort: 80, endPort: 80, protocolMask: ruleProtocolMask("tcp")},
			userspaceListenerFootprint{iface: site.ListenIface, ip: listenIP, startPort: 443, endPort: 443, protocolMask: ruleProtocolMask("tcp")},
		)
		if site.QUIC {
			footprints = append(footprints, userspaceListenerFootprint{iface: site.ListenIface, ip: listenIP, startPort: 443, endPort: 443, protocolMask: ruleProtocolMask("udp")})
		}
	}
	return footprints
}

// userspaceListenerNeedsInterface reports whether a listener on ip, ports
// startPort..endPort and the protocols in mask must stay bound to iface.
func userspaceListenerNeedsInterface(iface string, ip string, startPort int, endPort int, mask int, footprints []userspaceListenerFootprint) bool {
	if iface == "" {
		return false
	}
	if ipLiteralFamily(ip) == "" || ipLiteralIsWildcard(ip) {
		return true
	}
	for _, other := range footprints {
		if other.iface == "" || other.iface == iface {
			continue
		}
		if other.protocolMask&mask == 0 || !portRangesOverlap(startPort, endPort, other.startPort, other.endPort) {
			continue
		}
		if ruleIPsOverlap(ip, other.ip) {
			return true
		}
	}
	return false
}

// releaseSharedSiteListenInterfaces returns the sites for the shared proxy,
// without their listen interface where none of their listeners (TCP 80 and
// 443, UDP 443 with QUIC) needs it. The proxy routes by host name alone, so
// the interface only scopes the listeners.
func releaseSharedSiteListenInterfaces(sites []Site, rules []Rule, ranges []PortRange) []Site {
	out := append([]Site(nil), sites...)
	footprints := collectUserspaceListenerFootprints(rules, ranges, sites)
	tcp := ruleProtocolMask("tcp")
	for i := range out {
		site := &out[i]
		https := tcp
		if site.QUIC {
			https |= ruleProtocolMask("udp")
		}
		if userspaceListenerNeedsInterface(site.ListenIface, site.ListenIP, 80, 80, tcp, footprints) ||
			userspaceListenerNeedsInterface(site.ListenIface, site.ListenIP, 443, 443, https, footprints) {
			continue
		}
		site.ListenIface = ""
	}
	return out
}

// releaseUserspaceListenInterfaces clears the inbound interface of the rules
// and ranges assigned to workers whose listeners can do without it.
func releaseUserspaceListenInterfaces(ruleAssignments [][]Rule, rangeAssignments [][]PortRange, rules []Rule, ranges []PortRange, sites []Site) {
	footprints := collectUserspaceListenerFootprints(rules, ranges, sites)
	for _, assigned := range ruleAssignments {
		for i := range assigned {
			rule := &assigned[i]
			if !userspaceListenerNeedsInterface(rule.InInterface, rule.InIP, rule.InPort, rule.InPort, ruleProtocolMask(rule.Protocol), footprints) {
				rule.InInterface = ""
			}
		}
	}
	for _, assigned := range rangeAssignments {
		for i := range assigned {
			pr := &assigned[i]
			if !userspaceListenerNeedsInterface(pr.InInterface, pr.InIP, pr.StartPort, pr.EndPort, ruleProtocolMask(pr.Protocol), footprints) {
				pr.InInterface = ""
			}
		}
	}
}
