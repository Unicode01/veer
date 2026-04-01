package app

import (
	"fmt"
	"sort"
	"strings"
)

type projectedSiteState struct {
	Site         Site
	ContentScope string
	ContentIndex int
	EnableScope  string
	EnableIndex  int
}

type projectedRangeState struct {
	PortRange    PortRange
	ContentScope string
	ContentIndex int
	EnableScope  string
	EnableIndex  int
}

type projectedListener struct {
	kind         string
	scope        string
	index        int
	id           int64
	field        string
	iface        string
	ip           string
	startPort    int
	endPort      int
	protocolMask int
	label        string
}

func projectExistingRuleStates(rules []Rule) []projectedRuleState {
	if len(rules) == 0 {
		return nil
	}
	out := make([]projectedRuleState, 0, len(rules))
	for _, rule := range rules {
		out = append(out, projectedRuleState{
			Rule:         rule,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		})
	}
	return out
}

func projectExistingSiteStates(sites []Site) []projectedSiteState {
	if len(sites) == 0 {
		return nil
	}
	out := make([]projectedSiteState, 0, len(sites))
	for _, site := range sites {
		out = append(out, projectedSiteState{
			Site:         site,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		})
	}
	return out
}

func projectExistingRangeStates(ranges []PortRange) []projectedRangeState {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]projectedRangeState, 0, len(ranges))
	for _, pr := range ranges {
		out = append(out, projectedRangeState{
			PortRange:    pr,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		})
	}
	return out
}

func detectProjectedConflicts(ruleStates []projectedRuleState, siteStates []projectedSiteState, rangeStates []projectedRangeState) []ruleValidationIssue {
	issues := detectListenerConflicts(buildProjectedListeners(ruleStates, siteStates, rangeStates))
	issues = append(issues, detectSiteDomainConflicts(siteStates)...)
	return issues
}

func buildProjectedListeners(ruleStates []projectedRuleState, siteStates []projectedSiteState, rangeStates []projectedRangeState) []projectedListener {
	listeners := make([]projectedListener, 0, len(ruleStates)+len(siteStates)*2+len(rangeStates))
	for _, state := range ruleStates {
		if !state.Rule.Enabled {
			continue
		}
		scope, index, id, field := ruleConflictIssueTarget(state)
		listeners = append(listeners, projectedListener{
			kind:         "rule",
			scope:        scope,
			index:        index,
			id:           id,
			field:        field,
			iface:        state.Rule.InInterface,
			ip:           state.Rule.InIP,
			startPort:    state.Rule.InPort,
			endPort:      state.Rule.InPort,
			protocolMask: ruleProtocolMask(state.Rule.Protocol),
			label:        describeRuleConflict(state),
		})
	}
	for _, state := range siteStates {
		if !state.Site.Enabled {
			continue
		}
		scope, index, id, field := siteConflictIssueTarget(state)
		if state.Site.BackendHTTP > 0 {
			listeners = append(listeners, projectedListener{
				kind:         "site",
				scope:        scope,
				index:        index,
				id:           id,
				field:        field,
				iface:        state.Site.ListenIface,
				ip:           state.Site.ListenIP,
				startPort:    80,
				endPort:      80,
				protocolMask: ruleProtocolMask("tcp"),
				label:        describeSiteConflict(state, "http"),
			})
		}
		if state.Site.BackendHTTPS > 0 {
			listeners = append(listeners, projectedListener{
				kind:         "site",
				scope:        scope,
				index:        index,
				id:           id,
				field:        field,
				iface:        state.Site.ListenIface,
				ip:           state.Site.ListenIP,
				startPort:    443,
				endPort:      443,
				protocolMask: ruleProtocolMask("tcp"),
				label:        describeSiteConflict(state, "https"),
			})
		}
	}
	for _, state := range rangeStates {
		if !state.PortRange.Enabled {
			continue
		}
		scope, index, id, field := rangeConflictIssueTarget(state)
		listeners = append(listeners, projectedListener{
			kind:         "range",
			scope:        scope,
			index:        index,
			id:           id,
			field:        field,
			iface:        state.PortRange.InInterface,
			ip:           state.PortRange.InIP,
			startPort:    state.PortRange.StartPort,
			endPort:      state.PortRange.EndPort,
			protocolMask: ruleProtocolMask(state.PortRange.Protocol),
			label:        describeRangeConflict(state),
		})
	}
	return listeners
}

func detectListenerConflicts(listeners []projectedListener) []ruleValidationIssue {
	if len(listeners) < 2 {
		return nil
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].startPort != listeners[j].startPort {
			return listeners[i].startPort < listeners[j].startPort
		}
		if listeners[i].endPort != listeners[j].endPort {
			return listeners[i].endPort < listeners[j].endPort
		}
		if listeners[i].ip != listeners[j].ip {
			return listeners[i].ip < listeners[j].ip
		}
		if listeners[i].iface != listeners[j].iface {
			return listeners[i].iface < listeners[j].iface
		}
		if listeners[i].protocolMask != listeners[j].protocolMask {
			return listeners[i].protocolMask < listeners[j].protocolMask
		}
		if listeners[i].kind != listeners[j].kind {
			return listeners[i].kind < listeners[j].kind
		}
		return listeners[i].id < listeners[j].id
	})

	var issues []ruleValidationIssue
	for i := 0; i < len(listeners); i++ {
		for j := i + 1; j < len(listeners); j++ {
			if listeners[j].startPort > listeners[i].endPort {
				break
			}
			if !listenerItemsConflict(listeners[i], listeners[j]) {
				continue
			}
			issues = appendProjectedConflictIssue(issues, listeners[i], listeners[j])
			issues = appendProjectedConflictIssue(issues, listeners[j], listeners[i])
		}
	}
	return issues
}

func listenerItemsConflict(a, b projectedListener) bool {
	if a.kind == "site" && b.kind == "site" {
		return false
	}
	if a.protocolMask&b.protocolMask == 0 {
		return false
	}
	if !ruleInterfacesOverlap(a.iface, b.iface) {
		return false
	}
	if !ruleIPsOverlap(a.ip, b.ip) {
		return false
	}
	return portRangesOverlap(a.startPort, a.endPort, b.startPort, b.endPort)
}

func portRangesOverlap(aStart, aEnd, bStart, bEnd int) bool {
	return aStart <= bEnd && bStart <= aEnd
}

func appendProjectedConflictIssue(issues []ruleValidationIssue, current, other projectedListener) []ruleValidationIssue {
	if current.scope == "" {
		return issues
	}
	return appendRuleIssue(issues, current.scope, current.index, current.id, current.field, fmt.Sprintf("listener conflicts with %s", other.label))
}

func detectSiteDomainConflicts(states []projectedSiteState) []ruleValidationIssue {
	if len(states) < 2 {
		return nil
	}
	type routeKey struct {
		domain string
		kind   string
	}
	byRoute := make(map[routeKey][]projectedSiteState)
	for _, state := range states {
		if !state.Site.Enabled {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(state.Site.Domain))
		if domain == "" {
			continue
		}
		if state.Site.BackendHTTP > 0 {
			byRoute[routeKey{domain: domain, kind: "http"}] = append(byRoute[routeKey{domain: domain, kind: "http"}], state)
		}
		if state.Site.BackendHTTPS > 0 {
			byRoute[routeKey{domain: domain, kind: "https"}] = append(byRoute[routeKey{domain: domain, kind: "https"}], state)
		}
	}

	var issues []ruleValidationIssue
	for key, group := range byRoute {
		if len(group) < 2 {
			continue
		}
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				issues = appendSiteDomainConflictIssue(issues, group[i], group[j], key.kind)
				issues = appendSiteDomainConflictIssue(issues, group[j], group[i], key.kind)
			}
		}
	}
	return issues
}

func appendSiteDomainConflictIssue(issues []ruleValidationIssue, current, other projectedSiteState, kind string) []ruleValidationIssue {
	scope, index, id, _ := siteConflictIssueTarget(current)
	if scope == "" {
		return issues
	}
	return appendRuleIssue(issues, scope, index, id, "domain", fmt.Sprintf("%s route conflicts with %s", strings.ToUpper(kind), describeSiteDomainConflict(other, kind)))
}

func siteConflictIssueTarget(state projectedSiteState) (string, int, int64, string) {
	switch state.ContentScope {
	case "create", "update":
		return state.ContentScope, state.ContentIndex, state.Site.ID, "listen_ip"
	case "existing":
		if state.EnableScope == "toggle" {
			return "toggle", 0, state.Site.ID, "listen_ip"
		}
	}
	return "", 0, 0, ""
}

func rangeConflictIssueTarget(state projectedRangeState) (string, int, int64, string) {
	switch state.ContentScope {
	case "create", "update":
		return state.ContentScope, state.ContentIndex, state.PortRange.ID, "start_port"
	case "existing":
		if state.EnableScope == "toggle" {
			return "toggle", 0, state.PortRange.ID, "start_port"
		}
	}
	return "", 0, 0, ""
}

func describeSiteConflict(state projectedSiteState, kind string) string {
	iface := state.Site.ListenIface
	if iface == "" {
		iface = "*"
	}
	port := 80
	if kind == "https" {
		port = 443
	}
	switch state.ContentScope {
	case "create":
		return fmt.Sprintf("create[%d] site %s %s:%d [TCP] domain=%s", state.ContentIndex, iface, state.Site.ListenIP, port, strings.ToLower(state.Site.Domain))
	default:
		return fmt.Sprintf("site #%d %s %s:%d [TCP] domain=%s", state.Site.ID, iface, state.Site.ListenIP, port, strings.ToLower(state.Site.Domain))
	}
}

func describeSiteDomainConflict(state projectedSiteState, kind string) string {
	switch state.ContentScope {
	case "create":
		return fmt.Sprintf("create[%d] domain=%s [%s]", state.ContentIndex, strings.ToLower(state.Site.Domain), strings.ToUpper(kind))
	default:
		return fmt.Sprintf("site #%d domain=%s [%s]", state.Site.ID, strings.ToLower(state.Site.Domain), strings.ToUpper(kind))
	}
}

func describeRangeConflict(state projectedRangeState) string {
	iface := state.PortRange.InInterface
	if iface == "" {
		iface = "*"
	}
	switch state.ContentScope {
	case "create":
		return fmt.Sprintf("create[%d] %s %s:%d-%d [%s]", state.ContentIndex, iface, state.PortRange.InIP, state.PortRange.StartPort, state.PortRange.EndPort, strings.ToUpper(state.PortRange.Protocol))
	default:
		return fmt.Sprintf("range #%d %s %s:%d-%d [%s]", state.PortRange.ID, iface, state.PortRange.InIP, state.PortRange.StartPort, state.PortRange.EndPort, strings.ToUpper(state.PortRange.Protocol))
	}
}

func loadValidationEntities(db sqlRuleStore) ([]Rule, []Site, []PortRange, error) {
	rules, err := dbGetRules(db)
	if err != nil {
		return nil, nil, nil, err
	}
	sites, err := dbGetSites(db)
	if err != nil {
		return nil, nil, nil, err
	}
	ranges, err := dbGetRanges(db)
	if err != nil {
		return nil, nil, nil, err
	}
	return rules, sites, ranges, nil
}

func prepareSiteCreate(db sqlRuleStore, raw Site) (Site, []ruleValidationIssue, error) {
	knownIfaces, hostAddrs, err := loadHostValidationData()
	if err != nil {
		return raw, nil, err
	}
	site, validationErr := normalizeAndValidateSite(raw, false, knownIfaces, hostAddrs)
	if validationErr != "" {
		return site, []ruleValidationIssue{{Scope: "create", Index: 1, Field: "site", Message: validationErr}}, nil
	}
	site.Enabled = true
	rules, sites, ranges, err := loadValidationEntities(db)
	if err != nil {
		return site, nil, err
	}
	siteStates := projectExistingSiteStates(sites)
	siteStates = append(siteStates, projectedSiteState{
		Site:         site,
		ContentScope: "create",
		ContentIndex: 1,
		EnableScope:  "create",
		EnableIndex:  1,
	})
	return site, detectProjectedConflicts(projectExistingRuleStates(rules), siteStates, projectExistingRangeStates(ranges)), nil
}

func prepareSiteUpdate(db sqlRuleStore, raw Site) (Site, []ruleValidationIssue, error) {
	knownIfaces, hostAddrs, err := loadHostValidationData()
	if err != nil {
		return raw, nil, err
	}
	site, validationErr := normalizeAndValidateSite(raw, true, knownIfaces, hostAddrs)
	if validationErr != "" {
		return site, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: "site", Message: validationErr}}, nil
	}
	rules, sites, ranges, err := loadValidationEntities(db)
	if err != nil {
		return site, nil, err
	}
	siteStates := make([]projectedSiteState, 0, len(sites))
	found := false
	for _, existing := range sites {
		if existing.ID != site.ID {
			siteStates = append(siteStates, projectedSiteState{
				Site:         existing,
				ContentScope: "existing",
				ContentIndex: -1,
				EnableScope:  "existing",
				EnableIndex:  -1,
			})
			continue
		}
		site.Enabled = existing.Enabled
		siteStates = append(siteStates, projectedSiteState{
			Site:         site,
			ContentScope: "update",
			ContentIndex: 1,
			EnableScope:  "update",
			EnableIndex:  1,
		})
		found = true
	}
	if !found {
		return site, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: "id", Message: "site not found"}}, nil
	}
	return site, detectProjectedConflicts(projectExistingRuleStates(rules), siteStates, projectExistingRangeStates(ranges)), nil
}

func prepareSiteToggle(db sqlRuleStore, id int64) (Site, []ruleValidationIssue, error) {
	rules, sites, ranges, err := loadValidationEntities(db)
	if err != nil {
		return Site{}, nil, err
	}
	siteStates := make([]projectedSiteState, 0, len(sites))
	var target Site
	found := false
	for _, existing := range sites {
		if existing.ID != id {
			siteStates = append(siteStates, projectedSiteState{
				Site:         existing,
				ContentScope: "existing",
				ContentIndex: -1,
				EnableScope:  "existing",
				EnableIndex:  -1,
			})
			continue
		}
		target = existing
		target.Enabled = !existing.Enabled
		siteStates = append(siteStates, projectedSiteState{
			Site:         target,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "toggle",
			EnableIndex:  0,
		})
		found = true
	}
	if !found {
		return Site{}, []ruleValidationIssue{{Scope: "toggle", ID: id, Field: "id", Message: "site not found"}}, nil
	}
	return target, detectProjectedConflicts(projectExistingRuleStates(rules), siteStates, projectExistingRangeStates(ranges)), nil
}

func prepareRangeCreate(db sqlRuleStore, raw PortRange) (PortRange, []ruleValidationIssue, error) {
	knownIfaces, hostAddrs, err := loadHostValidationData()
	if err != nil {
		return raw, nil, err
	}
	pr, validationErr := normalizeAndValidateRange(raw, false, knownIfaces, hostAddrs)
	if validationErr != "" {
		return pr, []ruleValidationIssue{{Scope: "create", Index: 1, Field: "range", Message: validationErr}}, nil
	}
	pr.Enabled = true
	rules, sites, ranges, err := loadValidationEntities(db)
	if err != nil {
		return pr, nil, err
	}
	rangeStates := projectExistingRangeStates(ranges)
	rangeStates = append(rangeStates, projectedRangeState{
		PortRange:    pr,
		ContentScope: "create",
		ContentIndex: 1,
		EnableScope:  "create",
		EnableIndex:  1,
	})
	return pr, detectProjectedConflicts(projectExistingRuleStates(rules), projectExistingSiteStates(sites), rangeStates), nil
}

func prepareRangeUpdate(db sqlRuleStore, raw PortRange) (PortRange, []ruleValidationIssue, error) {
	knownIfaces, hostAddrs, err := loadHostValidationData()
	if err != nil {
		return raw, nil, err
	}
	pr, validationErr := normalizeAndValidateRange(raw, true, knownIfaces, hostAddrs)
	if validationErr != "" {
		return pr, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: "range", Message: validationErr}}, nil
	}
	rules, sites, ranges, err := loadValidationEntities(db)
	if err != nil {
		return pr, nil, err
	}
	rangeStates := make([]projectedRangeState, 0, len(ranges))
	found := false
	for _, existing := range ranges {
		if existing.ID != pr.ID {
			rangeStates = append(rangeStates, projectedRangeState{
				PortRange:    existing,
				ContentScope: "existing",
				ContentIndex: -1,
				EnableScope:  "existing",
				EnableIndex:  -1,
			})
			continue
		}
		pr.Enabled = existing.Enabled
		rangeStates = append(rangeStates, projectedRangeState{
			PortRange:    pr,
			ContentScope: "update",
			ContentIndex: 1,
			EnableScope:  "update",
			EnableIndex:  1,
		})
		found = true
	}
	if !found {
		return pr, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: "id", Message: "range not found"}}, nil
	}
	return pr, detectProjectedConflicts(projectExistingRuleStates(rules), projectExistingSiteStates(sites), rangeStates), nil
}

func prepareRangeToggle(db sqlRuleStore, id int64) (PortRange, []ruleValidationIssue, error) {
	rules, sites, ranges, err := loadValidationEntities(db)
	if err != nil {
		return PortRange{}, nil, err
	}
	rangeStates := make([]projectedRangeState, 0, len(ranges))
	var target PortRange
	found := false
	for _, existing := range ranges {
		if existing.ID != id {
			rangeStates = append(rangeStates, projectedRangeState{
				PortRange:    existing,
				ContentScope: "existing",
				ContentIndex: -1,
				EnableScope:  "existing",
				EnableIndex:  -1,
			})
			continue
		}
		target = existing
		target.Enabled = !existing.Enabled
		rangeStates = append(rangeStates, projectedRangeState{
			PortRange:    target,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "toggle",
			EnableIndex:  0,
		})
		found = true
	}
	if !found {
		return PortRange{}, []ruleValidationIssue{{Scope: "toggle", ID: id, Field: "id", Message: "range not found"}}, nil
	}
	return target, detectProjectedConflicts(projectExistingRuleStates(rules), projectExistingSiteStates(sites), rangeStates), nil
}

func hasValidationMessage(issues []ruleValidationIssue, message string) bool {
	for _, issue := range issues {
		if issue.Message == message {
			return true
		}
	}
	return false
}
