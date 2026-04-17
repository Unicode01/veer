package app

import (
	"database/sql"
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

func loadEnabledValidationEntities(db sqlRuleStore) ([]Rule, []Site, []PortRange, error) {
	rules, err := dbGetEnabledRules(db)
	if err != nil {
		return nil, nil, nil, err
	}
	sites, err := dbGetEnabledSites(db)
	if err != nil {
		return nil, nil, nil, err
	}
	ranges, err := dbGetEnabledRanges(db)
	if err != nil {
		return nil, nil, nil, err
	}
	return rules, sites, ranges, nil
}

func loadValidationInterfaceData() (map[string]struct{}, map[string]InterfaceInfo, hostInterfaceAddrs, error) {
	knownIfaces, hostAddrs, err := loadHostValidationData()
	if err != nil {
		return nil, nil, nil, err
	}
	items, err := loadInterfaceInfos()
	if err != nil {
		return nil, nil, nil, err
	}
	return knownIfaces, buildInterfaceInfoMap(items), hostAddrs, nil
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
	rules, sites, ranges, err := loadEnabledValidationEntities(db)
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
	rules, sites, ranges, err := loadEnabledValidationEntities(db)
	if err != nil {
		return site, nil, err
	}
	current, err := dbGetSite(db, site.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return site, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: "id", Message: "site not found"}}, nil
		}
		return site, nil, err
	}
	site.Enabled = current.Enabled

	siteStates := make([]projectedSiteState, 0, len(sites))
	for _, existing := range sites {
		if existing.ID == site.ID {
			continue
		}
		siteStates = append(siteStates, projectedSiteState{
			Site:         existing,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		})
	}
	siteStates = append(siteStates, projectedSiteState{
		Site:         site,
		ContentScope: "update",
		ContentIndex: 1,
		EnableScope:  "update",
		EnableIndex:  1,
	})
	return site, detectProjectedConflicts(projectExistingRuleStates(rules), siteStates, projectExistingRangeStates(ranges)), nil
}

func prepareSiteToggle(db sqlRuleStore, id int64) (Site, []ruleValidationIssue, error) {
	rules, sites, ranges, err := loadEnabledValidationEntities(db)
	if err != nil {
		return Site{}, nil, err
	}
	current, err := dbGetSite(db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return Site{}, []ruleValidationIssue{{Scope: "toggle", ID: id, Field: "id", Message: "site not found"}}, nil
		}
		return Site{}, nil, err
	}

	siteStates := make([]projectedSiteState, 0, len(sites))
	for _, existing := range sites {
		if existing.ID == id {
			continue
		}
		siteStates = append(siteStates, projectedSiteState{
			Site:         existing,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		})
	}

	target := *current
	target.Enabled = !current.Enabled
	siteStates = append(siteStates, projectedSiteState{
		Site:         target,
		ContentScope: "existing",
		ContentIndex: -1,
		EnableScope:  "toggle",
		EnableIndex:  0,
	})
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
	rules, sites, ranges, err := loadEnabledValidationEntities(db)
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
	rules, sites, ranges, err := loadEnabledValidationEntities(db)
	if err != nil {
		return pr, nil, err
	}
	current, err := dbGetRange(db, pr.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return pr, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: "id", Message: "range not found"}}, nil
		}
		return pr, nil, err
	}
	pr.Enabled = current.Enabled

	rangeStates := make([]projectedRangeState, 0, len(ranges))
	for _, existing := range ranges {
		if existing.ID == pr.ID {
			continue
		}
		rangeStates = append(rangeStates, projectedRangeState{
			PortRange:    existing,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		})
	}
	rangeStates = append(rangeStates, projectedRangeState{
		PortRange:    pr,
		ContentScope: "update",
		ContentIndex: 1,
		EnableScope:  "update",
		EnableIndex:  1,
	})
	return pr, detectProjectedConflicts(projectExistingRuleStates(rules), projectExistingSiteStates(sites), rangeStates), nil
}

func prepareRangeToggle(db sqlRuleStore, id int64) (PortRange, []ruleValidationIssue, error) {
	rules, sites, ranges, err := loadEnabledValidationEntities(db)
	if err != nil {
		return PortRange{}, nil, err
	}
	current, err := dbGetRange(db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return PortRange{}, []ruleValidationIssue{{Scope: "toggle", ID: id, Field: "id", Message: "range not found"}}, nil
		}
		return PortRange{}, nil, err
	}

	rangeStates := make([]projectedRangeState, 0, len(ranges))
	for _, existing := range ranges {
		if existing.ID == id {
			continue
		}
		rangeStates = append(rangeStates, projectedRangeState{
			PortRange:    existing,
			ContentScope: "existing",
			ContentIndex: -1,
			EnableScope:  "existing",
			EnableIndex:  -1,
		})
	}

	target := *current
	target.Enabled = !current.Enabled
	rangeStates = append(rangeStates, projectedRangeState{
		PortRange:    target,
		ContentScope: "existing",
		ContentIndex: -1,
		EnableScope:  "toggle",
		EnableIndex:  0,
	})
	return target, detectProjectedConflicts(projectExistingRuleStates(rules), projectExistingSiteStates(sites), rangeStates), nil
}

func normalizeAndValidateEgressNAT(raw EgressNAT, requireID bool, knownIfaces map[string]struct{}, ifaceByName map[string]InterfaceInfo, hostAddrs hostInterfaceAddrs) (EgressNAT, string) {
	raw.ParentInterface = strings.TrimSpace(raw.ParentInterface)
	raw.ChildInterface = strings.TrimSpace(raw.ChildInterface)
	raw.OutInterface = strings.TrimSpace(raw.OutInterface)
	raw.OutSourceIP = strings.TrimSpace(raw.OutSourceIP)
	raw.Protocol = normalizeEgressNATProtocol(raw.Protocol)
	raw.NATType = normalizeEgressNATType(raw.NATType)
	if raw.ChildInterface == "*" {
		raw.ChildInterface = ""
	}

	if requireID && raw.ID <= 0 {
		return raw, "id is required"
	}
	if !requireID && raw.ID != 0 {
		return raw, "id must be omitted when creating an egress nat"
	}
	if raw.ParentInterface == "" || raw.OutInterface == "" {
		return raw, "parent_interface and out_interface are required"
	}
	if !isValidEgressNATProtocol(raw.Protocol) {
		return raw, "protocol must include one or more of tcp, udp, icmp"
	}
	if !isValidEgressNATType(raw.NATType) {
		return raw, "nat_type must be symmetric or full_cone"
	}
	if egressNATUsesSingleTargetParent(raw, ifaceByName) && raw.ParentInterface == raw.OutInterface {
		return raw, "parent_interface must be different from out_interface when selecting a single target interface"
	}
	raw = normalizeEgressNATScope(raw, ifaceByName)
	if raw.ChildInterface != "" && raw.ChildInterface == raw.OutInterface {
		return raw, "child_interface must be different from out_interface"
	}
	if _, ok := knownIfaces[raw.ParentInterface]; !ok {
		return raw, "parent_interface does not exist on this host"
	}
	if _, ok := knownIfaces[raw.OutInterface]; !ok {
		return raw, "out_interface does not exist on this host"
	}
	if raw.ChildInterface != "" {
		childInfo, ok := ifaceByName[raw.ChildInterface]
		if !ok {
			return raw, "child_interface does not exist on this host"
		}
		if strings.TrimSpace(childInfo.Parent) != raw.ParentInterface {
			return raw, "child_interface is not attached to the selected parent_interface"
		}
	}
	normalizedSourceIP, err := normalizeOptionalSpecificIP(raw.OutSourceIP)
	if err != nil {
		return raw, "out_source_ip " + err.Error()
	}
	raw.OutSourceIP = normalizedSourceIP
	if raw.OutSourceIP != "" {
		if ipLiteralFamily(raw.OutSourceIP) != ipFamilyIPv4 {
			return raw, "out_source_ip must be a valid IPv4 address"
		}
		if msg := validateLocalSourceIP(raw.OutSourceIP, raw.OutInterface, hostAddrs); msg != "" {
			return raw, "out_source_ip " + msg
		}
	}
	return raw, ""
}

func egressNATValidationField(message string) string {
	text := strings.TrimSpace(message)
	for _, prefix := range []string{"id ", "parent_interface ", "child_interface ", "out_interface ", "out_source_ip ", "protocol ", "nat_type "} {
		if strings.HasPrefix(text, prefix) {
			return strings.TrimSpace(strings.TrimSuffix(prefix, " "))
		}
	}
	switch text {
	case "id is required", "id must be omitted when creating an egress nat":
		return "id"
	case "parent_interface must be different from out_interface when selecting a single target interface":
		return "parent_interface"
	default:
		return "egress_nat"
	}
}

type egressNATScopeDescriptor struct {
	Parent   string
	Target   string
	Wildcard bool
}

func describeEgressNATScope(item EgressNAT, ifaceByName map[string]InterfaceInfo) egressNATScopeDescriptor {
	item = normalizeEgressNATScope(item, ifaceByName)
	parentName := strings.TrimSpace(item.ParentInterface)
	childName := strings.TrimSpace(item.ChildInterface)
	if childName != "" {
		return egressNATScopeDescriptor{
			Parent:   parentName,
			Target:   childName,
			Wildcard: false,
		}
	}
	return egressNATScopeDescriptor{
		Parent:   parentName,
		Wildcard: true,
	}
}

func egressNATScopesOverlap(a, b EgressNAT, ifaceByName map[string]InterfaceInfo) bool {
	scopeA := describeEgressNATScope(a, ifaceByName)
	scopeB := describeEgressNATScope(b, ifaceByName)
	if scopeA.Parent == "" || scopeB.Parent == "" {
		return false
	}
	if scopeA.Wildcard {
		if scopeB.Wildcard {
			return scopeA.Parent == scopeB.Parent
		}
		return scopeA.Parent == scopeB.Parent
	}
	if scopeB.Wildcard {
		return scopeA.Parent == scopeB.Parent
	}
	return scopeA.Target != "" && scopeA.Target == scopeB.Target
}

func validateProjectedEgressNATs(items []EgressNAT, ifaceByName map[string]InterfaceInfo, scope string, id int64) []ruleValidationIssue {
	if len(items) == 0 {
		return nil
	}
	targetIndex := -1
	for i, item := range items {
		if scope == "create" && item.ID == 0 {
			targetIndex = i
			break
		}
		if scope != "create" && item.ID == id {
			targetIndex = i
			break
		}
	}
	if targetIndex < 0 {
		return nil
	}

	target := items[targetIndex]
	if !target.Enabled {
		return nil
	}
	field := "child_interface"
	if strings.TrimSpace(target.ChildInterface) == "" {
		field = "parent_interface"
	}

	for i, other := range items {
		if i == targetIndex || !other.Enabled {
			continue
		}
		if !ruleProtocolsOverlap(normalizeEgressNATProtocol(target.Protocol), normalizeEgressNATProtocol(other.Protocol)) {
			continue
		}
		if !egressNATScopesOverlap(target, other, ifaceByName) {
			continue
		}
		return []ruleValidationIssue{{
			Scope:   scope,
			ID:      id,
			Field:   field,
			Message: fmt.Sprintf("egress nat scope conflicts with egress nat #%d", other.ID),
		}}
	}
	return nil
}

func prepareEgressNATCreate(db sqlRuleStore, raw EgressNAT) (EgressNAT, []ruleValidationIssue, error) {
	knownIfaces, ifaceByName, hostAddrs, err := loadValidationInterfaceData()
	if err != nil {
		return raw, nil, err
	}
	item, validationErr := normalizeAndValidateEgressNAT(raw, false, knownIfaces, ifaceByName, hostAddrs)
	if validationErr != "" {
		return item, []ruleValidationIssue{{Scope: "create", Index: 1, Field: egressNATValidationField(validationErr), Message: validationErr}}, nil
	}
	item.Enabled = true

	existing, err := dbGetEnabledEgressNATs(db)
	if err != nil {
		return item, nil, err
	}
	projected := append(existing, item)
	return item, validateProjectedEgressNATs(projected, ifaceByName, "create", 0), nil
}

func prepareEgressNATUpdate(db sqlRuleStore, raw EgressNAT) (EgressNAT, []ruleValidationIssue, error) {
	knownIfaces, ifaceByName, hostAddrs, err := loadValidationInterfaceData()
	if err != nil {
		return raw, nil, err
	}
	item, validationErr := normalizeAndValidateEgressNAT(raw, true, knownIfaces, ifaceByName, hostAddrs)
	if validationErr != "" {
		return item, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: egressNATValidationField(validationErr), Message: validationErr}}, nil
	}

	existing, err := dbGetEnabledEgressNATs(db)
	if err != nil {
		return item, nil, err
	}
	current, err := dbGetEgressNAT(db, item.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return item, []ruleValidationIssue{{Scope: "update", Index: 1, ID: raw.ID, Field: "id", Message: "egress nat not found"}}, nil
		}
		return item, nil, err
	}
	item.Enabled = current.Enabled

	projected := make([]EgressNAT, 0, len(existing)+1)
	for _, current := range existing {
		if current.ID != item.ID {
			projected = append(projected, current)
		}
	}
	projected = append(projected, item)
	return item, validateProjectedEgressNATs(projected, ifaceByName, "update", item.ID), nil
}

func prepareEgressNATToggle(db sqlRuleStore, id int64) (EgressNAT, []ruleValidationIssue, error) {
	_, ifaceByName, _, err := loadValidationInterfaceData()
	if err != nil {
		return EgressNAT{}, nil, err
	}
	items, err := dbGetEnabledEgressNATs(db)
	if err != nil {
		return EgressNAT{}, nil, err
	}
	current, err := dbGetEgressNAT(db, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return EgressNAT{}, []ruleValidationIssue{{Scope: "toggle", ID: id, Field: "id", Message: "egress nat not found"}}, nil
		}
		return EgressNAT{}, nil, err
	}

	projected := make([]EgressNAT, 0, len(items)+1)
	for _, item := range items {
		if item.ID == id {
			continue
		}
		projected = append(projected, item)
	}
	target := *current
	target.Enabled = !current.Enabled
	projected = append(projected, target)
	return target, validateProjectedEgressNATs(projected, ifaceByName, "toggle", id), nil
}

func hasValidationMessage(issues []ruleValidationIssue, message string) bool {
	for _, issue := range issues {
		if issue.Message == message {
			return true
		}
	}
	return false
}
