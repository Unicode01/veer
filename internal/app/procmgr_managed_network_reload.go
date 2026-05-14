package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"
)

var loadIPv6AssignmentsForManagedNetworkReload = dbGetIPv6Assignments

type managedNetworkRuntimeReloadFingerprint struct {
	ManagedNetworks         []managedNetworkRuntimeReloadFingerprintNetwork             `json:"managed_networks,omitempty"`
	Reservations            []managedNetworkRuntimeReloadFingerprintReservation         `json:"reservations,omitempty"`
	IPv6Assignments         []managedNetworkRuntimeReloadFingerprintIPv6Assign          `json:"ipv6_assignments,omitempty"`
	EgressNATs              []managedNetworkRuntimeReloadFingerprintEgressNAT           `json:"egress_nats,omitempty"`
	DynamicSourceInterfaces []managedNetworkRuntimeReloadFingerprintDynamicSourceTarget `json:"dynamic_source_interfaces,omitempty"`
}

type managedNetworkRuntimeReloadFingerprintNetwork struct {
	ID                  int64  `json:"id"`
	BridgeMode          string `json:"bridge_mode,omitempty"`
	Bridge              string `json:"bridge,omitempty"`
	BridgeMTU           int    `json:"bridge_mtu,omitempty"`
	BridgeVLANAware     bool   `json:"bridge_vlan_aware,omitempty"`
	UplinkInterface     string `json:"uplink_interface,omitempty"`
	IPv4Enabled         bool   `json:"ipv4_enabled,omitempty"`
	IPv4CIDR            string `json:"ipv4_cidr,omitempty"`
	IPv4Gateway         string `json:"ipv4_gateway,omitempty"`
	IPv4PoolStart       string `json:"ipv4_pool_start,omitempty"`
	IPv4PoolEnd         string `json:"ipv4_pool_end,omitempty"`
	IPv4DNSServers      string `json:"ipv4_dns_servers,omitempty"`
	IPv6Enabled         bool   `json:"ipv6_enabled,omitempty"`
	IPv6ParentInterface string `json:"ipv6_parent_interface,omitempty"`
	IPv6ParentPrefix    string `json:"ipv6_parent_prefix,omitempty"`
	IPv6AssignmentMode  string `json:"ipv6_assignment_mode,omitempty"`
	AutoEgressNAT       bool   `json:"auto_egress_nat,omitempty"`
	Enabled             bool   `json:"enabled,omitempty"`
}

type managedNetworkRuntimeReloadFingerprintReservation struct {
	ManagedNetworkID int64  `json:"managed_network_id"`
	MACAddress       string `json:"mac_address,omitempty"`
	IPv4Address      string `json:"ipv4_address,omitempty"`
}

type managedNetworkRuntimeReloadFingerprintIPv6Assign struct {
	ParentInterface string `json:"parent_interface,omitempty"`
	TargetInterface string `json:"target_interface,omitempty"`
	ParentPrefix    string `json:"parent_prefix,omitempty"`
	AssignedPrefix  string `json:"assigned_prefix,omitempty"`
	Address         string `json:"address,omitempty"`
	PrefixLen       int    `json:"prefix_len,omitempty"`
	Enabled         bool   `json:"enabled,omitempty"`
}

type managedNetworkRuntimeReloadFingerprintEgressNAT struct {
	ParentInterface string `json:"parent_interface,omitempty"`
	ChildInterface  string `json:"child_interface,omitempty"`
	OutInterface    string `json:"out_interface,omitempty"`
	OutSourceIP     string `json:"out_source_ip,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	NATType         string `json:"nat_type,omitempty"`
	Enabled         bool   `json:"enabled,omitempty"`
}

type managedNetworkRuntimeReloadFingerprintDynamicSourceTarget struct {
	Interface string   `json:"interface,omitempty"`
	IPv4Addrs []string `json:"ipv4_addrs,omitempty"`
}

func buildManagedNetworkRuntimeReloadFingerprint(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation, effectiveIPv6Assignments []IPv6Assignment, effectiveEgressNATs []EgressNAT, ifaceInfos []InterfaceInfo) string {
	payload := managedNetworkRuntimeReloadFingerprint{
		ManagedNetworks:         managedNetworkRuntimeReloadFingerprintNetworks(managedNetworks),
		Reservations:            managedNetworkRuntimeReloadFingerprintReservations(reservations),
		IPv6Assignments:         managedNetworkRuntimeReloadFingerprintIPv6Assignments(effectiveIPv6Assignments),
		EgressNATs:              managedNetworkRuntimeReloadFingerprintEgressNATs(effectiveEgressNATs),
		DynamicSourceInterfaces: managedNetworkRuntimeReloadFingerprintDynamicSourceInterfaces(effectiveEgressNATs, ifaceInfos),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func managedNetworkRuntimeReloadFingerprintNetworks(items []ManagedNetwork) []managedNetworkRuntimeReloadFingerprintNetwork {
	if len(items) == 0 {
		return nil
	}
	out := make([]managedNetworkRuntimeReloadFingerprintNetwork, 0, len(items))
	for _, item := range items {
		item = normalizeManagedNetwork(item)
		out = append(out, managedNetworkRuntimeReloadFingerprintNetwork{
			ID:                  item.ID,
			BridgeMode:          item.BridgeMode,
			Bridge:              item.Bridge,
			BridgeMTU:           item.BridgeMTU,
			BridgeVLANAware:     item.BridgeVLANAware,
			UplinkInterface:     item.UplinkInterface,
			IPv4Enabled:         item.IPv4Enabled,
			IPv4CIDR:            item.IPv4CIDR,
			IPv4Gateway:         item.IPv4Gateway,
			IPv4PoolStart:       item.IPv4PoolStart,
			IPv4PoolEnd:         item.IPv4PoolEnd,
			IPv4DNSServers:      item.IPv4DNSServers,
			IPv6Enabled:         item.IPv6Enabled,
			IPv6ParentInterface: item.IPv6ParentInterface,
			IPv6ParentPrefix:    item.IPv6ParentPrefix,
			IPv6AssignmentMode:  item.IPv6AssignmentMode,
			AutoEgressNAT:       item.AutoEgressNAT,
			Enabled:             item.Enabled,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Bridge != out[j].Bridge {
			return out[i].Bridge < out[j].Bridge
		}
		return out[i].UplinkInterface < out[j].UplinkInterface
	})
	return out
}

func managedNetworkRuntimeReloadFingerprintReservations(items []ManagedNetworkReservation) []managedNetworkRuntimeReloadFingerprintReservation {
	if len(items) == 0 {
		return nil
	}
	out := make([]managedNetworkRuntimeReloadFingerprintReservation, 0, len(items))
	for _, item := range items {
		out = append(out, managedNetworkRuntimeReloadFingerprintReservation{
			ManagedNetworkID: item.ManagedNetworkID,
			MACAddress:       strings.TrimSpace(item.MACAddress),
			IPv4Address:      strings.TrimSpace(item.IPv4Address),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ManagedNetworkID != out[j].ManagedNetworkID {
			return out[i].ManagedNetworkID < out[j].ManagedNetworkID
		}
		if out[i].MACAddress != out[j].MACAddress {
			return out[i].MACAddress < out[j].MACAddress
		}
		return out[i].IPv4Address < out[j].IPv4Address
	})
	return out
}

func managedNetworkRuntimeReloadFingerprintIPv6Assignments(items []IPv6Assignment) []managedNetworkRuntimeReloadFingerprintIPv6Assign {
	if len(items) == 0 {
		return nil
	}
	out := make([]managedNetworkRuntimeReloadFingerprintIPv6Assign, 0, len(items))
	for _, item := range items {
		out = append(out, managedNetworkRuntimeReloadFingerprintIPv6Assign{
			ParentInterface: strings.TrimSpace(item.ParentInterface),
			TargetInterface: strings.TrimSpace(item.TargetInterface),
			ParentPrefix:    strings.TrimSpace(item.ParentPrefix),
			AssignedPrefix:  strings.TrimSpace(item.AssignedPrefix),
			Address:         strings.TrimSpace(item.Address),
			PrefixLen:       item.PrefixLen,
			Enabled:         item.Enabled,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ParentInterface != out[j].ParentInterface {
			return out[i].ParentInterface < out[j].ParentInterface
		}
		if out[i].TargetInterface != out[j].TargetInterface {
			return out[i].TargetInterface < out[j].TargetInterface
		}
		if out[i].AssignedPrefix != out[j].AssignedPrefix {
			return out[i].AssignedPrefix < out[j].AssignedPrefix
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].ParentPrefix < out[j].ParentPrefix
	})
	return out
}

func managedNetworkRuntimeReloadFingerprintEgressNATs(items []EgressNAT) []managedNetworkRuntimeReloadFingerprintEgressNAT {
	if len(items) == 0 {
		return nil
	}
	out := make([]managedNetworkRuntimeReloadFingerprintEgressNAT, 0, len(items))
	for _, item := range items {
		out = append(out, managedNetworkRuntimeReloadFingerprintEgressNAT{
			ParentInterface: strings.TrimSpace(item.ParentInterface),
			ChildInterface:  strings.TrimSpace(item.ChildInterface),
			OutInterface:    strings.TrimSpace(item.OutInterface),
			OutSourceIP:     strings.TrimSpace(item.OutSourceIP),
			Protocol:        normalizeEgressNATProtocol(item.Protocol),
			NATType:         normalizeEgressNATType(item.NATType),
			Enabled:         item.Enabled,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ParentInterface != out[j].ParentInterface {
			return out[i].ParentInterface < out[j].ParentInterface
		}
		if out[i].ChildInterface != out[j].ChildInterface {
			return out[i].ChildInterface < out[j].ChildInterface
		}
		if out[i].OutInterface != out[j].OutInterface {
			return out[i].OutInterface < out[j].OutInterface
		}
		if out[i].OutSourceIP != out[j].OutSourceIP {
			return out[i].OutSourceIP < out[j].OutSourceIP
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].NATType < out[j].NATType
	})
	return out
}

func managedNetworkRuntimeReloadFingerprintDynamicSourceInterfaces(items []EgressNAT, infos []InterfaceInfo) []managedNetworkRuntimeReloadFingerprintDynamicSourceTarget {
	if len(items) == 0 {
		return nil
	}

	targets := make(map[string]struct{})
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		if strings.TrimSpace(item.OutSourceIP) != "" {
			continue
		}
		outInterface := strings.TrimSpace(item.OutInterface)
		if outInterface == "" {
			continue
		}
		targets[outInterface] = struct{}{}
	}
	if len(targets) == 0 {
		return nil
	}

	ifaceByName := buildInterfaceInfoMap(infos)
	out := make([]managedNetworkRuntimeReloadFingerprintDynamicSourceTarget, 0, len(targets))
	for name := range targets {
		target := managedNetworkRuntimeReloadFingerprintDynamicSourceTarget{Interface: name}
		if info, ok := ifaceByName[name]; ok {
			addrs := make([]string, 0, len(info.Addrs))
			for _, addr := range info.Addrs {
				ip := net.ParseIP(strings.TrimSpace(addr))
				if ip == nil || ip.To4() == nil {
					continue
				}
				addrs = append(addrs, canonicalIPLiteral(ip))
			}
			if len(addrs) > 0 {
				sort.Strings(addrs)
				target.IPv4Addrs = addrs
			}
		}
		out = append(out, target)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Interface < out[j].Interface
	})
	return out
}

func (pm *ProcessManager) requestManagedNetworkRuntimeReload(delay time.Duration, names ...string) {
	pm.requestManagedNetworkRuntimeReloadWithSource(delay, "", names...)
}

func (pm *ProcessManager) requestManagedNetworkRuntimeReloadWithSource(delay time.Duration, source string, names ...string) {
	if pm == nil {
		return
	}
	if delay < 0 {
		delay = 0
	}
	dueAt := time.Now().Add(delay)

	pm.mu.Lock()
	if pm.shuttingDown {
		pm.mu.Unlock()
		return
	}
	switch {
	case !pm.managedRuntimeReloadPending:
		pm.managedRuntimeReloadDueAt = dueAt
	case delay <= 0:
		if pm.managedRuntimeReloadDueAt.IsZero() || dueAt.Before(pm.managedRuntimeReloadDueAt) {
			pm.managedRuntimeReloadDueAt = dueAt
		}
	default:
		if pm.managedRuntimeReloadDueAt.IsZero() || dueAt.After(pm.managedRuntimeReloadDueAt) {
			pm.managedRuntimeReloadDueAt = dueAt
		}
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if pm.managedRuntimeReloadInterfaces == nil {
			pm.managedRuntimeReloadInterfaces = make(map[string]struct{})
		}
		pm.managedRuntimeReloadInterfaces[name] = struct{}{}
	}
	pm.managedRuntimeReloadPending = true
	pm.managedRuntimeReloadLastRequestedAt = time.Now()
	pm.managedRuntimeReloadLastRequestSource = normalizeManagedNetworkRuntimeReloadSource(source)
	pm.managedRuntimeReloadLastRequestSummary = summarizeManagedRuntimeReloadInterfaces(pm.managedRuntimeReloadInterfaces)
	wake := pm.managedRuntimeReloadWake
	pm.mu.Unlock()

	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (pm *ProcessManager) markManagedNetworkRuntimeReloadStarted() {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	pm.managedRuntimeReloadLastStartedAt = time.Now()
	pm.managedRuntimeReloadLastCompletedAt = time.Time{}
	pm.managedRuntimeReloadLastResult = ""
	pm.managedRuntimeReloadLastAppliedSummary = ""
	pm.managedRuntimeReloadLastError = ""
	pm.mu.Unlock()
}

func (pm *ProcessManager) markManagedNetworkRuntimeReloadCompleted(result string, appliedSummary string, err error) {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	pm.managedRuntimeReloadLastCompletedAt = time.Now()
	pm.managedRuntimeReloadLastResult = strings.TrimSpace(result)
	pm.managedRuntimeReloadLastAppliedSummary = strings.TrimSpace(appliedSummary)
	if err != nil {
		pm.managedRuntimeReloadLastError = err.Error()
	} else {
		pm.managedRuntimeReloadLastError = ""
	}
	pm.mu.Unlock()
}

func (pm *ProcessManager) shouldSkipManagedNetworkAddrReload(fingerprint string) bool {
	if pm == nil || strings.TrimSpace(fingerprint) == "" {
		return false
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.managedRuntimeReloadAppliedFingerprint != "" && pm.managedRuntimeReloadAppliedFingerprint == fingerprint
}

func (pm *ProcessManager) detectManagedNetworkRuntimeDrift() {
	if pm == nil || pm.db == nil {
		return
	}

	pm.mu.Lock()
	hasManagedRuntime := len(pm.managedNetworkInterfaces) > 0 || pm.ipv6AssignmentsConfigured
	pending := pm.managedRuntimeReloadPending
	appliedFingerprint := strings.TrimSpace(pm.managedRuntimeReloadAppliedFingerprint)
	shuttingDown := pm.shuttingDown
	pm.mu.Unlock()

	if shuttingDown || pending || !hasManagedRuntime || appliedFingerprint == "" {
		return
	}

	currentFingerprint, touchedInterfaces, err := pm.currentManagedNetworkRuntimeFingerprint()
	if err != nil {
		log.Printf("managed network runtime: drift check skipped: %v", err)
		return
	}
	currentFingerprint = strings.TrimSpace(currentFingerprint)
	if currentFingerprint == "" || currentFingerprint == appliedFingerprint {
		return
	}

	if summary := summarizeManagedRuntimeReloadInterfaces(sliceToManagedNetworkInterfaceSet(touchedInterfaces)); summary != "" {
		log.Printf("managed network runtime: detected effective state drift on %s, queueing targeted reload", summary)
	} else {
		log.Printf("managed network runtime: detected effective state drift, queueing targeted reload")
	}
	pm.requestManagedNetworkRuntimeReloadWithSource(0, "drift_check", touchedInterfaces...)
}

func (pm *ProcessManager) currentManagedNetworkRuntimeFingerprint() (string, []string, error) {
	if pm == nil || pm.db == nil {
		return "", nil, nil
	}

	managedNetworks, err := dbGetManagedNetworks(pm.db)
	if err != nil {
		return "", nil, fmt.Errorf("load managed networks: %w", err)
	}
	managedNetworkReservations, err := dbGetManagedNetworkReservations(pm.db)
	if err != nil {
		return "", nil, fmt.Errorf("load managed network reservations: %w", err)
	}
	explicitEgressNATs, err := dbGetEgressNATs(pm.db)
	if err != nil {
		return "", nil, fmt.Errorf("load egress nats: %w", err)
	}
	ipv6Assignments, err := loadIPv6AssignmentsForManagedNetworkReload(pm.db)
	if err != nil {
		return "", nil, fmt.Errorf("load ipv6 assignments: %w", err)
	}

	egressNATSnapshot := loadEgressNATInterfaceSnapshot()
	if egressNATSnapshot.Err != nil {
		return "", nil, fmt.Errorf("load interface inventory: %w", egressNATSnapshot.Err)
	}
	explicitEgressNATs = normalizeEgressNATItemsWithSnapshot(explicitEgressNATs, egressNATSnapshot)
	managedNetworkCompiled := compileManagedNetworkRuntime(managedNetworks, ipv6Assignments, explicitEgressNATs, egressNATSnapshot.Infos)

	effectiveIPv6Assignments := append([]IPv6Assignment(nil), ipv6Assignments...)
	if len(managedNetworkCompiled.IPv6Assignments) > 0 {
		effectiveIPv6Assignments = append(effectiveIPv6Assignments, managedNetworkCompiled.IPv6Assignments...)
	}
	if len(effectiveIPv6Assignments) > 0 {
		hostIfaces, err := loadIPv6AssignmentHostNetworkInterfaces()
		if err != nil {
			return "", nil, fmt.Errorf("load host interfaces for ipv6 resolution: %w", err)
		}
		resolvedAssignments, warnings := resolveIPv6AssignmentsForCurrentHost(effectiveIPv6Assignments, buildHostNetworkInterfaceMap(hostIfaces))
		if len(warnings) > 0 {
			return "", nil, errors.New(strings.Join(warnings, "; "))
		}
		effectiveIPv6Assignments = resolvedAssignments
	}

	effectiveEgressNATs := append([]EgressNAT(nil), explicitEgressNATs...)
	if len(managedNetworkCompiled.EgressNATs) > 0 {
		effectiveEgressNATs = append(effectiveEgressNATs, managedNetworkCompiled.EgressNATs...)
	}

	fingerprint := buildManagedNetworkRuntimeReloadFingerprint(
		managedNetworks,
		managedNetworkReservations,
		effectiveIPv6Assignments,
		effectiveEgressNATs,
		egressNATSnapshot.Infos,
	)
	touchedInterfaces := collectManagedNetworkRuntimeTouchedInterfaces(managedNetworks, effectiveIPv6Assignments, managedNetworkCompiled)
	return fingerprint, touchedInterfaces, nil
}

var managedNetworkAddrReloadSkipCheck = canSkipManagedNetworkAddrReload

func appendManagedNetworkRuntimeReloadIssue(issues []string, scope string, err error) []string {
	if err == nil {
		return issues
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return append(issues, err.Error())
	}
	return append(issues, fmt.Sprintf("%s: %v", scope, err))
}

func managedNetworkRuntimeReloadCompletion(issues []string) (string, error) {
	if len(issues) == 0 {
		return "success", nil
	}
	cleaned := make([]string, 0, len(issues))
	seen := make(map[string]struct{}, len(issues))
	for _, issue := range issues {
		issue = strings.TrimSpace(issue)
		if issue == "" {
			continue
		}
		if _, ok := seen[issue]; ok {
			continue
		}
		seen[issue] = struct{}{}
		cleaned = append(cleaned, issue)
	}
	if len(cleaned) == 0 {
		return "success", nil
	}
	return "partial", fmt.Errorf("%s", strings.Join(cleaned, "; "))
}

func mergeManagedNetworkRuntimeReloadError(existing string, scope string, err error) error {
	issues := make([]string, 0, 2)
	existing = strings.TrimSpace(existing)
	if existing != "" {
		for _, issue := range strings.Split(existing, ";") {
			issue = strings.TrimSpace(issue)
			if issue != "" {
				issues = append(issues, issue)
			}
		}
	}
	issues = appendManagedNetworkRuntimeReloadIssue(issues, scope, err)
	_, mergedErr := managedNetworkRuntimeReloadCompletion(issues)
	return mergedErr
}

func (pm *ProcessManager) noteManagedNetworkRuntimeReloadIssue(scope string, err error) {
	if pm == nil || err == nil {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.managedRuntimeReloadLastError = strings.TrimSpace(mergeManagedNetworkRuntimeReloadError(pm.managedRuntimeReloadLastError, scope, err).Error())
	result := strings.TrimSpace(pm.managedRuntimeReloadLastResult)
	switch result {
	case "", "success":
		pm.managedRuntimeReloadLastResult = "partial"
	}
}

func (pm *ProcessManager) managedRuntimeReloadLoop() {
	defer close(pm.managedRuntimeReloadDone)

	var timer *time.Timer
	for {
		pm.mu.Lock()
		pending := pm.managedRuntimeReloadPending
		dueAt := pm.managedRuntimeReloadDueAt
		wake := pm.managedRuntimeReloadWake
		shutdownCh := pm.shutdownCh
		shuttingDown := pm.shuttingDown
		pm.mu.Unlock()

		if shuttingDown {
			if timer != nil {
				stopTimer(timer)
			}
			return
		}

		if !pending {
			if timer != nil {
				stopTimer(timer)
				timer = nil
			}
			if wake == nil {
				return
			}
			select {
			case <-shutdownCh:
				return
			case _, ok := <-wake:
				if !ok {
					return
				}
			}
			continue
		}

		if wait := time.Until(dueAt); wait > 0 {
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				resetTimer(timer, wait)
			}
			select {
			case <-shutdownCh:
				stopTimer(timer)
				return
			case _, ok := <-wake:
				if !ok {
					stopTimer(timer)
					return
				}
				continue
			case <-timer.C:
			}
		}

		pm.mu.Lock()
		if pm.shuttingDown {
			pm.mu.Unlock()
			if timer != nil {
				stopTimer(timer)
			}
			return
		}
		if !pm.managedRuntimeReloadPending {
			pm.mu.Unlock()
			continue
		}
		now := time.Now()
		if !pm.managedRuntimeReloadDueAt.IsZero() && now.Before(pm.managedRuntimeReloadDueAt) {
			pm.mu.Unlock()
			continue
		}
		reloadSource := pm.managedRuntimeReloadLastRequestSource
		reloadInterfaces := cloneManagedNetworkInterfaceSet(pm.managedRuntimeReloadInterfaces)
		if len(reloadInterfaces) > 0 && managedNetworkRuntimeReloadSourceHonorsSuppression(reloadSource) {
			reloadInterfaces = pm.filterSuppressedManagedNetworkRuntimeInterfaceSetLocked(reloadInterfaces, now)
			if len(reloadInterfaces) == 0 {
				skippedSummary := summarizeManagedRuntimeReloadInterfaces(pm.managedRuntimeReloadInterfaces)
				pm.managedRuntimeReloadPending = false
				pm.managedRuntimeReloadDueAt = time.Time{}
				pm.managedRuntimeReloadInterfaces = nil
				pm.mu.Unlock()
				if skippedSummary != "" {
					log.Printf(
						"managed network runtime: skipped queued %s reload on %s (interfaces still suppressed after recent apply)",
						managedNetworkRuntimeReloadSourceLabel(reloadSource),
						skippedSummary,
					)
				}
				continue
			}
			pm.managedRuntimeReloadLastRequestSummary = summarizeManagedRuntimeReloadInterfaces(reloadInterfaces)
		}
		pm.managedRuntimeReloadPending = false
		pm.managedRuntimeReloadDueAt = time.Time{}
		pm.managedRuntimeReloadInterfaces = nil
		pm.mu.Unlock()

		reloadInterfaceNames := managedNetworkRuntimeInterfaceNamesFromSet(reloadInterfaces)
		pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkSelfEventSuppressFor, reloadInterfaceNames...)
		if summary := summarizeManagedRuntimeReloadInterfaces(reloadInterfaces); summary != "" {
			log.Printf("managed network runtime: auto reload triggered by %s on %s", managedNetworkRuntimeReloadSourceLabel(reloadSource), summary)
		}
		pm.markManagedNetworkRuntimeReloadStarted()
		var reloadRepairErr error
		var repairInterfaceNames []string
		if pm.shouldAutoRepairManagedNetworkRuntimeReload(reloadSource) {
			repairResult, repairErr := repairManagedNetworkHostStateForProcessManager(pm)
			repairInterfaceNames = managedNetworkRepairResultInterfaceNames(repairResult)
			pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkSelfEventSuppressFor, repairInterfaceNames...)
			if repairSummary := summarizeManagedNetworkRepairResult(repairResult); repairSummary != "" {
				log.Printf("managed network runtime: auto repair applied %s", repairSummary)
			}
			if repairErr != nil {
				log.Printf("managed network runtime: auto repair before reload failed: %v", repairErr)
				reloadRepairErr = repairErr
			}
		}
		if err := pm.reloadManagedNetworkRuntimeOnly(); err != nil {
			pm.markManagedNetworkRuntimeReloadCompleted("fallback", "", err)
			log.Printf("managed network runtime reload: targeted reload failed, falling back to full redistribute: %v", err)
			pm.requestRedistributeWorkers(0)
			continue
		}
		pm.noteManagedNetworkRuntimeReloadIssue("managed network auto repair", reloadRepairErr)
		pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkRuntimeReloadPostApplySuppressFor(reloadSource), append(reloadInterfaceNames, repairInterfaceNames...)...)
	}
}

func (pm *ProcessManager) reloadManagedNetworkRuntimeOnly() error {
	if pm == nil {
		return nil
	}
	if pm.db == nil {
		return fmt.Errorf("managed network runtime reload requires database access")
	}

	pm.redistributeMu.Lock()
	defer pm.redistributeMu.Unlock()

	managedNetworks, err := dbGetManagedNetworks(pm.db)
	if err != nil {
		return fmt.Errorf("load managed networks: %w", err)
	}
	managedNetworkReservations, err := dbGetManagedNetworkReservations(pm.db)
	if err != nil {
		return fmt.Errorf("load managed network reservations: %w", err)
	}
	reloadIssues := make([]string, 0, 2)

	explicitEgressNATs, err := dbGetEgressNATs(pm.db)
	if err != nil {
		return fmt.Errorf("load egress nats: %w", err)
	}
	ipv6Assignments, ipv6AssignmentLoadErr := loadIPv6AssignmentsForManagedNetworkReload(pm.db)
	if ipv6AssignmentLoadErr != nil {
		log.Printf("load ipv6 assignments: %v", ipv6AssignmentLoadErr)
		reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "load ipv6 assignments", ipv6AssignmentLoadErr)
	}

	egressNATSnapshot := egressNATInterfaceSnapshot{}
	needsManagedNetworkCompilation := len(managedNetworks) > 0
	if len(explicitEgressNATs) > 0 || needsManagedNetworkCompilation {
		egressNATSnapshot = loadEgressNATInterfaceSnapshot()
	}
	if needsManagedNetworkCompilation && egressNATSnapshot.Err != nil {
		log.Printf("managed network runtime: interface inventory unavailable: %v", egressNATSnapshot.Err)
		reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "managed network interface inventory", egressNATSnapshot.Err)
	}
	explicitEgressNATs = normalizeEgressNATItemsWithSnapshot(explicitEgressNATs, egressNATSnapshot)
	managedNetworkCompiled := compileManagedNetworkRuntime(managedNetworks, ipv6Assignments, explicitEgressNATs, egressNATSnapshot.Infos)
	for _, warning := range managedNetworkCompiled.Warnings {
		log.Printf("managed network runtime: %s", warning)
	}

	effectiveIPv6Assignments := append([]IPv6Assignment(nil), ipv6Assignments...)
	if len(managedNetworkCompiled.IPv6Assignments) > 0 {
		effectiveIPv6Assignments = append(effectiveIPv6Assignments, managedNetworkCompiled.IPv6Assignments...)
	}
	ipv6ResolutionWarnings := make([]string, 0)
	if len(effectiveIPv6Assignments) > 0 {
		if hostIfaces, err := loadIPv6AssignmentHostNetworkInterfaces(); err == nil {
			effectiveIPv6Assignments, ipv6ResolutionWarnings = resolveIPv6AssignmentsForCurrentHost(effectiveIPv6Assignments, buildHostNetworkInterfaceMap(hostIfaces))
		} else {
			log.Printf("managed network runtime: load host interfaces for ipv6 resolution: %v", err)
			ipv6ResolutionWarnings = append(ipv6ResolutionWarnings, fmt.Sprintf("load host interfaces for ipv6 resolution: %v", err))
		}
		for _, warning := range ipv6ResolutionWarnings {
			log.Printf("managed network runtime: %s", warning)
		}
	}

	effectiveEgressNATs := append([]EgressNAT(nil), explicitEgressNATs...)
	if len(managedNetworkCompiled.EgressNATs) > 0 {
		effectiveEgressNATs = append(effectiveEgressNATs, managedNetworkCompiled.EgressNATs...)
	}
	dynamicEgressNATParents := collectDynamicEgressNATParentsWithSnapshot(effectiveEgressNATs, egressNATSnapshot)
	managedNetworkInterfaces := cloneManagedNetworkInterfaceSet(managedNetworkCompiled.RedistributeIfaces)
	reloadSummary := summarizeManagedNetworkRuntimeReload(managedNetworks, managedNetworkReservations, effectiveIPv6Assignments, managedNetworkCompiled.EgressNATs)
	reloadFingerprint := buildManagedNetworkRuntimeReloadFingerprint(managedNetworks, managedNetworkReservations, effectiveIPv6Assignments, effectiveEgressNATs, egressNATSnapshot.Infos)
	pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkSelfEventSuppressFor, collectManagedNetworkRuntimeTouchedInterfaces(managedNetworks, effectiveIPv6Assignments, managedNetworkCompiled)...)

	ipv6Interfaces, ipv6ConfiguredCount := collectIPv6AssignmentInterfaceNames(effectiveIPv6Assignments)
	for name := range managedNetworkCompiled.RedistributeIfaces {
		if ipv6Interfaces == nil {
			ipv6Interfaces = make(map[string]struct{})
		}
		ipv6Interfaces[name] = struct{}{}
	}

	reloadSource := pm.snapshotManagedNetworkRuntimeReloadStatus().LastRequestSource
	if reloadSource == "addr_change" &&
		ipv6AssignmentLoadErr == nil &&
		egressNATSnapshot.Err == nil &&
		len(ipv6ResolutionWarnings) == 0 &&
		managedNetworkAddrReloadSkipCheck(managedNetworks, managedNetworkReservations) &&
		pm.shouldSkipManagedNetworkAddrReload(reloadFingerprint) {
		pm.mu.Lock()
		pm.managedNetworkInterfaces = managedNetworkInterfaces
		pm.dynamicEgressNATParents = dynamicEgressNATParents
		pm.ipv6AssignmentsConfigured = ipv6ConfiguredCount > 0 || len(managedNetworkCompiled.RedistributeIfaces) > 0
		pm.ipv6AssignmentInterfaces = ipv6Interfaces
		pm.mu.Unlock()
		if summary := summarizeManagedRuntimeReloadInterfaces(managedNetworkInterfaces); summary != "" {
			log.Printf("managed network runtime: address-triggered reload skipped on %s (effective state unchanged)", summary)
		} else {
			log.Printf("managed network runtime: address-triggered reload skipped (effective state unchanged)")
		}
		pm.markManagedNetworkRuntimeReloadCompleted("success", reloadSummary, nil)
		return nil
	}

	if pm.managedNetworkRuntime != nil {
		if err := pm.managedNetworkRuntime.Reconcile(managedNetworks, managedNetworkReservations); err != nil {
			log.Printf("managed network runtime reconcile: %v", err)
			reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "managed network runtime reconcile", err)
		}
	}

	if ipv6AssignmentLoadErr == nil {
		if pm.ipv6Runtime != nil {
			if err := pm.ipv6Runtime.Reconcile(effectiveIPv6Assignments); err != nil {
				log.Printf("ipv6 assignment runtime reconcile: %v", err)
				reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "ipv6 assignment runtime reconcile", err)
			}
		}
		pm.mu.Lock()
		pm.managedNetworkInterfaces = managedNetworkInterfaces
		pm.ipv6AssignmentsConfigured = ipv6ConfiguredCount > 0 || len(managedNetworkCompiled.RedistributeIfaces) > 0
		pm.ipv6AssignmentInterfaces = ipv6Interfaces
		pm.mu.Unlock()
	} else {
		pm.mu.Lock()
		pm.managedNetworkInterfaces = managedNetworkInterfaces
		pm.mu.Unlock()
	}
	reloadResult, reloadErr := managedNetworkRuntimeReloadCompletion(reloadIssues)

	if pm.kernelRuntime == nil || pm.cfg == nil {
		pm.mu.Lock()
		pm.managedNetworkInterfaces = managedNetworkInterfaces
		pm.dynamicEgressNATParents = dynamicEgressNATParents
		if reloadErr == nil {
			pm.managedRuntimeReloadAppliedFingerprint = reloadFingerprint
		}
		pm.mu.Unlock()
		if reloadSummary != "" {
			log.Printf("managed network runtime: targeted reload applied %s", reloadSummary)
		}
		pm.markManagedNetworkRuntimeReloadCompleted(reloadResult, reloadSummary, reloadErr)
		return nil
	}

	if err := pm.reconcileManagedNetworkAutoEgressNATs(explicitEgressNATs, managedNetworkCompiled.EgressNATs, dynamicEgressNATParents, egressNATSnapshot); err != nil {
		return err
	}
	if reloadErr == nil {
		pm.mu.Lock()
		pm.managedRuntimeReloadAppliedFingerprint = reloadFingerprint
		pm.mu.Unlock()
	}
	if reloadSummary != "" {
		log.Printf("managed network runtime: targeted reload applied %s", reloadSummary)
	}
	pm.markManagedNetworkRuntimeReloadCompleted(reloadResult, reloadSummary, reloadErr)
	return nil
}

func summarizeManagedNetworkRuntimeReload(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation, effectiveIPv6Assignments []IPv6Assignment, autoEgressNATs []EgressNAT) string {
	parts := make([]string, 0, 8)

	enabledNetworks := 0
	bridges := make(map[string]struct{})
	reservationsByNetwork := make(map[int64][]ManagedNetworkReservation)
	for _, item := range reservations {
		if item.ManagedNetworkID <= 0 {
			continue
		}
		reservationsByNetwork[item.ManagedNetworkID] = append(reservationsByNetwork[item.ManagedNetworkID], item)
	}
	dhcpv4Bridges := make(map[string]struct{})
	for _, network := range managedNetworks {
		network = normalizeManagedNetwork(network)
		if !network.Enabled {
			continue
		}
		enabledNetworks++
		if bridge := strings.TrimSpace(network.Bridge); bridge != "" {
			bridges[bridge] = struct{}{}
		}
		if !network.IPv4Enabled {
			continue
		}
		plan, err := buildManagedNetworkIPv4Plan(network, reservationsByNetwork[network.ID])
		if err != nil {
			continue
		}
		if bridge := strings.TrimSpace(plan.Bridge); bridge != "" {
			dhcpv4Bridges[bridge] = struct{}{}
		}
	}
	if enabledNetworks > 0 {
		parts = append(parts, fmt.Sprintf("networks=%d", enabledNetworks))
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(bridges); summary != "" {
		parts = append(parts, "bridges="+summary)
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(dhcpv4Bridges); summary != "" {
		parts = append(parts, "dhcpv4="+summary)
	}

	routes := make(map[ipv6AssignmentRouteSpec]struct{})
	proxies := make(map[ipv6AssignmentProxySpec]struct{})
	raTargets := make(map[string]struct{})
	dhcpv6Targets := make(map[string]struct{})
	for _, item := range effectiveIPv6Assignments {
		if !item.Enabled {
			continue
		}
		plan, err := buildIPv6AssignmentRuntimePlan(item)
		if err != nil {
			continue
		}
		routes[ipv6AssignmentRouteSpec{
			Prefix:          plan.AssignedPrefix,
			TargetInterface: plan.TargetInterface,
		}] = struct{}{}
		if plan.NeedsProxyNDP {
			proxies[ipv6AssignmentProxySpec{
				ParentInterface: plan.ParentInterface,
				Address:         plan.ProxyAddress,
			}] = struct{}{}
		}
		if plan.NeedsRADvertise || plan.Intent.kind == ipv6AssignmentIntentSingleAddress {
			raTargets[plan.TargetInterface] = struct{}{}
		}
		if plan.Intent.kind == ipv6AssignmentIntentSingleAddress {
			dhcpv6Targets[plan.TargetInterface] = struct{}{}
		}
	}
	if len(routes) > 0 {
		parts = append(parts, fmt.Sprintf("ipv6_routes=%d", len(routes)))
	}
	if len(proxies) > 0 {
		parts = append(parts, fmt.Sprintf("proxy_ndp=%d", len(proxies)))
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(raTargets); summary != "" {
		parts = append(parts, "ra="+summary)
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(dhcpv6Targets); summary != "" {
		parts = append(parts, "dhcpv6="+summary)
	}

	autoEgressNATCount := 0
	autoEgressParents := make(map[string]struct{})
	for _, item := range autoEgressNATs {
		if !item.Enabled {
			continue
		}
		autoEgressNATCount++
		if parent := strings.TrimSpace(item.ParentInterface); parent != "" {
			autoEgressParents[parent] = struct{}{}
		}
	}
	if autoEgressNATCount > 0 {
		part := fmt.Sprintf("auto_egress_nat=%d", autoEgressNATCount)
		if summary := summarizeManagedRuntimeReloadInterfaces(autoEgressParents); summary != "" {
			part += "(" + summary + ")"
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, " ")
}

func collectManagedNetworkRuntimeTouchedInterfaces(managedNetworks []ManagedNetwork, effectiveIPv6Assignments []IPv6Assignment, compiled managedNetworkRuntimeCompilation) []string {
	names := make([]string, 0, len(managedNetworks)*4+len(effectiveIPv6Assignments)*2)
	for _, network := range managedNetworks {
		network = normalizeManagedNetwork(network)
		if !network.Enabled {
			continue
		}
		names = append(names, network.Bridge, network.UplinkInterface, network.IPv6ParentInterface)
		if preview, ok := compiled.Previews[network.ID]; ok {
			names = append(names, preview.ChildInterfaces...)
		}
	}
	for _, item := range effectiveIPv6Assignments {
		if !item.Enabled {
			continue
		}
		names = append(names, item.ParentInterface, item.TargetInterface)
	}
	return uniqueManagedNetworkRuntimeInterfaceNames(names...)
}

func cloneManagedNetworkInterfaceSet(src map[string]struct{}) map[string]struct{} {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]struct{}, len(src))
	for name := range src {
		if name == "" {
			continue
		}
		dst[name] = struct{}{}
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func sliceToManagedNetworkInterfaceSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out[item] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func summarizeManagedRuntimeReloadInterfaces(src map[string]struct{}) string {
	if len(src) == 0 {
		return ""
	}
	items := make([]string, 0, len(src))
	for name := range src {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		items = append(items, name)
	}
	if len(items) == 0 {
		return ""
	}
	sort.Strings(items)
	if len(items) > 3 {
		items = append(items[:3], fmt.Sprintf("+%d", len(items)-3))
	}
	return strings.Join(items, ",")
}

func (pm *ProcessManager) reconcileManagedNetworkAutoEgressNATs(explicitEgressNATs []EgressNAT, autoEgressNATs []EgressNAT, dynamicEgressNATParents map[string]struct{}, snapshot egressNATInterfaceSnapshot) error {
	if pm == nil || pm.kernelRuntime == nil || pm.cfg == nil {
		return nil
	}

	rules, err := dbGetRules(pm.db)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	ranges, err := dbGetRanges(pm.db)
	if err != nil {
		return fmt.Errorf("load ranges: %w", err)
	}

	currentRulePlans, currentRangePlans, currentEgressNATPlans, currentKernelRules, currentKernelRanges, currentKernelEgressNATs, prevKernelRuleStats, prevKernelRangeStats, prevKernelEgressNATStats, prevKernelFlowOwners, prevKernelStatsSnapshot, prevKernelStatsAt, prevKernelStatsSnapshotAt :=
		pm.snapshotManagedNetworkKernelReloadState()

	retainer, ok := pm.kernelRuntime.(kernelHandoffRetentionRuntime)
	if !ok || retainer == nil {
		return fmt.Errorf("managed network runtime reload requires kernel assignment retention support")
	}

	currentExplicitKernelEgressNATs := filterPositiveKernelOwnerIDs(currentKernelEgressNATs)
	retainedDesiredByOwner, maxRuleID, retainedEntries, err := buildManagedNetworkRetainedKernelDesiredByOwner(
		rules,
		ranges,
		explicitEgressNATs,
		currentKernelRules,
		currentKernelRanges,
		currentExplicitKernelEgressNATs,
		currentRulePlans,
		currentRangePlans,
		currentEgressNATPlans,
		retainer,
	)
	if err != nil {
		return err
	}

	planner := newRuleDataplanePlanner(pm.kernelRuntime, pm.cfg.DefaultEngine)
	nextSyntheticID := maxRuleID + 1
	autoCandidates, autoPlans := buildEgressNATKernelCandidatesWithSnapshot(
		autoEgressNATs,
		planner,
		pm.cfg.KernelRulesMapLimit,
		retainedEntries,
		&nextSyntheticID,
		snapshot,
	)
	autoCandidateOwners := ownerSetFromKernelCandidates(autoCandidates)
	desiredByOwner := mergeKernelCandidateGroups(retainedDesiredByOwner, groupKernelCandidatesByOwner(autoCandidates))
	egressNATPlans := mergeManagedNetworkReloadEgressNATPlans(currentEgressNATPlans, autoPlans)

	currentKernelAssignments := pm.kernelRuntime.SnapshotAssignments()
	retainedByEngine, retainedCandidates, retainedSummary, err := buildRetainedKernelAssignments(
		rules,
		ranges,
		append(append([]EgressNAT(nil), explicitEgressNATs...), autoEgressNATs...),
		currentKernelRules,
		currentKernelRanges,
		currentExplicitKernelEgressNATs,
		currentRulePlans,
		currentRangePlans,
		egressNATPlans,
		desiredByOwner,
		retainer,
		currentKernelAssignments,
	)
	if err != nil {
		return err
	}

	retryCandidates := filterKernelCandidatesByOwners(autoCandidates, autoCandidateOwners, nil, nil, egressNATPlans)
	needsKernelRefresh := len(retryCandidates) > 0 || len(currentKernelEgressNATs) != len(currentExplicitKernelEgressNATs)
	if totalRetainedKernelAssignments(retainedByEngine) == 0 && len(retryCandidates) == 0 && !needsKernelRefresh {
		pm.mu.Lock()
		pm.dynamicEgressNATParents = dynamicEgressNATParents
		pm.egressNATPlans = egressNATPlans
		pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, time.Now(), currentRulePlans, currentRangePlans, egressNATPlans)
		pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(pm.kernelNetlinkOwnerRetryFailures, currentRulePlans, currentRangePlans, egressNATPlans)
		pm.mu.Unlock()
		return nil
	}

	activeRetryCandidates := retryCandidates
	for {
		results, err := reconcileIncrementalKernelRetry(pm.kernelRuntime, retainedByEngine, activeRetryCandidates)
		if len(activeRetryCandidates) == 0 {
			break
		}
		ownerFailures := collectKernelOwnerFailures(activeRetryCandidates, results, err)
		if len(ownerFailures) == 0 {
			break
		}
		ownerMetadata := collectKernelOwnerFallbackMetadata(activeRetryCandidates, ownerFailures)
		for owner, reason := range ownerFailures {
			applyKernelOwnerFallbackWithMetadata(owner, reason, ownerMetadata[owner], nil, nil, egressNATPlans)
		}
		activeRetryCandidates = filterKernelCandidatesByOwners(autoCandidates, autoCandidateOwners, nil, nil, egressNATPlans)
	}

	finalActiveCandidates := make([]kernelCandidateRule, 0, len(retainedCandidates)+len(activeRetryCandidates))
	finalActiveCandidates = append(finalActiveCandidates, retainedCandidates...)
	finalActiveCandidates = append(finalActiveCandidates, activeRetryCandidates...)

	kernelAssignments := pm.kernelRuntime.SnapshotAssignments()
	kernelAppliedRuleEngines, kernelAppliedRangeEngines, kernelAppliedEgressNATEngines, kernelAppliedRules, kernelAppliedRanges, kernelAppliedEgressNATs, kernelFlowOwners :=
		buildAppliedKernelOwnerState(finalActiveCandidates, kernelAssignments)

	preservedKernelSnapshot := retainKernelStatsSnapshot(prevKernelStatsSnapshot, prevKernelFlowOwners, kernelFlowOwners)
	pm.mu.Lock()
	pm.rulePlans = currentRulePlans
	pm.rangePlans = currentRangePlans
	pm.egressNATPlans = egressNATPlans
	pm.dynamicEgressNATParents = dynamicEgressNATParents
	pm.kernelRules = kernelAppliedRules
	pm.kernelRanges = kernelAppliedRanges
	pm.kernelEgressNATs = kernelAppliedEgressNATs
	pm.kernelRuleEngines = kernelAppliedRuleEngines
	pm.kernelRangeEngines = kernelAppliedRangeEngines
	pm.kernelEgressNATEngines = kernelAppliedEgressNATEngines
	pm.kernelFlowOwners = kernelFlowOwners
	pm.kernelRuleStats = retainKernelRuleStatsReports(prevKernelRuleStats, kernelAppliedRules)
	pm.kernelRangeStats = retainKernelRangeStatsReports(prevKernelRangeStats, kernelAppliedRanges)
	pm.kernelEgressNATStats = retainKernelEgressNATStatsReports(prevKernelEgressNATStats, kernelAppliedEgressNATs)
	pm.kernelStatsSnapshot = preservedKernelSnapshot
	if retainedSummary.ruleOwners > 0 || retainedSummary.rangeOwners > 0 || retainedSummary.egressNATOwners > 0 {
		pm.kernelStatsAt = prevKernelStatsAt
	} else {
		pm.kernelStatsAt = time.Time{}
	}
	if len(activeRetryCandidates) > 0 {
		pm.kernelStatsSnapshotAt = time.Time{}
	} else {
		pm.kernelStatsSnapshotAt = prevKernelStatsSnapshotAt
	}
	pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, time.Now(), currentRulePlans, currentRangePlans, egressNATPlans)
	pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(pm.kernelNetlinkOwnerRetryFailures, currentRulePlans, currentRangePlans, egressNATPlans)
	pm.mu.Unlock()

	if len(activeRetryCandidates) > 0 {
		pm.refreshKernelStatsCache()
	}
	return nil
}

func (pm *ProcessManager) snapshotManagedNetworkKernelReloadState() (
	map[int64]ruleDataplanePlan,
	map[int64]rangeDataplanePlan,
	map[int64]ruleDataplanePlan,
	map[int64]bool,
	map[int64]bool,
	map[int64]bool,
	map[int64]RuleStatsReport,
	map[int64]RangeStatsReport,
	map[int64]EgressNATStatsReport,
	map[uint32]kernelCandidateOwner,
	kernelRuleStatsSnapshot,
	time.Time,
	time.Time,
) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	rulePlans := cloneRuleDataplanePlans(pm.rulePlans)
	rangePlans := cloneRangeDataplanePlans(pm.rangePlans)
	egressNATPlans := cloneRuleDataplanePlans(pm.egressNATPlans)
	kernelRules := cloneKernelOwnerMap(pm.kernelRules)
	kernelRanges := cloneKernelOwnerMap(pm.kernelRanges)
	kernelEgressNATs := cloneKernelOwnerMap(pm.kernelEgressNATs)
	ruleStats := cloneRuleStatsReports(pm.kernelRuleStats)
	rangeStats := cloneRangeStatsReports(pm.kernelRangeStats)
	egressNATStats := cloneEgressNATStatsReports(pm.kernelEgressNATStats)
	kernelFlowOwners := cloneKernelFlowOwnerMap(pm.kernelFlowOwners)
	return rulePlans, rangePlans, egressNATPlans, kernelRules, kernelRanges, kernelEgressNATs, ruleStats, rangeStats, egressNATStats, kernelFlowOwners, pm.kernelStatsSnapshot, pm.kernelStatsAt, pm.kernelStatsSnapshotAt
}

func cloneRuleDataplanePlans(src map[int64]ruleDataplanePlan) map[int64]ruleDataplanePlan {
	if len(src) == 0 {
		return map[int64]ruleDataplanePlan{}
	}
	dst := make(map[int64]ruleDataplanePlan, len(src))
	for id, plan := range src {
		dst[id] = plan
	}
	return dst
}

func cloneRangeDataplanePlans(src map[int64]rangeDataplanePlan) map[int64]rangeDataplanePlan {
	if len(src) == 0 {
		return map[int64]rangeDataplanePlan{}
	}
	dst := make(map[int64]rangeDataplanePlan, len(src))
	for id, plan := range src {
		dst[id] = plan
	}
	return dst
}

func cloneKernelOwnerMap(src map[int64]bool) map[int64]bool {
	if len(src) == 0 {
		return map[int64]bool{}
	}
	dst := make(map[int64]bool, len(src))
	for id, active := range src {
		dst[id] = active
	}
	return dst
}

func cloneKernelFlowOwnerMap(src map[uint32]kernelCandidateOwner) map[uint32]kernelCandidateOwner {
	if len(src) == 0 {
		return map[uint32]kernelCandidateOwner{}
	}
	dst := make(map[uint32]kernelCandidateOwner, len(src))
	for id, owner := range src {
		dst[id] = owner
	}
	return dst
}

func filterPositiveKernelOwnerIDs(src map[int64]bool) map[int64]bool {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[int64]bool)
	for id, active := range src {
		if !active || id <= 0 {
			continue
		}
		dst[id] = true
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func buildManagedNetworkRetainedKernelDesiredByOwner(
	rules []Rule,
	ranges []PortRange,
	explicitEgressNATs []EgressNAT,
	currentKernelRules map[int64]bool,
	currentKernelRanges map[int64]bool,
	currentExplicitKernelEgressNATs map[int64]bool,
	rulePlans map[int64]ruleDataplanePlan,
	rangePlans map[int64]rangeDataplanePlan,
	egressNATPlans map[int64]ruleDataplanePlan,
	retainer kernelHandoffRetentionRuntime,
) (map[kernelCandidateOwner][]kernelCandidateRule, int64, int, error) {
	desiredByOwner := make(map[kernelCandidateOwner][]kernelCandidateRule)
	maxRuleID := int64(0)
	for _, rule := range rules {
		if rule.ID > maxRuleID {
			maxRuleID = rule.ID
		}
	}

	rulesByID := make(map[int64]Rule, len(rules))
	for _, rule := range rules {
		rulesByID[rule.ID] = rule
	}
	rangesByID := make(map[int64]PortRange, len(ranges))
	for _, pr := range ranges {
		rangesByID[pr.ID] = pr
	}
	egressNATByID := make(map[int64]EgressNAT, len(explicitEgressNATs))
	for _, item := range explicitEgressNATs {
		egressNATByID[item.ID] = item
	}

	retainedEntries := 0
	appendRetainedOwner := func(owner kernelCandidateOwner, items []Rule) {
		if len(items) == 0 {
			return
		}
		candidates := make([]kernelCandidateRule, 0, len(items))
		for _, item := range items {
			candidates = append(candidates, kernelCandidateRule{owner: owner, rule: item})
			if item.ID > maxRuleID {
				maxRuleID = item.ID
			}
		}
		desiredByOwner[owner] = candidates
		retainedEntries += len(candidates)
	}

	for id, active := range currentKernelRules {
		if !active {
			continue
		}
		rule, ok := rulesByID[id]
		if !ok {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active rule owner %d is no longer present", id)
		}
		if rulePlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active rule owner %d changed target engine", id)
		}
		retained, ok := retainer.retainedKernelRuleCandidates(rule)
		if !ok || len(retained) == 0 {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active rule owner %d cannot be retained in place", id)
		}
		appendRetainedOwner(kernelCandidateOwner{kind: workerKindRule, id: id}, retained)
	}
	for id, active := range currentKernelRanges {
		if !active {
			continue
		}
		pr, ok := rangesByID[id]
		if !ok {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active range owner %d is no longer present", id)
		}
		if rangePlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active range owner %d changed target engine", id)
		}
		retained, ok := retainer.retainedKernelRangeCandidates(pr)
		if !ok || len(retained) == 0 {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active range owner %d cannot be retained in place", id)
		}
		appendRetainedOwner(kernelCandidateOwner{kind: workerKindRange, id: id}, retained)
	}
	for id, active := range currentExplicitKernelEgressNATs {
		if !active {
			continue
		}
		item, ok := egressNATByID[id]
		if !ok {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active egress nat owner %d is no longer present", id)
		}
		if egressNATPlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active egress nat owner %d changed target engine", id)
		}
		retained, ok := retainer.retainedKernelEgressNATCandidates(item)
		if !ok || len(retained) == 0 {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active egress nat owner %d cannot be retained in place", id)
		}
		appendRetainedOwner(kernelCandidateOwner{kind: workerKindEgressNAT, id: id}, retained)
	}

	return desiredByOwner, maxRuleID, retainedEntries, nil
}

func mergeManagedNetworkReloadEgressNATPlans(current map[int64]ruleDataplanePlan, autoPlans map[int64]ruleDataplanePlan) map[int64]ruleDataplanePlan {
	merged := make(map[int64]ruleDataplanePlan, len(current)+len(autoPlans))
	for id, plan := range current {
		if id < 0 {
			continue
		}
		merged[id] = plan
	}
	for id, plan := range autoPlans {
		merged[id] = plan
	}
	return merged
}

func mergeKernelCandidateGroups(base map[kernelCandidateOwner][]kernelCandidateRule, extra map[kernelCandidateOwner][]kernelCandidateRule) map[kernelCandidateOwner][]kernelCandidateRule {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	merged := make(map[kernelCandidateOwner][]kernelCandidateRule, len(base)+len(extra))
	for owner, candidates := range base {
		merged[owner] = append([]kernelCandidateRule(nil), candidates...)
	}
	for owner, candidates := range extra {
		merged[owner] = append([]kernelCandidateRule(nil), candidates...)
	}
	return merged
}

func ownerSetFromKernelCandidates(candidates []kernelCandidateRule) map[kernelCandidateOwner]struct{} {
	if len(candidates) == 0 {
		return nil
	}
	out := make(map[kernelCandidateOwner]struct{})
	for _, candidate := range candidates {
		out[candidate.owner] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildAppliedKernelOwnerState(finalActiveCandidates []kernelCandidateRule, kernelAssignments map[int64]string) (
	map[int64]string,
	map[int64]string,
	map[int64]string,
	map[int64]bool,
	map[int64]bool,
	map[int64]bool,
	map[uint32]kernelCandidateOwner,
) {
	kernelAppliedRuleEngines := make(map[int64]string)
	kernelAppliedRangeEngines := make(map[int64]string)
	kernelAppliedEgressNATEngines := make(map[int64]string)
	kernelAppliedRules := make(map[int64]bool)
	kernelAppliedRanges := make(map[int64]bool)
	kernelAppliedEgressNATs := make(map[int64]bool)
	kernelFlowOwners := make(map[uint32]kernelCandidateOwner, len(finalActiveCandidates))
	for _, candidate := range finalActiveCandidates {
		if candidate.rule.ID <= 0 || candidate.rule.ID > int64(^uint32(0)) {
			continue
		}
		engine := kernelAssignments[candidate.rule.ID]
		if engine == "" {
			continue
		}
		kernelFlowOwners[uint32(candidate.rule.ID)] = candidate.owner
		switch candidate.owner.kind {
		case workerKindRule:
			kernelAppliedRules[candidate.owner.id] = true
			kernelAppliedRuleEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRuleEngines[candidate.owner.id], engine)
		case workerKindRange:
			kernelAppliedRanges[candidate.owner.id] = true
			kernelAppliedRangeEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRangeEngines[candidate.owner.id], engine)
		case workerKindEgressNAT:
			kernelAppliedEgressNATs[candidate.owner.id] = true
			kernelAppliedEgressNATEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedEgressNATEngines[candidate.owner.id], engine)
		}
	}
	return kernelAppliedRuleEngines, kernelAppliedRangeEngines, kernelAppliedEgressNATEngines, kernelAppliedRules, kernelAppliedRanges, kernelAppliedEgressNATs, kernelFlowOwners
}

func (pm *ProcessManager) shouldReloadManagedNetworkRuntimeForInterface(name string) bool {
	if pm == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	hasManagedRuntime := len(pm.managedNetworkInterfaces) > 0
	hasIPv6Runtime := pm.ipv6AssignmentsConfigured
	if !hasManagedRuntime && !hasIPv6Runtime {
		return false
	}

	name = strings.TrimSpace(name)
	if isManagedNetworkDynamicGuestLink(name) {
		return true
	}
	if name == "" {
		return true
	}
	if _, ok := pm.managedNetworkInterfaces[name]; ok {
		return true
	}
	_, ok := pm.ipv6AssignmentInterfaces[name]
	return ok
}

func normalizeManagedNetworkRuntimeReloadSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "manual"
	}
	return source
}

func managedNetworkRuntimeReloadSourceLabel(source string) string {
	switch normalizeManagedNetworkRuntimeReloadSource(source) {
	case "link_change":
		return "link change"
	case "addr_change":
		return "address change"
	case "drift_check":
		return "state drift"
	case "manual":
		return "manual request"
	default:
		return strings.ReplaceAll(normalizeManagedNetworkRuntimeReloadSource(source), "_", " ")
	}
}

func managedNetworkRuntimeReloadPostApplySuppressFor(source string) time.Duration {
	if normalizeManagedNetworkRuntimeReloadSource(source) == "link_change" {
		return managedNetworkLinkChangeSuppressFor
	}
	return 0
}

func managedNetworkRuntimeReloadSourceHonorsSuppression(source string) bool {
	switch normalizeManagedNetworkRuntimeReloadSource(source) {
	case "link_change", "addr_change":
		return true
	default:
		return false
	}
}

func (pm *ProcessManager) shouldAutoRepairManagedNetworkRuntimeReload(source string) bool {
	if pm == nil {
		return false
	}
	if normalizeManagedNetworkRuntimeReloadSource(source) != "link_change" {
		return false
	}
	if pm.cfg == nil {
		return true
	}
	return pm.cfg.ManagedNetworkAutoRepairEnabled()
}

func (pm *ProcessManager) snapshotManagedNetworkRuntimeReloadStatus() ManagedNetworkRuntimeReloadStatus {
	if pm == nil {
		return ManagedNetworkRuntimeReloadStatus{}
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	return ManagedNetworkRuntimeReloadStatus{
		Pending:            pm.managedRuntimeReloadPending,
		DueAt:              pm.managedRuntimeReloadDueAt,
		LastRequestedAt:    pm.managedRuntimeReloadLastRequestedAt,
		LastRequestSource:  pm.managedRuntimeReloadLastRequestSource,
		LastRequestSummary: pm.managedRuntimeReloadLastRequestSummary,
		LastStartedAt:      pm.managedRuntimeReloadLastStartedAt,
		LastCompletedAt:    pm.managedRuntimeReloadLastCompletedAt,
		LastResult:         pm.managedRuntimeReloadLastResult,
		LastAppliedSummary: pm.managedRuntimeReloadLastAppliedSummary,
		LastError:          pm.managedRuntimeReloadLastError,
	}
}

func uniqueManagedNetworkRuntimeInterfaceNames(names ...string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func managedNetworkRuntimeInterfaceNamesFromSet(items map[string]struct{}) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for name := range items {
		out = append(out, name)
	}
	return uniqueManagedNetworkRuntimeInterfaceNames(out...)
}

func (pm *ProcessManager) suppressManagedNetworkRuntimeReloadForInterfaces(duration time.Duration, names ...string) {
	if pm == nil || duration <= 0 {
		return
	}
	names = uniqueManagedNetworkRuntimeInterfaceNames(names...)
	if len(names) == 0 {
		return
	}

	now := time.Now()
	until := now.Add(duration)

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.managedRuntimeReloadSuppressUntil == nil {
		pm.managedRuntimeReloadSuppressUntil = make(map[string]time.Time)
	}
	for name, expiry := range pm.managedRuntimeReloadSuppressUntil {
		if !expiry.After(now) {
			delete(pm.managedRuntimeReloadSuppressUntil, name)
		}
	}
	for _, name := range names {
		if current := pm.managedRuntimeReloadSuppressUntil[name]; current.Before(until) {
			pm.managedRuntimeReloadSuppressUntil[name] = until
		}
	}
}

func (pm *ProcessManager) filterSuppressedManagedNetworkRuntimeInterfaces(names ...string) []string {
	if pm == nil {
		return uniqueManagedNetworkRuntimeInterfaceNames(names...)
	}
	names = uniqueManagedNetworkRuntimeInterfaceNames(names...)
	if len(names) == 0 {
		return nil
	}

	now := time.Now()
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for name, expiry := range pm.managedRuntimeReloadSuppressUntil {
		if !expiry.After(now) {
			delete(pm.managedRuntimeReloadSuppressUntil, name)
		}
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		if until, ok := pm.managedRuntimeReloadSuppressUntil[name]; ok && until.After(now) {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (pm *ProcessManager) filterSuppressedManagedNetworkRuntimeInterfaceSetLocked(items map[string]struct{}, now time.Time) map[string]struct{} {
	if pm == nil {
		return cloneManagedNetworkInterfaceSet(items)
	}
	if len(items) == 0 {
		return nil
	}
	for name, expiry := range pm.managedRuntimeReloadSuppressUntil {
		if !expiry.After(now) {
			delete(pm.managedRuntimeReloadSuppressUntil, name)
		}
	}
	filtered := make(map[string]struct{}, len(items))
	for name := range items {
		if until, ok := pm.managedRuntimeReloadSuppressUntil[name]; ok && until.After(now) {
			continue
		}
		filtered[name] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func (pm *ProcessManager) requestManagedNetworkRuntimeReloadForRelevantInterfaces(source string, names ...string) bool {
	if pm == nil {
		return false
	}
	rawNames := uniqueManagedNetworkRuntimeInterfaceNames(names...)
	uniqueNames := pm.filterSuppressedManagedNetworkRuntimeInterfaces(rawNames...)
	for _, candidate := range uniqueNames {
		if pm.shouldReloadManagedNetworkRuntimeForInterface(candidate) {
			pm.requestManagedNetworkRuntimeReloadWithSource(managedNetworkReloadDebounce, source, uniqueNames...)
			return true
		}
	}
	if len(rawNames) > 0 {
		return false
	}
	if pm.shouldReloadManagedNetworkRuntimeForInterface("") {
		pm.requestManagedNetworkRuntimeReloadWithSource(managedNetworkReloadDebounce, source)
		return true
	}
	return false
}
