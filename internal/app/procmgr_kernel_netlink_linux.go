//go:build linux

package app

import (
	"log"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (pm *ProcessManager) startKernelNetlinkMonitor() {
	if pm == nil {
		return
	}

	linkStates, err := snapshotKernelNetlinkLinkStates()
	if err != nil {
		log.Printf("kernel dataplane netlink: link state snapshot unavailable: %v", err)
	}

	pm.mu.Lock()
	if pm.kernelNetlinkStop != nil {
		pm.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	wake := make(chan struct{}, 1)
	pm.kernelNetlinkStop = stop
	pm.kernelNetlinkRecoverWake = wake
	pm.kernelNetlinkLinkStates = linkStates
	pm.mu.Unlock()

	go pm.runKernelNetlinkRecoveryLoop(stop, wake)
	go pm.runKernelNetlinkMonitor(stop)
}

func (pm *ProcessManager) stopKernelNetlinkMonitor() {
	if pm == nil {
		return
	}

	pm.mu.Lock()
	stop := pm.kernelNetlinkStop
	pm.kernelNetlinkStop = nil
	pm.kernelNetlinkRecoverWake = nil
	pm.kernelNetlinkRecoverPending = false
	pm.kernelNetlinkRecoverSource = ""
	pm.kernelNetlinkRecoverSummary = ""
	pm.kernelNetlinkRecoverTrigger = kernelNetlinkRecoveryTrigger{}
	pm.kernelNetlinkRecoverRequestedAt = time.Time{}
	pm.kernelNetlinkLinkStates = nil
	pm.mu.Unlock()

	if stop != nil {
		close(stop)
	}
}

func (pm *ProcessManager) runKernelNetlinkMonitor(stop <-chan struct{}) {
	linkUpdates := make(chan netlink.LinkUpdate, 16)
	addrUpdates := make(chan netlink.AddrUpdate, 16)
	neighUpdates := make(chan netlink.NeighUpdate, 32)

	linkReady := false
	if err := netlink.LinkSubscribeWithOptions(linkUpdates, stop, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				log.Printf("kernel dataplane netlink: link monitor error: %v", err)
			}
		},
	}); err != nil {
		log.Printf("kernel dataplane netlink: link monitor unavailable: %v", err)
	} else {
		linkReady = true
	}

	addrReady := false
	if err := netlink.AddrSubscribeWithOptions(addrUpdates, stop, netlink.AddrSubscribeOptions{
		ErrorCallback: func(err error) {
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				log.Printf("kernel dataplane netlink: address monitor error: %v", err)
			}
		},
	}); err != nil {
		log.Printf("kernel dataplane netlink: address monitor unavailable: %v", err)
	} else {
		addrReady = true
	}

	neighReady := false
	if err := netlink.NeighSubscribeWithOptions(neighUpdates, stop, netlink.NeighSubscribeOptions{
		ErrorCallback: func(err error) {
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				log.Printf("kernel dataplane netlink: neighbor monitor error: %v", err)
			}
		},
	}); err != nil {
		log.Printf("kernel dataplane netlink: neighbor monitor unavailable: %v", err)
	} else {
		neighReady = true
	}

	if !linkReady && !addrReady && !neighReady {
		return
	}

	for {
		select {
		case <-stop:
			return
		case update, ok := <-linkUpdates:
			if !ok {
				linkUpdates = nil
				if addrUpdates == nil && neighUpdates == nil {
					return
				}
				continue
			}
			if update.Header.Type == unix.RTM_NEWLINK || update.Header.Type == unix.RTM_DELLINK {
				if !pm.shouldHandleKernelNetlinkLinkUpdate(update) {
					continue
				}
				pm.handleIPv6AssignmentLinkUpdate(update)
				pm.handleKernelNetlinkRecoveryTrigger(kernelNetlinkRecoveryTriggerFromLinkUpdate(update))
			}
		case update, ok := <-addrUpdates:
			if !ok {
				addrUpdates = nil
				if linkUpdates == nil && neighUpdates == nil {
					return
				}
				continue
			}
			if !isVisibleInterfaceIP(update.LinkAddress.IP) {
				continue
			}
			pm.handleIPv6AssignmentAddrUpdate(update)
		case update, ok := <-neighUpdates:
			if !ok {
				neighUpdates = nil
				if linkUpdates == nil && addrUpdates == nil {
					return
				}
				continue
			}
			switch update.Family {
			case unix.AF_INET, unix.AF_INET6:
				pm.handleKernelNetlinkRecoveryTrigger(kernelNetlinkRecoveryTriggerFromNeighUpdate("neighbor", update))
			case unix.AF_BRIDGE:
				pm.handleKernelNetlinkRecoveryTrigger(kernelNetlinkRecoveryTriggerFromNeighUpdate("fdb", update))
			default:
				pm.handleKernelNetlinkRecoveryTrigger(kernelNetlinkRecoveryTriggerFromNeighUpdate("neighbor", update))
			}
		}
	}
}

func collectIPv6AssignmentRelatedInterfaceNames(link netlink.Link) []string {
	if link == nil || link.Attrs() == nil {
		return nil
	}
	relatedNames := make([]string, 0, 3)
	if name := strings.TrimSpace(link.Attrs().Name); name != "" {
		relatedNames = append(relatedNames, name)
	}
	if link.Attrs().MasterIndex > 0 {
		if master, err := netlink.LinkByIndex(link.Attrs().MasterIndex); err == nil && master != nil && master.Attrs() != nil {
			if masterName := strings.TrimSpace(master.Attrs().Name); masterName != "" {
				relatedNames = append(relatedNames, masterName)
			}
		}
	}
	if link.Attrs().ParentIndex > 0 {
		if parent, err := netlink.LinkByIndex(link.Attrs().ParentIndex); err == nil && parent != nil && parent.Attrs() != nil {
			if parentName := strings.TrimSpace(parent.Attrs().Name); parentName != "" {
				relatedNames = append(relatedNames, parentName)
			}
		}
	}
	return uniqueManagedNetworkRuntimeInterfaceNames(relatedNames...)
}

func (pm *ProcessManager) handleIPv6AssignmentLinkUpdate(update netlink.LinkUpdate) {
	if pm == nil {
		return
	}

	name := ""
	relatedNames := make([]string, 0, 3)
	if update.Link != nil && update.Link.Attrs() != nil {
		name = strings.TrimSpace(update.Link.Attrs().Name)
		relatedNames = append(relatedNames, collectIPv6AssignmentRelatedInterfaceNames(update.Link)...)
	}
	if name == "" && update.IfInfomsg.Index > 0 && update.Header.Type != unix.RTM_DELLINK {
		if resolved, err := netlink.LinkByIndex(int(update.IfInfomsg.Index)); err == nil && resolved != nil && resolved.Attrs() != nil {
			name = strings.TrimSpace(resolved.Attrs().Name)
			relatedNames = append(relatedNames, collectIPv6AssignmentRelatedInterfaceNames(resolved)...)
		}
	}

	if !pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces("link_change", relatedNames...) && name != "" {
		pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces("link_change", name)
	}
}

func (pm *ProcessManager) handleIPv6AssignmentAddrUpdate(update netlink.AddrUpdate) {
	if pm == nil {
		return
	}
	name := ""
	relatedNames := make([]string, 0, 3)
	if update.LinkIndex > 0 {
		if link, err := netlink.LinkByIndex(update.LinkIndex); err == nil && link != nil && link.Attrs() != nil {
			name = strings.TrimSpace(link.Attrs().Name)
			relatedNames = append(relatedNames, collectIPv6AssignmentRelatedInterfaceNames(link)...)
		}
	}
	family := unix.AF_UNSPEC
	if ip := update.LinkAddress.IP; ip != nil {
		if ip.To4() != nil {
			family = unix.AF_INET
		} else {
			family = unix.AF_INET6
		}
	}
	pm.handleVisibleInterfaceAddrUpdate(family, name, relatedNames...)
}

func (pm *ProcessManager) handleVisibleInterfaceAddrUpdate(family int, name string, relatedNames ...string) {
	if pm == nil {
		return
	}
	const reloadSource = "addr_change"
	if !pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces(reloadSource, relatedNames...) && name != "" {
		pm.requestManagedNetworkRuntimeReloadForRelevantInterfaces(reloadSource, name)
	}
	pm.handleKernelNetlinkRecoveryTrigger(kernelNetlinkRecoveryTriggerFromAddrUpdate(family, append(append([]string(nil), relatedNames...), name)...))
}

func kernelNetlinkRecoveryTriggerFromAddrUpdate(family int, names ...string) kernelNetlinkRecoveryTrigger {
	trigger := newKernelNetlinkRecoveryTrigger("addr")
	switch family {
	case unix.AF_INET:
		trigger.addAddrFamily(ipFamilyIPv4)
	case unix.AF_INET6:
		trigger.addAddrFamily(ipFamilyIPv6)
	}
	for _, name := range uniqueManagedNetworkRuntimeInterfaceNames(names...) {
		trigger.addInterfaceName(name)
	}
	return trigger
}

func snapshotKernelNetlinkLinkStates() (map[int]kernelNetlinkLinkSnapshot, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := make(map[int]kernelNetlinkLinkSnapshot, len(links))
	for _, link := range links {
		index, snapshot, ok := kernelNetlinkLinkSnapshotFromLink(link)
		if !ok {
			continue
		}
		out[index] = snapshot
	}
	return out, nil
}

func kernelNetlinkLinkSnapshotFromLink(link netlink.Link) (int, kernelNetlinkLinkSnapshot, bool) {
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return 0, kernelNetlinkLinkSnapshot{}, false
	}
	attrs := link.Attrs()
	return attrs.Index, kernelNetlinkLinkSnapshot{
		Name:        normalizeKernelTransientFallbackInterface(attrs.Name),
		LinkType:    strings.ToLower(strings.TrimSpace(link.Type())),
		MasterIndex: attrs.MasterIndex,
		AdminUp:     attrs.RawFlags&unix.IFF_UP != 0,
		LowerUp:     attrs.RawFlags&unix.IFF_LOWER_UP != 0,
		OperState:   strings.ToLower(strings.TrimSpace(attrs.OperState.String())),
	}, true
}

func (pm *ProcessManager) shouldHandleKernelNetlinkLinkUpdate(update netlink.LinkUpdate) bool {
	if pm == nil {
		return false
	}

	link := update.Link
	if (link == nil || link.Attrs() == nil) && update.IfInfomsg.Index > 0 && update.Header.Type != unix.RTM_DELLINK {
		resolved, err := netlink.LinkByIndex(int(update.IfInfomsg.Index))
		if err == nil {
			link = resolved
		}
	}

	index, snapshot, ok := kernelNetlinkLinkSnapshotFromLink(link)
	if !ok && update.IfInfomsg.Index > 0 {
		index = int(update.IfInfomsg.Index)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.kernelNetlinkLinkStates == nil {
		pm.kernelNetlinkLinkStates = make(map[int]kernelNetlinkLinkSnapshot)
	}
	if update.Header.Type == unix.RTM_DELLINK {
		return applyKernelNetlinkLinkStateUpdate(pm.kernelNetlinkLinkStates, index, kernelNetlinkLinkSnapshot{}, true)
	}
	if !ok {
		return true
	}
	return applyKernelNetlinkLinkStateUpdate(pm.kernelNetlinkLinkStates, index, snapshot, false)
}

func kernelNetlinkRecoveryTriggerFromLinkUpdate(update netlink.LinkUpdate) kernelNetlinkRecoveryTrigger {
	trigger := newKernelNetlinkRecoveryTrigger("link")
	if update.Link != nil && update.Link.Attrs() != nil {
		applyKernelNetlinkLinkRecoveryHints(&trigger, update.Link)
		return trigger
	}
	if update.IfInfomsg.Index > 0 {
		// Without link attributes we conservatively resolve the changed index later.
		trigger.addLinkNeighborIndex(int(update.IfInfomsg.Index))
		trigger.addLinkFDBIndex(int(update.IfInfomsg.Index))
	}
	return trigger
}

func kernelNetlinkRecoveryTriggerFromNeighUpdate(source string, update netlink.NeighUpdate) kernelNetlinkRecoveryTrigger {
	trigger := newKernelNetlinkRecoveryTrigger(source)
	linkIndex := update.LinkIndex
	if source == "fdb" && update.MasterIndex > 0 {
		linkIndex = update.MasterIndex
	}
	trigger.addLinkIndex(linkIndex)
	if source == "neighbor" && update.IP != nil {
		trigger.addBackendIP(update.IP.String())
	}
	if source == "fdb" && isValidHardwareAddr(update.HardwareAddr) {
		trigger.addBackendMAC(update.HardwareAddr.String())
	}
	return trigger
}

func normalizeKernelNetlinkRecoveryTrigger(trigger kernelNetlinkRecoveryTrigger) kernelNetlinkRecoveryTrigger {
	if len(trigger.linkIndexes) == 0 && len(trigger.linkNeighborIndexes) == 0 && len(trigger.linkFDBIndexes) == 0 {
		return trigger
	}
	out := trigger.clone()
	for index := range trigger.linkIndexes {
		if index <= 0 {
			continue
		}
		link, err := netlink.LinkByIndex(index)
		if err != nil || link == nil || link.Attrs() == nil {
			continue
		}
		out.addInterfaceName(link.Attrs().Name)
	}
	for index := range trigger.linkNeighborIndexes {
		if index <= 0 {
			continue
		}
		link, err := netlink.LinkByIndex(index)
		if err != nil || link == nil || link.Attrs() == nil {
			continue
		}
		out.addLinkNeighborInterface(link.Attrs().Name)
	}
	for index := range trigger.linkFDBIndexes {
		if index <= 0 {
			continue
		}
		link, err := netlink.LinkByIndex(index)
		if err != nil || link == nil || link.Attrs() == nil {
			continue
		}
		if isXDPBridgeLink(link) {
			out.addLinkFDBInterface(link.Attrs().Name)
			continue
		}
		if link.Attrs().MasterIndex > 0 {
			master, err := netlink.LinkByIndex(link.Attrs().MasterIndex)
			if err == nil && master != nil && master.Attrs() != nil {
				out.addLinkFDBInterface(master.Attrs().Name)
				continue
			}
		}
		out.addLinkFDBInterface(link.Attrs().Name)
	}
	return out
}

func applyKernelNetlinkLinkRecoveryHints(trigger *kernelNetlinkRecoveryTrigger, link netlink.Link) {
	if trigger == nil || link == nil || link.Attrs() == nil {
		return
	}
	attrs := link.Attrs()
	trigger.addLinkIndex(attrs.Index)
	if isXDPBridgeLink(link) {
		trigger.addLinkNeighborInterface(attrs.Name)
		trigger.addLinkNeighborIndex(attrs.Index)
		trigger.addLinkFDBInterface(attrs.Name)
		trigger.addLinkFDBIndex(attrs.Index)
		return
	}
	trigger.addLinkNeighborInterface(attrs.Name)
	trigger.addLinkNeighborIndex(attrs.Index)
	if attrs.MasterIndex > 0 {
		trigger.addLinkFDBIndex(attrs.MasterIndex)
	}
}
