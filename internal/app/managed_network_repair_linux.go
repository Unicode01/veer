//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
)

var loadManagedNetworkPVEConfigsForTests func() (map[string]string, error)
var managedNetworkRepairLinkOpsForTests managedNetworkRepairLinkOps

type managedNetworkRepairLinkOps interface {
	LinkByName(name string) (netlink.Link, error)
	LinkByIndex(index int) (netlink.Link, error)
	LinkSetNoMaster(link netlink.Link) error
	LinkSetMaster(link netlink.Link, master netlink.Link) error
	LinkSetUp(link netlink.Link) error
}

type linuxManagedNetworkRepairLinkOps struct{}

func (linuxManagedNetworkRepairLinkOps) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (linuxManagedNetworkRepairLinkOps) LinkByIndex(index int) (netlink.Link, error) {
	return netlink.LinkByIndex(index)
}

func (linuxManagedNetworkRepairLinkOps) LinkSetNoMaster(link netlink.Link) error {
	return netlink.LinkSetNoMaster(link)
}

func (linuxManagedNetworkRepairLinkOps) LinkSetMaster(link netlink.Link, master netlink.Link) error {
	return netlink.LinkSetMaster(link, master)
}

func (linuxManagedNetworkRepairLinkOps) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func repairManagedNetworkHostState(items []ManagedNetwork) (managedNetworkRepairResult, error) {
	var result managedNetworkRepairResult
	if len(items) == 0 {
		return result, nil
	}

	enabled := make(map[string]ManagedNetwork)
	bridgeNames := make([]string, 0, len(items))
	for _, item := range items {
		item = normalizeManagedNetwork(item)
		bridge := strings.TrimSpace(item.Bridge)
		if !item.Enabled || bridge == "" {
			continue
		}
		if _, ok := enabled[bridge]; ok {
			continue
		}
		enabled[bridge] = item
		bridgeNames = append(bridgeNames, bridge)
	}
	if len(enabled) == 0 {
		return result, nil
	}
	sort.Strings(bridgeNames)

	netOps := newLinuxManagedNetworkNetOps()
	errs := make([]string, 0)
	for _, bridge := range bridgeNames {
		item := enabled[bridge]
		if !managedNetworkInterfaceNeedsRepair(item) {
			continue
		}
		if err := netOps.EnsureManagedNetworkInterface(managedNetworkInterfaceSpecForItem(item)); err != nil {
			errs = append(errs, fmt.Sprintf("ensure managed interface %s: %v", item.Bridge, err))
			continue
		}
		result.Bridges = append(result.Bridges, item.Bridge)
	}

	bindings, err := loadManagedNetworkPVEBridgeBindings()
	if err != nil {
		errs = append(errs, fmt.Sprintf("load proxmox guest bridge bindings: %v", err))
	} else if len(bindings) > 0 {
		linkResult, err := repairManagedNetworkPVEBridgeLinks(enabled, bindings, currentManagedNetworkRepairLinkOps())
		result.GuestLinks = append(result.GuestLinks, linkResult.GuestLinks...)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	result.Bridges = sortAndDedupeStrings(result.Bridges)
	result.GuestLinks = sortAndDedupeStrings(result.GuestLinks)

	if len(errs) == 0 {
		return result, nil
	}
	return result, errors.New(strings.Join(errs, "; "))
}

func currentManagedNetworkRepairLinkOps() managedNetworkRepairLinkOps {
	if managedNetworkRepairLinkOpsForTests != nil {
		return managedNetworkRepairLinkOpsForTests
	}
	return linuxManagedNetworkRepairLinkOps{}
}

func loadManagedNetworkPVEBridgeBindings() ([]managedNetworkPVEBridgeBinding, error) {
	configs, err := loadManagedNetworkPVEConfigs()
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, nil
	}

	out := make([]managedNetworkPVEBridgeBinding, 0)
	for vmid, content := range configs {
		out = append(out, parseManagedNetworkPVEBridgeBindings(vmid, content)...)
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bridge != out[j].Bridge {
			return out[i].Bridge < out[j].Bridge
		}
		if out[i].VMID != out[j].VMID {
			return out[i].VMID < out[j].VMID
		}
		return out[i].Slot < out[j].Slot
	})
	return out, nil
}

func loadManagedNetworkPVEGuestNICs() ([]managedNetworkPVEGuestNIC, error) {
	configs, err := loadManagedNetworkPVEConfigs()
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, nil
	}

	out := make([]managedNetworkPVEGuestNIC, 0)
	for vmid, content := range configs {
		out = append(out, parseManagedNetworkPVEGuestNICs(vmid, content)...)
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VMID != out[j].VMID {
			return out[i].VMID < out[j].VMID
		}
		if out[i].ConfigKey != out[j].ConfigKey {
			return out[i].ConfigKey < out[j].ConfigKey
		}
		if out[i].Bridge != out[j].Bridge {
			return out[i].Bridge < out[j].Bridge
		}
		return out[i].MACAddress < out[j].MACAddress
	})
	return out, nil
}

func loadManagedNetworkPVEConfigs() (map[string]string, error) {
	if loadManagedNetworkPVEConfigsForTests != nil {
		return loadManagedNetworkPVEConfigsForTests()
	}

	paths, err := filepath.Glob("/etc/pve/qemu-server/*.conf")
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}

	configs := make(map[string]string, len(paths))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		vmid := strings.TrimSpace(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
		if vmid == "" {
			continue
		}
		configs[vmid] = string(body)
	}
	if len(configs) == 0 {
		return nil, nil
	}
	return configs, nil
}

func repairManagedNetworkPVEBridgeLinks(networks map[string]ManagedNetwork, bindings []managedNetworkPVEBridgeBinding, ops managedNetworkRepairLinkOps) (managedNetworkRepairResult, error) {
	var result managedNetworkRepairResult
	if len(networks) == 0 || len(bindings) == 0 || ops == nil {
		return result, nil
	}

	bridges := make(map[string]netlink.Link)
	errs := make([]string, 0)
	for _, binding := range bindings {
		bridgeName := strings.TrimSpace(binding.Bridge)
		if _, ok := networks[bridgeName]; !ok {
			continue
		}

		bridgeLink, ok := bridges[bridgeName]
		if !ok {
			link, err := ops.LinkByName(bridgeName)
			if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
				errs = append(errs, fmt.Sprintf("resolve bridge %s: %v", bridgeName, err))
				continue
			}
			if _, err := ensureManagedNetworkRepairLinkUp(link, ops); err != nil {
				errs = append(errs, fmt.Sprintf("set bridge %s up: %v", bridgeName, err))
				continue
			}
			bridgeLink = link
			bridges[bridgeName] = bridgeLink
		}

		linkResult, err := repairManagedNetworkPVEGuestLink(binding, bridgeLink, ops)
		result.GuestLinks = append(result.GuestLinks, linkResult.GuestLinks...)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	result.GuestLinks = sortAndDedupeStrings(result.GuestLinks)

	if len(errs) == 0 {
		return result, nil
	}
	return result, errors.New(strings.Join(errs, "; "))
}

func repairManagedNetworkPVEGuestLink(binding managedNetworkPVEBridgeBinding, bridge netlink.Link, ops managedNetworkRepairLinkOps) (managedNetworkRepairResult, error) {
	var result managedNetworkRepairResult
	if bridge == nil || bridge.Attrs() == nil || bridge.Attrs().Index <= 0 || ops == nil {
		return result, nil
	}
	for _, name := range managedNetworkPVEGuestLinkCandidates(binding) {
		link, err := ops.LinkByName(name)
		if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
			continue
		}
		changed, err := ensureManagedNetworkGuestLinkAttached(link, bridge, ops)
		if err != nil {
			return result, fmt.Errorf("repair guest link %s -> %s: %w", name, bridge.Attrs().Name, err)
		}
		if changed {
			result.GuestLinks = append(result.GuestLinks, name+"->"+bridge.Attrs().Name)
			log.Printf("managed network repair: reattached guest link %s to %s", name, bridge.Attrs().Name)
		}
		return result, nil
	}
	return result, nil
}

func ensureManagedNetworkGuestLinkAttached(link netlink.Link, bridge netlink.Link, ops managedNetworkRepairLinkOps) (bool, error) {
	if link == nil || bridge == nil || ops == nil {
		return false, nil
	}
	linkAttrs := link.Attrs()
	bridgeAttrs := bridge.Attrs()
	if linkAttrs == nil || bridgeAttrs == nil || bridgeAttrs.Index <= 0 {
		return false, nil
	}
	if linkAttrs.MasterIndex == bridgeAttrs.Index {
		return ensureManagedNetworkRepairLinkUp(link, ops)
	}
	if linkAttrs.MasterIndex > 0 {
		currentMaster, err := ops.LinkByIndex(linkAttrs.MasterIndex)
		if err == nil && currentMaster != nil && currentMaster.Attrs() != nil && currentMaster.Attrs().Index == bridgeAttrs.Index {
			return ensureManagedNetworkRepairLinkUp(link, ops)
		}
		if err := ops.LinkSetNoMaster(link); err != nil {
			return false, err
		}
	}
	if err := ops.LinkSetMaster(link, bridge); err != nil {
		return false, err
	}
	_, err := ensureManagedNetworkRepairLinkUp(link, ops)
	return true, err
}

func managedNetworkInterfaceNeedsRepair(item ManagedNetwork) bool {
	item = normalizeManagedNetwork(item)
	bridgeName := strings.TrimSpace(item.Bridge)
	if bridgeName == "" {
		return false
	}
	link, err := netlink.LinkByName(bridgeName)
	if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return true
	}
	if normalizeManagedNetworkBridgeMode(item.BridgeMode) == managedNetworkBridgeModeCreate && !strings.EqualFold(strings.TrimSpace(link.Type()), "bridge") {
		return true
	}
	return !managedNetworkLinkAdminUp(link)
}

func ensureManagedNetworkRepairLinkUp(link netlink.Link, ops managedNetworkRepairLinkOps) (bool, error) {
	if link == nil || link.Attrs() == nil || ops == nil {
		return false, nil
	}
	if managedNetworkLinkAdminUp(link) {
		return false, nil
	}
	if err := ops.LinkSetUp(link); err != nil {
		return false, err
	}
	return true, nil
}
