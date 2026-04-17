//go:build linux

package managednet

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var managedNetworkPVEConfigGlobs = []string{
	"/etc/pve/qemu-server/*.conf",
	"/etc/pve/lxc/*.conf",
}

type linuxRepairLinkOps struct{}

type managedNetworkInterfaceSpec struct {
	Name            string
	Mode            string
	BridgeMTU       int
	BridgeVLANAware bool
}

func (linuxRepairLinkOps) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (linuxRepairLinkOps) LinkByIndex(index int) (netlink.Link, error) {
	return netlink.LinkByIndex(index)
}

func (linuxRepairLinkOps) LinkSetNoMaster(link netlink.Link) error {
	return netlink.LinkSetNoMaster(link)
}

func (linuxRepairLinkOps) LinkSetMaster(link netlink.Link, master netlink.Link) error {
	return netlink.LinkSetMaster(link, master)
}

func (linuxRepairLinkOps) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func RepairHostState(items []ManagedNetwork, opts RepairOptions) (RepairResult, error) {
	var result RepairResult
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

	errs := make([]string, 0)
	for _, bridge := range bridgeNames {
		item := enabled[bridge]
		if !managedNetworkInterfaceNeedsRepair(item) {
			continue
		}
		if err := ensureManagedNetworkInterface(managedNetworkInterfaceSpecForItem(item)); err != nil {
			errs = append(errs, fmt.Sprintf("ensure managed interface %s: %v", item.Bridge, err))
			continue
		}
		result.Bridges = append(result.Bridges, item.Bridge)
	}

	bindings, err := LoadPVEBridgeBindings(opts)
	if err != nil {
		errs = append(errs, fmt.Sprintf("load proxmox guest bridge bindings: %v", err))
	} else if len(bindings) > 0 {
		linkResult, err := RepairPVEBridgeLinks(enabled, bindings, currentRepairLinkOps(opts))
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

func currentRepairLinkOps(opts RepairOptions) RepairLinkOps {
	if opts.LinkOps != nil {
		return opts.LinkOps
	}
	return linuxRepairLinkOps{}
}

func LoadPVEBridgeBindings(opts RepairOptions) ([]PVEBridgeBinding, error) {
	configs, err := loadPVEConfigs(opts)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, nil
	}

	out := make([]PVEBridgeBinding, 0)
	for vmid, content := range configs {
		out = append(out, ParsePVEBridgeBindings(vmid, content)...)
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

func LoadPVEGuestNICs(opts RepairOptions) ([]PVEGuestNIC, error) {
	configs, err := loadPVEConfigs(opts)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, nil
	}

	out := make([]PVEGuestNIC, 0)
	for vmid, content := range configs {
		out = append(out, ParsePVEGuestNICs(vmid, content)...)
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

func loadPVEConfigs(opts RepairOptions) (map[string]string, error) {
	if opts.LoadPVEConfigs != nil {
		return opts.LoadPVEConfigs()
	}
	return LoadPVEConfigsFromGlobs(managedNetworkPVEConfigGlobs)
}

func LoadPVEConfigsFromGlobs(patterns []string) (map[string]string, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	paths := make([]string, 0)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
	}
	if len(paths) == 0 {
		return nil, nil
	}
	sort.Strings(paths)

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

func RepairPVEBridgeLinks(networks map[string]ManagedNetwork, bindings []PVEBridgeBinding, ops RepairLinkOps) (RepairResult, error) {
	var result RepairResult
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
			if _, err := ensureRepairLinkUp(link, ops); err != nil {
				errs = append(errs, fmt.Sprintf("set bridge %s up: %v", bridgeName, err))
				continue
			}
			bridgeLink = link
			bridges[bridgeName] = bridgeLink
		}

		linkResult, err := repairPVEGuestLink(binding, bridgeLink, ops)
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

func repairPVEGuestLink(binding PVEBridgeBinding, bridge netlink.Link, ops RepairLinkOps) (RepairResult, error) {
	var result RepairResult
	if bridge == nil || bridge.Attrs() == nil || bridge.Attrs().Index <= 0 || ops == nil {
		return result, nil
	}
	for _, name := range PVEGuestLinkCandidates(binding) {
		link, err := ops.LinkByName(name)
		if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
			continue
		}
		changed, err := EnsureGuestLinkAttached(link, bridge, ops)
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

func EnsureGuestLinkAttached(link netlink.Link, bridge netlink.Link, ops RepairLinkOps) (bool, error) {
	if link == nil || bridge == nil || ops == nil {
		return false, nil
	}
	linkAttrs := link.Attrs()
	bridgeAttrs := bridge.Attrs()
	if linkAttrs == nil || bridgeAttrs == nil || bridgeAttrs.Index <= 0 {
		return false, nil
	}
	if linkAttrs.MasterIndex == bridgeAttrs.Index {
		return ensureRepairLinkUp(link, ops)
	}
	if linkAttrs.MasterIndex > 0 {
		currentMaster, err := ops.LinkByIndex(linkAttrs.MasterIndex)
		if err == nil && currentMaster != nil && currentMaster.Attrs() != nil && currentMaster.Attrs().Index == bridgeAttrs.Index {
			return ensureRepairLinkUp(link, ops)
		}
		if err := ops.LinkSetNoMaster(link); err != nil {
			return false, err
		}
	}
	if err := ops.LinkSetMaster(link, bridge); err != nil {
		return false, err
	}
	_, err := ensureRepairLinkUp(link, ops)
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
	if normalizeManagedNetworkBridgeMode(item.BridgeMode) == BridgeModeCreate && !strings.EqualFold(strings.TrimSpace(link.Type()), "bridge") {
		return true
	}
	return !repairLinkAdminUp(link)
}

func ensureRepairLinkUp(link netlink.Link, ops RepairLinkOps) (bool, error) {
	if link == nil || link.Attrs() == nil || ops == nil {
		return false, nil
	}
	if repairLinkAdminUp(link) {
		return false, nil
	}
	if err := ops.LinkSetUp(link); err != nil {
		return false, err
	}
	return true, nil
}

func repairLinkAdminUp(link netlink.Link) bool {
	if link == nil || link.Attrs() == nil {
		return false
	}
	return link.Attrs().RawFlags&unix.IFF_UP != 0
}

func managedNetworkInterfaceSpecForItem(item ManagedNetwork) managedNetworkInterfaceSpec {
	item = normalizeManagedNetwork(item)
	return managedNetworkInterfaceSpec{
		Name:            item.Bridge,
		Mode:            item.BridgeMode,
		BridgeMTU:       item.BridgeMTU,
		BridgeVLANAware: item.BridgeVLANAware,
	}
}

func ensureManagedNetworkInterface(spec managedNetworkInterfaceSpec) error {
	interfaceName := strings.TrimSpace(spec.Name)
	mode := normalizeManagedNetworkBridgeMode(spec.Mode)
	if interfaceName == "" {
		return fmt.Errorf("interface is required")
	}

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if !errors.As(err, &linkNotFound) {
			return err
		}
		if mode == BridgeModeExisting {
			return fmt.Errorf("interface %q does not exist", interfaceName)
		}
		attrs := netlink.LinkAttrs{Name: interfaceName}
		if spec.BridgeMTU > 0 {
			attrs.MTU = spec.BridgeMTU
		}
		bridge := &netlink.Bridge{LinkAttrs: attrs}
		bridge.VlanFiltering = &spec.BridgeVLANAware
		if err := netlink.LinkAdd(bridge); err != nil {
			return err
		}
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			return err
		}
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", interfaceName)
	}
	if mode == BridgeModeCreate && !strings.EqualFold(strings.TrimSpace(link.Type()), "bridge") {
		return fmt.Errorf("interface %q already exists and is not a bridge", interfaceName)
	}
	if mode == BridgeModeCreate {
		if spec.BridgeMTU > 0 && link.Attrs().MTU != spec.BridgeMTU {
			if err := netlink.LinkSetMTU(link, spec.BridgeMTU); err != nil {
				return err
			}
		}
		if bridge, ok := link.(*netlink.Bridge); ok {
			if bridge.VlanFiltering == nil || *bridge.VlanFiltering != spec.BridgeVLANAware {
				if err := netlink.BridgeSetVlanFiltering(bridge, spec.BridgeVLANAware); err != nil {
					return err
				}
			}
		}
	}
	if !repairLinkAdminUp(link) {
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
	}
	return nil
}
