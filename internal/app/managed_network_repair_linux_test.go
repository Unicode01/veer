//go:build linux

package app

import (
	"fmt"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fakeManagedNetworkRepairLinkOps struct {
	byName    map[string]netlink.Link
	byIndex   map[int]netlink.Link
	noMaster  []string
	setMaster []string
	setUp     []string
}

func (ops *fakeManagedNetworkRepairLinkOps) LinkByName(name string) (netlink.Link, error) {
	link, ok := ops.byName[name]
	if !ok {
		return nil, fmt.Errorf("link %s not found", name)
	}
	return link, nil
}

func (ops *fakeManagedNetworkRepairLinkOps) LinkByIndex(index int) (netlink.Link, error) {
	link, ok := ops.byIndex[index]
	if !ok {
		return nil, fmt.Errorf("link index %d not found", index)
	}
	return link, nil
}

func (ops *fakeManagedNetworkRepairLinkOps) LinkSetNoMaster(link netlink.Link) error {
	ops.noMaster = append(ops.noMaster, link.Attrs().Name)
	link.Attrs().MasterIndex = 0
	return nil
}

func (ops *fakeManagedNetworkRepairLinkOps) LinkSetMaster(link netlink.Link, master netlink.Link) error {
	ops.setMaster = append(ops.setMaster, link.Attrs().Name+"->"+master.Attrs().Name)
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func (ops *fakeManagedNetworkRepairLinkOps) LinkSetUp(link netlink.Link) error {
	ops.setUp = append(ops.setUp, link.Attrs().Name)
	link.Attrs().RawFlags |= unix.IFF_UP
	return nil
}

func TestRepairManagedNetworkPVEBridgeLinksPrefersFwprWhenPresent(t *testing.T) {
	t.Parallel()

	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vmbr1", Index: 10}}
	fwpr := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fwpr100p0", Index: 11}}
	tap := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tap100i0", Index: 12}}
	ops := &fakeManagedNetworkRepairLinkOps{
		byName: map[string]netlink.Link{
			"vmbr1":     bridge,
			"fwpr100p0": fwpr,
			"tap100i0":  tap,
		},
		byIndex: map[int]netlink.Link{
			10: bridge,
			11: fwpr,
			12: tap,
		},
	}

	result, err := repairManagedNetworkPVEBridgeLinks(
		map[string]ManagedNetwork{"vmbr1": {Bridge: "vmbr1", Enabled: true}},
		[]managedNetworkPVEBridgeBinding{{VMID: "100", Slot: "0", Bridge: "vmbr1"}},
		ops,
	)
	if err != nil {
		t.Fatalf("repairManagedNetworkPVEBridgeLinks() error = %v", err)
	}
	if len(result.GuestLinks) != 1 || result.GuestLinks[0] != "fwpr100p0->vmbr1" {
		t.Fatalf("GuestLinks = %v, want [fwpr100p0->vmbr1]", result.GuestLinks)
	}
	if len(ops.setMaster) != 1 || ops.setMaster[0] != "fwpr100p0->vmbr1" {
		t.Fatalf("setMaster = %v, want [fwpr100p0->vmbr1]", ops.setMaster)
	}
	if len(ops.setUp) != 2 || ops.setUp[0] != "vmbr1" || ops.setUp[1] != "fwpr100p0" {
		t.Fatalf("setUp = %v, want [vmbr1 fwpr100p0]", ops.setUp)
	}
}

func TestEnsureManagedNetworkGuestLinkAttachedDetachesOldMasterBeforeReattach(t *testing.T) {
	t.Parallel()

	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vmbr1", Index: 10, HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}}}
	oldBridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vmbr9", Index: 99}}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tap100i0", Index: 11, MasterIndex: 99}}
	ops := &fakeManagedNetworkRepairLinkOps{
		byName: map[string]netlink.Link{
			"vmbr1":    bridge,
			"vmbr9":    oldBridge,
			"tap100i0": link,
		},
		byIndex: map[int]netlink.Link{
			10: bridge,
			11: link,
			99: oldBridge,
		},
	}

	changed, err := ensureManagedNetworkGuestLinkAttached(link, bridge, ops)
	if err != nil {
		t.Fatalf("ensureManagedNetworkGuestLinkAttached() error = %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if len(ops.noMaster) != 1 || ops.noMaster[0] != "tap100i0" {
		t.Fatalf("noMaster = %v, want [tap100i0]", ops.noMaster)
	}
	if len(ops.setMaster) != 1 || ops.setMaster[0] != "tap100i0->vmbr1" {
		t.Fatalf("setMaster = %v, want [tap100i0->vmbr1]", ops.setMaster)
	}
	if len(ops.setUp) != 1 || ops.setUp[0] != "tap100i0" {
		t.Fatalf("setUp = %v, want [tap100i0]", ops.setUp)
	}
}

func TestEnsureManagedNetworkGuestLinkAttachedDoesNothingWhenAlreadyAttachedAndUp(t *testing.T) {
	t.Parallel()

	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vmbr1", Index: 10, RawFlags: unix.IFF_UP}}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tap100i0", Index: 11, MasterIndex: 10, RawFlags: unix.IFF_UP}}
	ops := &fakeManagedNetworkRepairLinkOps{
		byName: map[string]netlink.Link{
			"vmbr1":    bridge,
			"tap100i0": link,
		},
		byIndex: map[int]netlink.Link{
			10: bridge,
			11: link,
		},
	}

	changed, err := ensureManagedNetworkGuestLinkAttached(link, bridge, ops)
	if err != nil {
		t.Fatalf("ensureManagedNetworkGuestLinkAttached() error = %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false")
	}
	if len(ops.noMaster) != 0 {
		t.Fatalf("noMaster = %v, want none", ops.noMaster)
	}
	if len(ops.setMaster) != 0 {
		t.Fatalf("setMaster = %v, want none", ops.setMaster)
	}
	if len(ops.setUp) != 0 {
		t.Fatalf("setUp = %v, want none", ops.setUp)
	}
}
