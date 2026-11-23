//go:build linux

package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/nlretry"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// These mirror struct hairpin_key_v4, struct hairpin_addrs_v4 and
// FORWARD_TC_HAIRPIN_ADDRS in forward-tc-bpf.c.
const (
	kernelHairpinMapNameV4      = "hairpin_v4"
	kernelHairpinAddrsMapNameV4 = "hairpin_addrs_v4"
	kernelHairpinAddrSlots      = 8
)

type tcHairpinKeyV4 struct {
	DstAddr uint32
	DstPort uint16
	Proto   uint8
	Pad     uint8
}

type tcHairpinAddrsV4 struct {
	Count uint32
	Addrs [kernelHairpinAddrSlots]uint32
}

// buildKernelHairpinEntries lists the forwards a guest behind egress NAT can
// reach through an address of this host (hairpin, or NAT loopback): every
// IPv4 port forward, keyed by its inbound address, port and protocol, as a
// full NAT rule. A transparent forward gets the source address the
// non-transparent one would use on its outbound interface, so the backend
// answers through this host and not straight back to a neighbour on its own
// network. A forward on any address of its inbound interface is listed under
// each IPv4 address the interface has. Each entry names the forward's inbound
// interface: guests on it, or on a port of it, reach the forward by the usual
// path and are left to it. Without egress NAT there is nothing to hairpin
// from, and the list is empty.
//
// sourceOf returns the source address a non-transparent forward would use for
// item, and addrsOf an interface's IPv4 addresses, both in host order. The
// notes name forwards left out.
func buildKernelHairpinEntries(prepared []preparedKernelRule, sourceOf func(item preparedKernelRule) (uint32, error), addrsOf func(ifindex int) []uint32) (map[tcHairpinKeyV4]tcRuleValueV4, []string) {
	entries := make(map[tcHairpinKeyV4]tcRuleValueV4)
	hasEgressNAT := false
	for _, item := range prepared {
		if item.value.Flags&kernelRuleFlagEgressNAT != 0 {
			hasEgressNAT = true
			break
		}
	}
	if !hasEgressNAT {
		return entries, nil
	}

	var notes []string
	noted := make(map[int64]struct{})
	note := func(item preparedKernelRule, err error) {
		if _, ok := noted[item.rule.ID]; ok {
			return
		}
		noted[item.rule.ID] = struct{}{}
		notes = append(notes, fmt.Sprintf("%s %d: %v", kernelRuleLogKind(item.rule), kernelRuleLogOwnerID(item.rule), err))
	}
	for _, item := range prepared {
		if item.spec.Family == ipFamilyIPv6 || item.value.Flags&(kernelRuleFlagEgressNAT|kernelRuleFlagPassthrough|kernelRuleFlagDrop) != 0 {
			continue
		}
		value := item.value
		if value.Flags&kernelRuleFlagFullNAT == 0 {
			natAddr, err := sourceOf(item)
			if err == nil && natAddr == 0 {
				err = errors.New("no IPv4 address to answer from")
			}
			if err != nil {
				note(item, err)
				continue
			}
			value.NATAddr = natAddr
			value.Flags |= kernelRuleFlagFullNAT
		}
		value.HairpinInIfIndex = uint32(item.inIfIndex)
		addrs := []uint32{item.key.DstAddr}
		if item.key.DstAddr == 0 {
			addrs = addrsOf(item.inIfIndex)
		}
		for _, addr := range addrs {
			if addr == 0 {
				continue
			}
			key := tcHairpinKeyV4{DstAddr: addr, DstPort: item.key.DstPort, Proto: item.key.Proto}
			if _, taken := entries[key]; taken {
				continue
			}
			entries[key] = value
		}
	}
	return entries, notes
}

// kernelHairpinAddrs is the address list hairpin_addrs_v4 gates lookups with.
func kernelHairpinAddrs(entries map[tcHairpinKeyV4]tcRuleValueV4) tcHairpinAddrsV4 {
	seen := make(map[uint32]struct{})
	var addrs []uint32
	for key := range entries {
		if _, ok := seen[key.DstAddr]; ok {
			continue
		}
		seen[key.DstAddr] = struct{}{}
		addrs = append(addrs, key.DstAddr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	out := tcHairpinAddrsV4{Count: uint32(len(addrs))}
	copy(out.Addrs[:], addrs)
	return out
}

// syncKernelHairpinMaps makes the hairpin maps hold entries. New entries go in
// before the address list names them, and stale ones go after it stops
// naming theirs. Objects without the maps are left alone.
func syncKernelHairpinMaps(coll *ebpf.Collection, entries map[tcHairpinKeyV4]tcRuleValueV4) error {
	if coll == nil {
		return nil
	}
	hairpin := coll.Maps[kernelHairpinMapNameV4]
	addrs := coll.Maps[kernelHairpinAddrsMapNameV4]
	if hairpin == nil || addrs == nil {
		return nil
	}
	var stale []tcHairpinKeyV4
	iter := hairpin.Iterate()
	var key tcHairpinKeyV4
	var value tcRuleValueV4
	for iter.Next(&key, &value) {
		if _, ok := entries[key]; !ok {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate hairpin map: %w", err)
	}
	for key, value := range entries {
		if err := hairpin.Put(key, value); err != nil {
			return fmt.Errorf("write hairpin entry: %w", err)
		}
	}
	if err := addrs.Put(uint32(0), kernelHairpinAddrs(entries)); err != nil {
		return fmt.Errorf("write hairpin addresses: %w", err)
	}
	for _, key := range stale {
		if err := hairpin.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale hairpin entry: %w", err)
		}
	}
	return nil
}

// kernelHairpinSourceOf resolves, through ctx, the address a non-transparent
// forward would source NAT to on its outbound interface.
func kernelHairpinSourceOf(ctx *kernelPrepareContext) func(item preparedKernelRule) (uint32, error) {
	return func(item preparedKernelRule) (uint32, error) {
		link, err := ctx.linkByName(item.rule.OutInterface)
		if err != nil {
			return 0, fmt.Errorf("resolve outbound interface %q: %w", item.rule.OutInterface, err)
		}
		natAddr, err := ctx.resolveSNATIPv4(link, item.rule.OutIP, item.rule.OutSourceIP)
		if err != nil {
			return 0, fmt.Errorf("source address on %q: %w", item.rule.OutInterface, err)
		}
		return natAddr, nil
	}
}

// kernelInterfaceIPv4Addrs returns the IPv4 addresses of an interface in host
// order, or none when it cannot be read.
func kernelInterfaceIPv4Addrs(ifindex int) []uint32 {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil
	}
	list, err := nlretry.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	out := make([]uint32, 0, len(list))
	for _, addr := range list {
		if addr.IPNet == nil {
			continue
		}
		if ip := addr.IP.To4(); ip != nil {
			out = append(out, uint32(ip[0])<<24|uint32(ip[1])<<16|uint32(ip[2])<<8|uint32(ip[3]))
		}
	}
	return out
}

// syncKernelHairpinLocked brings the hairpin maps of coll in line with the
// prepared rules. Hairpin is best effort: a failure is logged and leaves the
// rest of the reconcile alone.
func (rt *linuxKernelRuleRuntime) syncKernelHairpinLocked(coll *ebpf.Collection, prepared []preparedKernelRule) {
	ctx := newKernelPrepareContext(rt.enableTrafficStats, rt.enablePreparedL2, rt.enableReplyL2Cache)
	entries, notes := buildKernelHairpinEntries(prepared, kernelHairpinSourceOf(ctx), kernelInterfaceIPv4Addrs)
	if len(notes) == 0 {
		rt.hairpinLog.Reset()
	} else {
		rt.hairpinLog.Logf("kernel dataplane hairpin: left out %s", strings.Join(notes, "; "))
	}
	if err := syncKernelHairpinMaps(coll, entries); err != nil {
		rt.hairpinLog.Logf("kernel dataplane hairpin: %v", err)
	}
}
