//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type pluginTCSlot struct {
	index    int
	parent   uint32
	priority uint16
	handle   uint32
}

func pluginTCFilterSlot(filter *netlink.BpfFilter) pluginTCSlot {
	return pluginTCSlot{filter.LinkIndex, filter.Parent, filter.Priority, filter.Handle}
}

type pluginDirectTCUpdate struct {
	next      map[string]*loadedPluginDataplane
	previous  map[pluginTCSlot]*netlink.BpfFilter
	installed []*netlink.BpfFilter
}

func (update *pluginDirectTCUpdate) rollback() error {
	var failures []error
	var pending []*netlink.BpfFilter
	for i := len(update.installed) - 1; i >= 0; i-- {
		filter := update.installed[i]
		var err error
		if old := update.previous[pluginTCFilterSlot(filter)]; old != nil {
			// The old FD remains open until either commit or rollback completes.
			if pluginTCFilterExists(filter) {
				err = netlink.FilterReplace(old)
			} else if !pluginTCFilterExists(old) {
				// Interface removal or an external filter replacement may already
				// have removed our candidate. Preserve the external state; the next
				// reconcile will repair any missing desired attachment.
				err = removeOwnedPluginTCFilter(filter)
			}
		} else {
			err = removeOwnedPluginTCFilter(filter)
		}
		if err != nil {
			failures = append(failures, err)
			pending = append(pending, filter)
		}
	}
	update.installed = pending
	return errors.Join(failures...)
}

// Keep handles stable while priorities continue to express the desired order.
// Reserving all live handles also prevents a new hook replacing a removed
// hook's slot before the candidate has committed.
func assignStablePluginTCHandles(items []pluginDataplaneDesiredPlugin, previous map[string]*loadedPluginDataplane) error {
	type identity struct{ plugin, hook, object, program, iface, attach string }
	key := func(p pluginTCAttachPlan) identity {
		return identity{p.PluginID, p.HookID, p.ObjectID, p.ProgramRef, p.Interface, p.Attach}
	}
	known := make(map[identity]uint16)
	used := make(map[uint16]bool)
	for _, loaded := range previous {
		for _, plan := range loaded.plans {
			known[key(plan)] = plan.HandleMinor
			used[plan.HandleMinor] = true
		}
	}
	next := int(pluginTCFilterHandleBase)
	for i := range items {
		for j := range items[i].attachments {
			plan := &items[i].attachments[j]
			if handle, ok := known[key(*plan)]; ok {
				plan.HandleMinor = handle
				continue
			}
			for next <= int(^uint16(0)) && used[uint16(next)] {
				next++
			}
			if next > int(^uint16(0)) {
				return fmt.Errorf("no free tc handles for live and candidate plugin attachments")
			}
			plan.HandleMinor = uint16(next)
			used[plan.HandleMinor] = true
		}
	}
	return nil
}

func (rt *linuxPluginDataplaneRuntime) reconcileDirectTCPlans(desired []pluginDataplaneDesiredPlugin, states map[string]PluginRuntimeState) pluginRuntimeSnapshot {
	fail := func(err error) pluginRuntimeSnapshot {
		// Report the retained runtime alongside the failure, never a successful
		// desired-state snapshot when staging or rollback failed.
		snapshot := clonePluginRuntimeSnapshot(rt.snapshot)
		if snapshot.Plugins == nil {
			snapshot.Plugins = make(map[string]PluginRuntimeState)
		}
		affected := make(map[string]bool)
		for id, state := range states {
			if rt.loaded[id] == nil {
				snapshot.Plugins[id] = state
			}
		}
		for id := range rt.loaded {
			affected[id] = true
		}
		for id := range rt.retiredTC {
			affected[id] = true
		}
		for _, item := range desired {
			affected[item.plugin.ID] = true
		}
		for id := range affected {
			state := snapshot.Plugins[id]
			state.Mode, state.Error = pluginRuntimeModeError, err.Error()
			state.Reason = "tc update incomplete; live attachments retained"
			snapshot.Plugins[id] = state
		}
		log.Printf("plugin direct tc update failed: %v", err)
		rt.fingerprint = ""
		return snapshot
	}
	if rt.pendingTC != nil {
		if err := rt.pendingTC.rollback(); err != nil {
			return fail(err)
		}
		closeUnusedPluginTCObjects(rt.pendingTC.next, rt.loaded)
		rt.pendingTC = nil
	}
	if err := retirePluginTCGeneration(rt.retiredTC, rt.loaded); err != nil {
		return fail(err)
	}
	rt.retiredTC = nil
	// Explicit removals/revocations must take effect even if another plugin's
	// candidate subsequently fails to load.
	live := make(map[string]*loadedPluginDataplane)
	for _, item := range desired {
		if old := rt.loaded[item.plugin.ID]; old != nil {
			live[item.plugin.ID] = old
		}
	}
	if err := retirePluginTCGeneration(rt.loaded, live); err != nil {
		return fail(err)
	}
	for id := range rt.loaded {
		if _, ok := live[id]; !ok {
			delete(rt.snapshot.Plugins, id)
		}
	}
	rt.loaded = live
	if err := assignStablePluginTCHandles(desired, rt.loaded); err != nil {
		return fail(err)
	}
	fingerprint := pluginDataplaneFingerprint(desired, states)
	if fingerprint == rt.fingerprint && rt.loadedAttachmentsHealthyLocked() {
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}
	next := make(map[string]*loadedPluginDataplane)
	for _, item := range desired {
		loaded, err := preparePluginDirectTC(item, rt.loaded[item.plugin.ID])
		if err != nil {
			closeUnusedPluginTCObjects(next, rt.loaded)
			return fail(fmt.Errorf("prepare plugin %s: %w", item.plugin.ID, err))
		}
		next[item.plugin.ID] = loaded
	}
	update := &pluginDirectTCUpdate{next: next, previous: make(map[pluginTCSlot]*netlink.BpfFilter)}
	for _, loaded := range rt.loaded {
		for _, filter := range loaded.filters {
			update.previous[pluginTCFilterSlot(filter)] = filter
		}
	}
	for _, item := range desired {
		loaded := next[item.plugin.ID]
		for i, filter := range loaded.filters {
			if update.previous[pluginTCFilterSlot(filter)] == filter {
				continue
			}
			if err := installPluginTCFilter(loaded.plans[i], filter); err != nil {
				rt.pendingTC = update
				rollbackErr := update.rollback()
				if rollbackErr == nil {
					closeUnusedPluginTCObjects(next, rt.loaded)
					rt.pendingTC = nil
				}
				return fail(errors.Join(fmt.Errorf("attach plugin %s: %w", item.plugin.ID, err), rollbackErr))
			}
			update.installed = append(update.installed, filter)
		}
	}
	previous := rt.loaded
	rt.loaded = next
	for _, item := range desired {
		loaded := next[item.plugin.ID]
		state := PluginRuntimeState{Mode: pluginRuntimeModeDataplane, Attachable: true,
			Attached: len(loaded.filters) > 0, AttachmentCount: len(loaded.filters), Reason: strings.Join(item.warnings, "; ")}
		for i, plan := range loaded.plans {
			state.Attachments = append(state.Attachments, PluginAttachmentState{HookID: plan.HookID, Engine: kernelEngineTC,
				Attach: plan.Attach, Interface: plan.Interface, Program: plan.ObjectID + ":" + plan.ProgramRef,
				Mode: plan.Mode, Priority: int(plan.Priority), FilterHandle: fmt.Sprintf("0x%x", loaded.filters[i].Handle), Status: "attached"})
		}
		state.Attachments = sortedPluginAttachmentStates(state.Attachments)
		states[item.plugin.ID] = state
	}
	rt.snapshot = pluginRuntimeSnapshot{Plugins: states}
	rt.fingerprint = fingerprint
	if err := retirePluginTCGeneration(previous, next); err != nil {
		rt.retiredTC = previous
		return fail(fmt.Errorf("retire old tc attachments: %w", err))
	}
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func preparePluginDirectTC(item pluginDataplaneDesiredPlugin, previous *loadedPluginDataplane) (*loadedPluginDataplane, error) {
	loaded := &loadedPluginDataplane{plans: append([]pluginTCAttachPlan(nil), item.attachments...)}
	cache := make(map[string]*loadedPluginObject)
	if previous != nil {
		for _, plan := range item.attachments {
			for _, ref := range previous.objects {
				if plan.ObjectSHA256 != "" && ref.ObjectID == plan.ObjectID && ref.ObjectSHA256 == plan.ObjectSHA256 {
					cache[plan.ObjectPath] = &loadedPluginObject{path: plan.ObjectPath, spec: ref.spec, coll: ref.coll}
					break
				}
			}
		}
	}
	fail := func(err error) (*loadedPluginDataplane, error) {
		for _, object := range cache {
			loaded.objects = append(loaded.objects, loadedPluginObjectRef{coll: object.coll})
		}
		// Nothing was attached yet; reused collections remain owned by previous.
		closeUnusedPluginTCObjects(map[string]*loadedPluginDataplane{"candidate": loaded}, map[string]*loadedPluginDataplane{"previous": previous})
		return nil, err
	}
	for _, plan := range item.attachments {
		object, err := loadPluginObjectForAttach(cache, plan.ObjectPath, plan.ObjectSHA256)
		if err != nil {
			return fail(err)
		}
		program, err := pluginProgramForAttach(object, plan.ProgramSection, plan.ProgramRef)
		if err != nil {
			return fail(err)
		}
		filter := newPluginTCFilter(plan, program)
		if previous != nil {
			for _, old := range previous.filters {
				if pluginTCFilterSlot(old) == pluginTCFilterSlot(filter) && old.Id == filter.Id && old.Name == filter.Name && pluginTCFilterExists(old) {
					filter = old
					break
				}
			}
		}
		loaded.filters = append(loaded.filters, filter)
		loaded.objects = append(loaded.objects, loadedPluginObjectRef{PluginID: plan.PluginID, ObjectID: plan.ObjectID,
			ObjectPath: plan.ObjectPath, ObjectSHA256: plan.ObjectSHA256, spec: object.spec, coll: object.coll})
	}
	loaded.objects = uniqueLoadedPluginObjectRefs(loaded.objects)
	return loaded, nil
}

func removeOwnedPluginTCFilter(filter *netlink.BpfFilter) error {
	link, err := pluginControlNetLinkByIndex(filter.LinkIndex)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if errors.As(err, &missing) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return err
	}
	filters, err := pluginTCFilterList(link, filter.Parent)
	if err != nil {
		return err
	}
	for _, current := range filters {
		bpf, ok := current.(*netlink.BpfFilter)
		if ok && pluginTCFilterSlot(bpf) == pluginTCFilterSlot(filter) && bpf.Name == filter.Name && (filter.Id == 0 || bpf.Id == filter.Id) {
			err := netlink.FilterDel(bpf)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
				return nil
			}
			return err
		}
	}
	return nil
}

func retirePluginTCGeneration(previous, next map[string]*loadedPluginDataplane) error {
	keep := make(map[pluginTCSlot]bool)
	for _, loaded := range next {
		if loaded != nil {
			for _, filter := range loaded.filters {
				keep[pluginTCFilterSlot(filter)] = true
			}
		}
	}
	var failures []error
	for _, loaded := range previous {
		if loaded == nil {
			continue
		}
		for _, filter := range loaded.filters {
			if !keep[pluginTCFilterSlot(filter)] {
				if err := removeOwnedPluginTCFilter(filter); err != nil {
					failures = append(failures, err)
				}
			}
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	closeUnusedPluginTCObjects(previous, next)
	return nil
}

func closeUnusedPluginTCObjects(previous, next map[string]*loadedPluginDataplane) {
	keep := make(map[*ebpf.Collection]bool)
	for _, loaded := range next {
		if loaded != nil {
			for _, ref := range loaded.objects {
				keep[ref.coll] = true
			}
		}
	}
	for _, loaded := range previous {
		if loaded != nil {
			for _, ref := range loaded.objects {
				if ref.coll != nil && !keep[ref.coll] {
					ref.coll.Close()
					keep[ref.coll] = true
				}
			}
		}
	}
}
