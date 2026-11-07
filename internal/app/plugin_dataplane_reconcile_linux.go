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
	if rt.loaded == nil {
		rt.loaded = make(map[string]*loadedPluginDataplane)
	}
	if rt.pendingTC == nil {
		rt.pendingTC = make(map[string]*pluginDirectTCUpdate)
	}
	if rt.retiredTC == nil {
		rt.retiredTC = make(map[string]*loadedPluginDataplane)
	}
	failures := make(map[string]error)
	failed := func(id string, err error) {
		failures[id] = errors.Join(failures[id], err)
		state, ok := states[id]
		if !ok || !state.Attached {
			state = rt.snapshot.Plugins[id]
		}
		state.Mode, state.Error = pluginRuntimeModeError, failures[id].Error()
		state.Reason = "tc update incomplete; live attachments retained"
		states[id] = state
		log.Printf("plugin direct tc %s: %v", id, err)
	}
	// A failed rollback fences only that plugin. Other plugins can still repair
	// missing attachments, update their programs, or be explicitly removed.
	for id, update := range rt.pendingTC {
		if err := update.rollback(); err != nil {
			failed(id, err)
			continue
		}
		closeUnusedPluginTCObjects(update.next, rt.loaded, rt.retiredTC)
		delete(rt.pendingTC, id)
	}
	for id, old := range rt.retiredTC {
		delete(rt.retiredTC, id)
		remaining, err := retirePluginTCGeneration(map[string]*loadedPluginDataplane{id: old}, rt.loaded, rt.retiredTC, rt.pendingTCObjects())
		if err != nil {
			rt.retiredTC[id] = remaining[id]
			failed(pluginTCGenerationID(id, old), err)
		} else {
			delete(rt.retiredTC, id)
		}
	}
	wanted := make(map[string]bool, len(desired))
	for _, item := range desired {
		wanted[item.plugin.ID] = true
	}
	for id, old := range rt.loaded {
		if wanted[id] || failures[id] != nil {
			continue
		}
		remaining, err := retirePluginTCGeneration(map[string]*loadedPluginDataplane{id: old}, nil, rt.retiredTC, rt.pendingTCObjects())
		if err != nil {
			rt.loaded[id] = remaining[id]
			failed(id, err)
		} else {
			delete(rt.loaded, id)
		}
	}
	// Reserve candidate/retired handles too; no healthy plugin may reuse a slot
	// whose cleanup is still pending.
	reserved := make(map[string]*loadedPluginDataplane)
	for id, old := range rt.loaded {
		reserved[id] = old
	}
	for id, old := range rt.retiredTC {
		reserved["retired/"+id] = old
	}
	for id, update := range rt.pendingTC {
		for key, old := range update.next {
			reserved["pending/"+id+"/"+key] = old
		}
	}
	if err := assignStablePluginTCHandles(desired, reserved); err != nil {
		for _, item := range desired {
			failed(item.plugin.ID, err)
		}
	} else {
		fingerprint := pluginDataplaneFingerprint(desired, states)
		if len(failures) == 0 && fingerprint == rt.fingerprint && rt.loadedAttachmentsHealthyLocked() {
			return clonePluginRuntimeSnapshot(rt.snapshot)
		}
		defer func() {
			if len(failures) == 0 {
				rt.fingerprint = fingerprint
			}
		}()
		for _, item := range desired {
			id := item.plugin.ID
			if failures[id] != nil {
				continue
			}
			old := rt.loaded[id]
			loaded, err := preparePluginDirectTC(item, old)
			if err != nil {
				failed(id, fmt.Errorf("prepare: %w", err))
				continue
			}
			candidate := map[string]*loadedPluginDataplane{id: loaded}
			update := &pluginDirectTCUpdate{next: candidate, previous: make(map[pluginTCSlot]*netlink.BpfFilter)}
			if old != nil {
				for _, filter := range old.filters {
					update.previous[pluginTCFilterSlot(filter)] = filter
				}
			}
			for i, filter := range loaded.filters {
				if update.previous[pluginTCFilterSlot(filter)] == filter {
					continue
				}
				if err = installPluginTCFilter(loaded.plans[i], filter); err != nil {
					break
				}
				update.installed = append(update.installed, filter)
			}
			if err != nil {
				rollbackErr := update.rollback()
				if rollbackErr != nil {
					rt.pendingTC[id] = update
				} else {
					closeUnusedPluginTCObjects(candidate, rt.loaded, rt.retiredTC)
				}
				failed(id, errors.Join(fmt.Errorf("attach: %w", err), rollbackErr))
				continue
			}
			rt.loaded[id] = loaded
			states[id] = pluginDirectTCRuntimeState(item, loaded)
			if old != nil {
				remaining, retireErr := retirePluginTCGeneration(map[string]*loadedPluginDataplane{id: old}, rt.loaded, rt.retiredTC, rt.pendingTCObjects())
				if retireErr != nil {
					rt.retiredTC[id] = remaining[id]
					failed(id, fmt.Errorf("retire: %w", retireErr))
				}
			}
		}
	}
	rt.snapshot = pluginRuntimeSnapshot{Plugins: states}
	rt.fingerprint = ""
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func pluginDirectTCRuntimeState(item pluginDataplaneDesiredPlugin, loaded *loadedPluginDataplane) PluginRuntimeState {
	state := PluginRuntimeState{Mode: pluginRuntimeModeDataplane, Attachable: true,
		Attached: len(loaded.filters) > 0, AttachmentCount: len(loaded.filters), Reason: strings.Join(item.warnings, "; ")}
	for i, plan := range loaded.plans {
		state.Attachments = append(state.Attachments, PluginAttachmentState{HookID: plan.HookID, Engine: kernelEngineTC,
			Attach: plan.Attach, Interface: plan.Interface, Program: plan.ObjectID + ":" + plan.ProgramRef,
			Mode: plan.Mode, Priority: int(plan.Priority), FilterHandle: fmt.Sprintf("0x%x", loaded.filters[i].Handle), Status: "attached"})
	}
	state.Attachments = sortedPluginAttachmentStates(state.Attachments)
	return state
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

// Return only resources that could not be detached. Successful slots release
// their collections unless another live or pending generation still uses them.
func retirePluginTCGeneration(previous, next map[string]*loadedPluginDataplane, retained ...map[string]*loadedPluginDataplane) (map[string]*loadedPluginDataplane, error) {
	return retirePluginTCGenerationWithRemove(previous, next, removeOwnedPluginTCFilter, retained...)
}

func retirePluginTCGenerationWithRemove(previous, next map[string]*loadedPluginDataplane, remove func(*netlink.BpfFilter) error, retained ...map[string]*loadedPluginDataplane) (map[string]*loadedPluginDataplane, error) {
	keep := make(map[pluginTCSlot]bool)
	for _, loaded := range next {
		if loaded != nil {
			for _, filter := range loaded.filters {
				keep[pluginTCFilterSlot(filter)] = true
			}
		}
	}
	remaining := make(map[string]*loadedPluginDataplane)
	var failures []error
	for id, loaded := range previous {
		if loaded == nil {
			continue
		}
		pending := &loadedPluginDataplane{objects: loaded.objects}
		for i, filter := range loaded.filters {
			if keep[pluginTCFilterSlot(filter)] {
				continue
			}
			if err := remove(filter); err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", id, err))
				pending.filters = append(pending.filters, filter)
				if i < len(loaded.plans) {
					pending.plans = append(pending.plans, loaded.plans[i])
				}
			}
		}
		if len(pending.filters) > 0 {
			remaining[id] = pending
		}
	}
	closeUnusedPluginTCObjects(previous, append(retained, next, remaining)...)
	return remaining, errors.Join(failures...)
}

func closeUnusedPluginTCObjects(previous map[string]*loadedPluginDataplane, retained ...map[string]*loadedPluginDataplane) {
	keep := make(map[*ebpf.Collection]bool)
	for _, next := range retained {
		for _, loaded := range next {
			if loaded != nil {
				for _, ref := range loaded.objects {
					keep[ref.coll] = true
				}
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

func pluginTCGenerationID(fallback string, loaded *loadedPluginDataplane) string {
	if loaded != nil && len(loaded.plans) > 0 && loaded.plans[0].PluginID != "" {
		return loaded.plans[0].PluginID
	}
	return fallback
}

func (rt *linuxPluginDataplaneRuntime) pendingTCObjects() map[string]*loadedPluginDataplane {
	all := make(map[string]*loadedPluginDataplane)
	for id, update := range rt.pendingTC {
		for key, loaded := range update.next {
			all[id+"/"+key] = loaded
		}
	}
	return all
}
