//go:build linux

package app

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

func TestPluginDirectTCIncrementalReconcile(t *testing.T) {
	if os.Getenv("FORWARD_RUN_PLUGIN_DATAPLANE_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires privileged plugin dataplane test environment")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	newLink := func(suffix int) netlink.Link {
		t.Helper()
		name := fmt.Sprintf("vpt%x%d", time.Now().UnixNano()&0xffffff, suffix)
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		actual, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		return actual
	}
	first, second := newLink(1), newLink(2)
	rt := &linuxPluginDataplaneRuntime{loaded: make(map[string]*loadedPluginDataplane)}
	t.Cleanup(func() { _ = rt.Close() })
	newPlugin := func(id string) pluginDataplaneDesiredPlugin {
		t.Helper()
		spec := &ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{"counts": {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}},
			Programs: map[string]*ebpf.ProgramSpec{
				"observe":   {Name: "observe", Type: ebpf.SchedCLS, SectionName: "tc/ingress", License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}},
				"alternate": {Name: "alternate", Type: ebpf.SchedCLS, SectionName: "tc/alternate", License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}},
			},
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			t.Fatal(err)
		}
		rt.loaded[id] = &loadedPluginDataplane{objects: []loadedPluginObjectRef{{PluginID: id, ObjectID: "observer", ObjectSHA256: id, coll: coll, spec: spec}}}
		return pluginDataplaneDesiredPlugin{plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: id}}, attachments: []pluginTCAttachPlan{{
			PluginID: id, HookID: "observe", ObjectID: "observer", ObjectPath: id + ".o", ObjectSHA256: id,
			ProgramRef: "observe", ProgramSection: "tc/ingress", Interface: first.Attrs().Name, IfIndex: first.Attrs().Index, Attach: "ingress", Mode: "observe",
		}}}
	}
	a, b := newPlugin("a"), newPlugin("b")
	reconcile := func(items ...pluginDataplaneDesiredPlugin) pluginRuntimeSnapshot {
		t.Helper()
		// Copy attachment slices because runtime slot allocation mutates the plan.
		for i := range items {
			items[i].attachments = append([]pluginTCAttachPlan(nil), items[i].attachments...)
		}
		if err := assignPluginTCFilterIDs(items); err != nil {
			t.Fatal(err)
		}
		return rt.reconcileDirectTCPlans(items, make(map[string]PluginRuntimeState))
	}
	assertHealthy := func(snapshot pluginRuntimeSnapshot) {
		t.Helper()
		for id, state := range snapshot.Plugins {
			if state.Error != "" {
				t.Fatalf("%s: %s", id, state.Error)
			}
		}
		if !rt.loadedAttachmentsHealthyLocked() {
			t.Fatal("TC attachment not healthy")
		}
	}
	assertHealthy(reconcile(a, b))
	oldA, oldB := rt.loaded["a"].filters[0], rt.loaded["b"].filters[0]
	counts := rt.loaded["a"].objects[0].coll.Maps["counts"]
	if err := counts.Put(uint32(0), uint64(73)); err != nil {
		t.Fatal(err)
	}
	assertState := func() {
		t.Helper()
		if rt.loaded["a"].objects[0].coll.Maps["counts"] != counts {
			t.Fatal("unmodified map was replaced")
		}
		var value uint64
		if err := counts.Lookup(uint32(0), &value); err != nil || value != 73 {
			t.Fatalf("map state = %d, %v", value, err)
		}
	}
	t.Run("missing_filter_only_repairs_affected_attachment", func(t *testing.T) {
		if err := netlink.FilterDel(oldB); err != nil {
			t.Fatal(err)
		}
		assertHealthy(reconcile(a, b))
		if rt.loaded["a"].filters[0] != oldA || rt.loaded["b"].filters[0].Id != oldB.Id {
			t.Fatal("unrelated filter or program replaced")
		}
		assertState()
	})
	t.Run("interface_change_preserves_other_plugin_and_maps", func(t *testing.T) {
		oldB = rt.loaded["b"].filters[0]
		a.attachments[0].Interface = second.Attrs().Name
		a.attachments[0].IfIndex = second.Attrs().Index
		assertHealthy(reconcile(a, b))
		if pluginTCFilterExists(oldA) || rt.loaded["b"].filters[0] != oldB {
			t.Fatal("interface move affected unrelated filter or retained old attachment")
		}
		if rt.loaded["a"].filters[0].Id != oldA.Id {
			t.Fatal("interface move reloaded program")
		}
		assertState()
	})
	t.Run("replacement_rollback_restores_old_program", func(t *testing.T) {
		old := rt.loaded["a"].filters[0]
		plan := rt.loaded["a"].plans[0]
		candidate := newPluginTCFilter(plan, rt.loaded["a"].objects[0].coll.Programs["alternate"])
		if err := installPluginTCFilter(plan, candidate); err != nil {
			t.Fatal(err)
		}
		update := &pluginDirectTCUpdate{previous: map[pluginTCSlot]*netlink.BpfFilter{pluginTCFilterSlot(old): old}, installed: []*netlink.BpfFilter{candidate}}
		if err := update.rollback(); err != nil {
			t.Fatal(err)
		}
		if !pluginTCFilterExists(old) || pluginTCFilterExists(candidate) {
			t.Fatal("rollback did not restore original program")
		}
		assertState()
	})
	t.Run("attach_failure_rolls_back_new_filters", func(t *testing.T) {
		changedA := a
		changedA.attachments = append([]pluginTCAttachPlan(nil), a.attachments...)
		changedA.attachments[0].ProgramRef = "alternate"
		changedA.attachments[0].ProgramSection = "tc/alternate"
		badB := b
		badB.attachments = append([]pluginTCAttachPlan(nil), b.attachments...)
		badB.attachments[0].IfIndex = 1 << 30
		snapshot := reconcile(changedA, badB)
		if snapshot.Plugins["b"].Error == "" {
			t.Fatal("attachment failure hidden")
		}
		if !pluginTCFilterExists(rt.loaded["a"].filters[0]) || !pluginTCFilterExists(oldB) {
			t.Fatal("failed candidate removed live filters")
		}
		filters, err := pluginTCFilterList(second, netlink.HANDLE_MIN_INGRESS)
		if err != nil || len(filters) != 1 {
			t.Fatalf("rollback left extra filters: %d, %v", len(filters), err)
		}
		assertHealthy(reconcile(a, b))
		assertState()
	})
	t.Run("prepare_failure_preserves_live_runtime_and_allows_removal", func(t *testing.T) {
		bad := a
		bad.attachments = append([]pluginTCAttachPlan(nil), a.attachments...)
		bad.attachments[0].ObjectSHA256 = "changed"
		bad.attachments[0].ObjectPath = "/nonexistent/veer-plugin-audit.o"
		snapshot := reconcile(bad, b)
		if snapshot.Plugins["a"].Error == "" || !pluginTCFilterExists(oldB) {
			t.Fatal("prepare failure changed live runtime")
		}
		assertState()
		snapshot = reconcile(bad)
		if snapshot.Plugins["a"].Error == "" || pluginTCFilterExists(oldB) {
			t.Fatal("unrelated load failure prevented explicit plugin removal")
		}
		assertState()
		assertHealthy(reconcile(a))
	})
}
