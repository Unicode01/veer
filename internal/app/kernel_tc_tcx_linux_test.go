//go:build linux

package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// kernelTCXProgramAttached reports whether a tcx program whose kernel name
// satisfies match runs on the hook.
func kernelTCXProgramAttached(t *testing.T, ifindex int, attach ebpf.AttachType, match func(name string) bool) bool {
	t.Helper()
	result, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: attach})
	if err != nil {
		return false
	}
	for _, attached := range result.Programs {
		prog, err := ebpf.NewProgramFromID(attached.ID)
		if err != nil {
			continue
		}
		info, err := prog.Info()
		_ = prog.Close()
		if err == nil && match(info.Name) {
			return true
		}
	}
	return false
}

func TestDesiredKernelAttachmentPlansFollowTheAttachAPI(t *testing.T) {
	prog := &ebpf.Program{}
	sets := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{3: {1}},
		ReplyIngress:   map[int][]int64{4: {1}},
	}
	for _, tc := range []struct {
		name string
		mode kernelTCAttachmentProgramMode
		tcx  bool
		want bool
	}{
		{name: "dispatch with tcx", mode: kernelTCAttachmentProgramModeDispatchV4, tcx: true, want: true},
		{name: "legacy with tcx", mode: kernelTCAttachmentProgramModeLegacy, tcx: true, want: true},
		{name: "plugin pipeline", mode: kernelTCAttachmentProgramModePipelineV4, tcx: true, want: true},
		{name: "cls_bpf", mode: kernelTCAttachmentProgramModeDispatchV4, tcx: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plans := desiredKernelAttachmentPlansForRuleSets(sets, kernelAttachmentPrograms{
				forwardProg: prog,
				replyProg:   prog,
				mode:        tc.mode,
				tcx:         tc.tcx,
			})
			if len(plans) != 2 {
				t.Fatalf("plans = %d, want 2", len(plans))
			}
			for _, plan := range plans {
				if plan.key.tcx != tc.want {
					t.Fatalf("plan %s key.tcx = %t, want %t", plan.name, plan.key.tcx, tc.want)
				}
			}
		})
	}
}

func TestKernelAttachmentKeysKeepTCXAndFilterPositionsApart(t *testing.T) {
	filter := kernelAttachment{filter: &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
		LinkIndex: 3,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Priority:  kernelReplyFilterPrio,
		Handle:    netlink.MakeHandle(0, kernelReplyFilterHandle),
	}}}
	filterKey, ok := filter.key()
	if !ok || filterKey.tcx {
		t.Fatalf("filter key = %+v, %t", filterKey, ok)
	}
	tcxKey := filterKey
	tcxKey.tcx = true
	tcx := kernelAttachment{tcx: &kernelTCXAttachment{key: tcxKey}}

	// A cls_bpf predecessor handed over to a tcx runtime: the filter is stale
	// although the tcx link uses the same numbers.
	if got := kernelAttachmentDeleteCount([]kernelAttachment{filter}, []kernelAttachment{tcx}); got != 1 {
		t.Fatalf("delete count = %d, want 1", got)
	}
	if got := mergeKernelAttachments([]kernelAttachment{filter}, []kernelAttachment{tcx}); len(got) != 2 {
		t.Fatalf("merged = %d attachments, want 2", len(got))
	}
	if _, ok := (kernelAttachment{}).key(); ok {
		t.Fatal("empty attachment has a key")
	}
}

func TestKernelHotRestartTCMetadataMarksTCXLinks(t *testing.T) {
	key := kernelAttachmentKey{
		linkIndex: 7,
		parent:    netlink.HANDLE_MIN_EGRESS,
		priority:  kernelForwardFilterPrio,
		handle:    netlink.MakeHandle(0, kernelForwardFilterHandle),
		tcx:       true,
	}
	meta := kernelHotRestartTCMetadata([]kernelAttachment{{tcx: &kernelTCXAttachment{key: key}}}, "hash")
	if len(meta.TCAttachments) != 1 {
		t.Fatalf("metadata attachments = %+v", meta.TCAttachments)
	}
	want := kernelHotRestartTCAttachment{LinkIndex: 7, Parent: netlink.HANDLE_MIN_EGRESS, Priority: kernelForwardFilterPrio, Handle: netlink.MakeHandle(0, kernelForwardFilterHandle), TCX: true}
	if meta.TCAttachments[0] != want {
		t.Fatalf("metadata attachment = %+v, want %+v", meta.TCAttachments[0], want)
	}
	if got := tcAttachmentAPI([]kernelAttachment{{tcx: &kernelTCXAttachment{key: key}}}); got != "tcx" {
		t.Fatalf("attachment API = %q, want tcx", got)
	}
}

func TestKernelTCXAttachmentLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if !kernelTCXSupported() {
		t.Skip("kernel has no tcx")
	}
	if os.Getenv("VEER_TCX_LIFECYCLE_CHILD") != "1" {
		cmd := exec.Command("unshare", "--net", "--", os.Args[0], "-test.run=^TestKernelTCXAttachmentLifecycle$", "-test.v", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "VEER_TCX_LIFECYCLE_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated tcx lifecycle: %v: %s", err, output)
		}
		return
	}

	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tcxlife0"}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(dummy) })
	ifindex := dummy.Attrs().Index
	stateRoot := filepath.Join("/sys/fs/bpf", fmt.Sprintf("veer-tcx-test-%d", os.Getpid()))
	t.Setenv(veerBPFStateDirEnv, stateRoot)
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
	t.Cleanup(func() { _ = os.RemoveAll(stateRoot) })

	program := func(name string) *ebpf.Program {
		t.Helper()
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	plan := func(priority uint16, handle uint16, name string, prog *ebpf.Program) kernelAttachmentPlan {
		return kernelAttachmentPlan{
			key: kernelAttachmentKey{
				linkIndex: ifindex,
				parent:    netlink.HANDLE_MIN_INGRESS,
				priority:  priority,
				handle:    netlink.MakeHandle(0, handle),
				tcx:       true,
			},
			ifindex:     ifindex,
			priority:    priority,
			handleMinor: handle,
			name:        name,
			prog:        prog,
		}
	}
	chain := func() []ebpf.ProgramID {
		t.Helper()
		result, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]ebpf.ProgramID, 0, len(result.Programs))
		for _, p := range result.Programs {
			ids = append(ids, p.ID)
		}
		return ids
	}
	id := func(p *ebpf.Program) ebpf.ProgramID { return ebpf.ProgramID(kernelProgramID(p)) }
	sameChain := func(want ...*ebpf.Program) {
		t.Helper()
		got := chain()
		if len(got) != len(want) {
			t.Fatalf("tcx chain = %v, want %d programs", got, len(want))
		}
		for i, p := range want {
			if got[i] != id(p) {
				t.Fatalf("tcx chain = %v, position %d want program %d", got, i, id(p))
			}
		}
	}

	forwardOld, replyOld := program("fwd_old"), program("reply_old")
	forwardNew, replyNew := program("fwd_new"), program("reply_new")
	rt := &linuxKernelRuleRuntime{}

	// Forward first: the reply program still has to run before it.
	if err := rt.attachProgramLocked(&rt.attachments, plan(kernelForwardFilterPrio, kernelForwardFilterHandle, "forward", forwardOld), nil); err != nil {
		t.Fatal(err)
	}
	if err := rt.attachProgramLocked(&rt.attachments, plan(kernelReplyFilterPrio, kernelReplyFilterHandle, "reply", replyOld), nil); err != nil {
		t.Fatal(err)
	}
	sameChain(replyOld, forwardOld)
	forwardLink := rt.attachments[0].tcx.slot.linkID

	// A reconcile updates the existing links in place, and its rollback puts
	// the previous programs back.
	var installed []kernelAttachment
	if err := rt.attachProgramLocked(&installed, plan(kernelReplyFilterPrio, kernelReplyFilterHandle, "reply", replyNew), rt.attachments); err != nil {
		t.Fatal(err)
	}
	if err := rt.attachProgramLocked(&installed, plan(kernelForwardFilterPrio, kernelForwardFilterHandle, "forward", forwardNew), rt.attachments); err != nil {
		t.Fatal(err)
	}
	sameChain(replyNew, forwardNew)
	if installed[1].tcx.slot.linkID != forwardLink {
		t.Fatalf("forward link = %d after update, want %d", installed[1].tcx.slot.linkID, forwardLink)
	}
	observed := kernelAttachmentObservations([]kernelAttachmentKey{installed[0].tcx.key, installed[1].tcx.key}, installed)
	for _, att := range installed {
		got := observed[att.tcx.key]
		if !got.present || got.programID != int(kernelProgramID(att.tcx.prog)) {
			t.Fatalf("observation for %s = %+v", att.tcx.name, got)
		}
	}
	extra := program("fwd_v6")
	if err := rt.attachProgramLocked(&installed, plan(kernelForwardFilterPrioV6, kernelForwardFilterHandleV6, "forward6", extra), rt.attachments); err != nil {
		t.Fatal(err)
	}
	sameChain(replyNew, forwardNew, extra)
	rt.discardAttachmentsLocked(installed)
	sameChain(replyOld, forwardOld)

	// Handoff: the pins keep the links attached without this process's
	// references, and the successor updates them in place.
	if err := pinKernelTCXAttachments(rt.attachments); err != nil {
		t.Fatal(err)
	}
	meta := kernelHotRestartTCMetadata(rt.attachments, "")
	closeKernelTCXAttachments(rt.attachments)
	sameChain(replyOld, forwardOld)
	predecessor := kernelAttachmentsFromHotRestartMetadata(meta.TCAttachments)
	if len(predecessor) != 2 {
		t.Fatalf("adopted %d predecessor links, want 2", len(predecessor))
	}
	successor := &linuxKernelRuleRuntime{}
	var next []kernelAttachment
	if err := successor.attachProgramLocked(&next, plan(kernelReplyFilterPrio, kernelReplyFilterHandle, "reply", replyNew), predecessor); err != nil {
		t.Fatal(err)
	}
	successor.deleteStaleAttachmentsLocked(predecessor, next)
	clearKernelHotRestartState(kernelEngineTC)
	sameChain(replyNew)
	successor.attachments = next

	// A second handoff from the adopted link pins it again.
	if err := pinKernelTCXAttachments(successor.attachments); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kernelHotRestartTCXLinkPinPath(next[0].tcx.key)); err != nil {
		t.Fatalf("adopted link was not pinned again: %v", err)
	}
	// An abandoned handoff detaches the pinned links.
	closeKernelTCXAttachments(successor.attachments)
	detachKernelTCXPredecessorLinks(kernelHotRestartTCMetadata(next, "").TCAttachments)
	clearKernelHotRestartState(kernelEngineTC)
	sameChain()
}
