//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// On Linux 6.6 and later the core TC programs can run from the device's tcx
// program list instead of cls_bpf filters under the clsact qdisc, which
// saves the classifier walk on every packet. tcx programs run before any
// cls_bpf filter and use the same verdicts, except that tcx has no
// TC_ACT_STOLEN: it continues with the next program instead. Plugin stages
// run as tail calls of the core programs, so the plugin contract excludes
// TC_ACT_STOLEN; a plugin that took a packet over returns a redirect without
// a target device (veer_tc_consumed), which both attach APIs treat alike.

var kernelTCXSupported = sync.OnceValue(func() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, -1),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	defer prog.Close()
	// No device has this index. A kernel with tcx accepts the attach type and
	// then fails to find the device.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: math.MaxInt32,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err == nil {
		_ = l.Close()
		return false
	}
	return errors.Is(err, unix.ENODEV)
})

// kernelTCXSlot holds the link of one core program position. The attachment
// lists of consecutive reconciles share the slot while they keep the
// position, so a rollback through an older list reaches the current link.
type kernelTCXSlot struct {
	link   link.Link
	linkID link.ID
}

type kernelTCXAttachment struct {
	key  kernelAttachmentKey
	name string
	// prog is the program this attachment put into the slot. It is nil for a
	// slot adopted from a hot-restart predecessor.
	prog *ebpf.Program
	slot *kernelTCXSlot
}

func kernelTCXAttachType(parent uint32) ebpf.AttachType {
	if parent == netlink.HANDLE_MIN_EGRESS {
		return ebpf.AttachTCXEgress
	}
	return ebpf.AttachTCXIngress
}

func newKernelTCXSlot(l link.Link) (*kernelTCXSlot, error) {
	info, err := l.Info()
	if err != nil {
		return nil, err
	}
	return &kernelTCXSlot{link: l, linkID: info.ID}, nil
}

func findKernelTCXSlot(key kernelAttachmentKey, attachments ...[]kernelAttachment) *kernelTCXSlot {
	for _, list := range attachments {
		for _, att := range list {
			if att.tcx != nil && att.tcx.key == key && att.tcx.slot != nil && att.tcx.slot.link != nil {
				return att.tcx.slot
			}
		}
	}
	return nil
}

// kernelTCXAnchor keeps the core programs of one hook in priority order, as
// the cls_bpf priorities do: reply before forward, IPv4 before IPv6. Only
// links the kernel still lists for the hook are used as anchors.
func kernelTCXAnchor(key kernelAttachmentKey, attachments ...[]kernelAttachment) (link.Anchor, error) {
	result, err := link.QueryPrograms(link.QueryOptions{Target: key.linkIndex, Attach: kernelTCXAttachType(key.parent)})
	if err != nil {
		return nil, err
	}
	attached := make(map[link.ID]struct{}, len(result.Programs))
	for _, prog := range result.Programs {
		if id, ok := prog.LinkID(); ok {
			attached[id] = struct{}{}
		}
	}
	var before, after *kernelTCXAttachment
	for _, list := range attachments {
		for _, att := range list {
			other := att.tcx
			if other == nil || other.slot == nil || other.slot.link == nil || other.key == key {
				continue
			}
			if other.key.linkIndex != key.linkIndex || other.key.parent != key.parent {
				continue
			}
			if _, ok := attached[other.slot.linkID]; !ok {
				continue
			}
			if other.key.priority > key.priority {
				if before == nil || other.key.priority < before.key.priority {
					before = other
				}
			} else if after == nil || other.key.priority > after.key.priority {
				after = other
			}
		}
	}
	switch {
	case before != nil:
		return link.BeforeLinkByID(before.slot.linkID), nil
	case after != nil:
		return link.AfterLinkByID(after.slot.linkID), nil
	default:
		return nil, nil
	}
}

// attachKernelTCX points the position of plan at plan.prog. A link that
// already holds the position is updated in place, which swaps the program
// atomically like FilterReplace does for a cls_bpf filter.
func attachKernelTCX(plan kernelAttachmentPlan, live ...[]kernelAttachment) (kernelAttachment, error) {
	slot := findKernelTCXSlot(plan.key, live...)
	if slot != nil {
		err := slot.link.Update(plan.prog)
		if err == nil {
			return newKernelTCXAttachment(plan, slot), nil
		}
		// The device of the link went away; only a new link can serve the
		// position.
		log.Printf("kernel dataplane attach: replace tcx link %d of %s on ifindex %d: %v", slot.linkID, plan.name, plan.ifindex, err)
		detachKernelTCXSlot(slot)
	}
	anchor, err := kernelTCXAnchor(plan.key, live...)
	if err != nil {
		return kernelAttachment{}, fmt.Errorf("query tcx programs: %w", err)
	}
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: plan.ifindex,
		Program:   plan.prog,
		Attach:    kernelTCXAttachType(plan.key.parent),
		Anchor:    anchor,
	})
	if err != nil {
		return kernelAttachment{}, err
	}
	created, err := newKernelTCXSlot(l)
	if err != nil {
		_ = l.Close()
		return kernelAttachment{}, fmt.Errorf("read tcx link info: %w", err)
	}
	if slot == nil {
		slot = created
	} else {
		*slot = *created
	}
	return newKernelTCXAttachment(plan, slot), nil
}

func newKernelTCXAttachment(plan kernelAttachmentPlan, slot *kernelTCXSlot) kernelAttachment {
	return kernelAttachment{tcx: &kernelTCXAttachment{
		key:  plan.key,
		name: plan.name,
		prog: plan.prog,
		slot: slot,
	}}
}

// detachKernelTCXSlot takes the program off the hook even while a pin still
// refers to the link.
func detachKernelTCXSlot(slot *kernelTCXSlot) {
	if slot == nil || slot.link == nil {
		return
	}
	_ = slot.link.Detach()
	_ = slot.link.Unpin()
	_ = slot.link.Close()
	slot.link = nil
	slot.linkID = 0
}

// observeKernelTCXAttachments records which tcx positions among keys the
// kernel still runs, and with which program.
func observeKernelTCXAttachments(observed map[kernelAttachmentKey]kernelAttachmentObservation, keys []kernelAttachmentKey, attachments []kernelAttachment) {
	slots := make(map[kernelAttachmentKey]*kernelTCXSlot, len(attachments))
	for _, att := range attachments {
		if att.tcx != nil && att.tcx.slot != nil && att.tcx.slot.link != nil {
			slots[att.tcx.key] = att.tcx.slot
		}
	}
	type hook struct {
		ifindex int
		parent  uint32
	}
	attachedByHook := make(map[hook]map[link.ID]ebpf.ProgramID)
	for _, key := range keys {
		slot := slots[key]
		if !key.tcx || slot == nil {
			continue
		}
		h := hook{ifindex: key.linkIndex, parent: key.parent}
		attached, ok := attachedByHook[h]
		if !ok {
			result, err := link.QueryPrograms(link.QueryOptions{Target: key.linkIndex, Attach: kernelTCXAttachType(key.parent)})
			if err == nil {
				attached = make(map[link.ID]ebpf.ProgramID, len(result.Programs))
				for _, prog := range result.Programs {
					if id, ok := prog.LinkID(); ok {
						attached[id] = prog.ID
					}
				}
			}
			attachedByHook[h] = attached
		}
		progID, ok := attached[slot.linkID]
		if !ok {
			continue
		}
		observed[key] = kernelAttachmentObservation{
			present:      true,
			isBPF:        true,
			programID:    int(progID),
			directAction: true,
		}
	}
}

func kernelHotRestartTCXLinkPinPath(key kernelAttachmentKey) string {
	name := fmt.Sprintf("%d-%x-%d-%x", key.linkIndex, key.parent, key.priority, key.handle)
	return filepath.Join(kernelHotRestartEngineDir(kernelEngineTC), "tcx-links", name)
}

// pinKernelTCXAttachments keeps the tcx links attached after this process
// exits. The successor opens the pins and updates the links in place. A
// successor that does not know tcx removes the pins with the rest of the
// handoff state, which detaches the links.
func pinKernelTCXAttachments(attachments []kernelAttachment) error {
	created := false
	for _, att := range attachments {
		if att.tcx == nil || att.tcx.slot == nil || att.tcx.slot.link == nil {
			continue
		}
		path := kernelHotRestartTCXLinkPinPath(att.tcx.key)
		if !created {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("create tcx link pin dir: %w", err)
			}
			created = true
		}
		// A link adopted from a pin still remembers that path, and Pin
		// returns early for the path a link remembers.
		_ = att.tcx.slot.link.Unpin()
		_ = os.Remove(path)
		if err := att.tcx.slot.link.Pin(path); err != nil {
			return fmt.Errorf("pin tcx link of %s on ifindex %d: %w", att.tcx.name, att.tcx.key.linkIndex, err)
		}
	}
	return nil
}

func loadKernelTCXPredecessorAttachment(item kernelHotRestartTCAttachment) (kernelAttachment, bool) {
	key := kernelAttachmentKey{
		linkIndex: item.LinkIndex,
		parent:    item.Parent,
		priority:  item.Priority,
		handle:    item.Handle,
		tcx:       true,
	}
	path := kernelHotRestartTCXLinkPinPath(key)
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("kernel dataplane hot restart: open tcx link pin %s: %v", path, err)
		}
		return kernelAttachment{}, false
	}
	slot, err := newKernelTCXSlot(l)
	if err != nil {
		log.Printf("kernel dataplane hot restart: read tcx link pin %s: %v", path, err)
		_ = l.Close()
		return kernelAttachment{}, false
	}
	return kernelAttachment{tcx: &kernelTCXAttachment{key: key, slot: slot}}, true
}

// detachKernelTCXPredecessorLinks drops the links a predecessor pinned for a
// handoff that will not happen.
func detachKernelTCXPredecessorLinks(items []kernelHotRestartTCAttachment) {
	for _, item := range items {
		if !item.TCX {
			continue
		}
		if att, ok := loadKernelTCXPredecessorAttachment(item); ok {
			detachKernelTCXSlot(att.tcx.slot)
		}
	}
}

// closeKernelTCXAttachments releases this process's references without
// detaching; pins, if any, keep the links attached.
func closeKernelTCXAttachments(attachments []kernelAttachment) {
	for _, att := range attachments {
		if att.tcx == nil || att.tcx.slot == nil || att.tcx.slot.link == nil {
			continue
		}
		_ = att.tcx.slot.link.Close()
		att.tcx.slot.link = nil
		att.tcx.slot.linkID = 0
	}
}
