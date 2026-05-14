//go:build linux

package kernelcap

import (
	"errors"
	"math"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"forward/internal/ipcmd"
)

func DetectAdaptiveMapTotalMemory() uint64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}

	total := uint64(info.Totalram)
	unit := uint64(info.Unit)
	if unit == 0 {
		unit = 1
	}
	if total > math.MaxUint64/unit {
		return math.MaxUint64
	}
	return total * unit
}

func detectKernelCapabilities() KernelCapabilities {
	caps := KernelCapabilities{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		KernelRelease: detectKernelRelease(),
	}

	caps.BPFMapArray = detectMapType("BPF array map", ebpf.Array)
	caps.BPFMapHash = detectMapType("BPF hash map", ebpf.Hash)
	caps.BPFMapLRUHash = detectMapType("BPF LRU hash map", ebpf.LRUHash)
	caps.BPFMapPerCPUHash = detectMapType("BPF per-CPU hash map", ebpf.PerCPUHash)
	caps.BPFMapPerCPUArray = detectMapType("BPF per-CPU array map", ebpf.PerCPUArray)
	caps.BPFMapProgArray = detectMapType("BPF program array map", ebpf.ProgramArray)
	caps.BPFMapDevMapHash = detectMapType("BPF devmap hash map", ebpf.DevMapHash)
	caps.BPFSchedCLS = detectProgramType("TC sched_cls eBPF program", ebpf.SchedCLS)
	caps.BPFXDP = detectProgramType("XDP eBPF program", ebpf.XDP)
	caps.Netlink = detectNetlinkCapabilities()
	caps.IPRoute = detectIPRouteCapabilities()
	caps.TCAttach = detectTCAttachCapability(caps.BPFSchedCLS, caps.Netlink.LinkList)
	caps.XDPGenericAttach = detectXDPGenericAttachCapability(caps.BPFXDP, caps.Netlink.LinkList)
	caps.TC = combineCapability(
		"TC dataplane",
		caps.BPFMapArray,
		caps.BPFMapHash,
		caps.BPFMapLRUHash,
		caps.BPFMapPerCPUHash,
		caps.BPFMapPerCPUArray,
		caps.BPFMapProgArray,
		caps.BPFSchedCLS,
		caps.TCAttach,
		caps.Netlink.RouteSocket,
		caps.Netlink.LinkList,
		caps.Netlink.RouteList,
	)
	caps.XDPGeneric = combineCapability(
		"XDP generic dataplane",
		caps.BPFMapArray,
		caps.BPFMapHash,
		caps.BPFMapPerCPUHash,
		caps.BPFMapPerCPUArray,
		caps.BPFMapProgArray,
		caps.BPFMapDevMapHash,
		caps.BPFXDP,
		caps.XDPGenericAttach,
		caps.Netlink.RouteSocket,
		caps.Netlink.LinkList,
		caps.Netlink.RouteList,
	)
	caps.Warnings = kernelCapabilityWarnings(caps)
	return caps
}

func detectXDPGenericAttachCapability(programCheck CapabilityCheck, linkListCheck CapabilityCheck) CapabilityCheck {
	if !programCheck.Available || !linkListCheck.Available {
		return combineCapability("XDP generic attach probe", programCheck, linkListCheck)
	}

	link, err := netlink.LinkByName("lo")
	if err != nil {
		return unavailableCapability("XDP generic attach", err)
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return CapabilityCheck{
			Available: false,
			Reason:    "XDP generic attach probe failed: loopback interface is invalid",
		}
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "forward_xdp_probe",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, int32(2)), // XDP_PASS
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		return unavailableCapability("XDP generic attach program", err)
	}
	defer prog.Close()

	flags := nl.XDP_FLAGS_UPDATE_IF_NOEXIST | nl.XDP_FLAGS_SKB_MODE
	if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), flags); err != nil {
		if errors.Is(err, unix.EBUSY) {
			return CapabilityCheck{Available: true}
		}
		return unavailableCapability("XDP generic attach", err)
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE); err != nil {
		return unavailableCapability("XDP generic detach", err)
	}
	return CapabilityCheck{Available: true}
}

func detectTCAttachCapability(programCheck CapabilityCheck, linkListCheck CapabilityCheck) CapabilityCheck {
	if !programCheck.Available || !linkListCheck.Available {
		return combineCapability("TC clsact attach probe", programCheck, linkListCheck)
	}

	link, err := netlink.LinkByName("lo")
	if err != nil {
		return unavailableCapability("TC clsact attach", err)
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return CapabilityCheck{
			Available: false,
			Reason:    "TC clsact attach probe failed: loopback interface is invalid",
		}
	}
	hadClsact, qdiscErr := linkHasClsactQdisc(link)
	if qdiscErr != nil {
		return unavailableCapability("TC clsact qdisc inventory", qdiscErr)
	}
	cleanupQdisc := false

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "forward_tc_probe",
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		return unavailableCapability("TC clsact attach program", err)
	}
	defer prog.Close()

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: attrs.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return unavailableCapability("TC clsact qdisc attach", err)
	}
	if !hadClsact {
		cleanupQdisc = true
		defer func() {
			if cleanupQdisc {
				_ = netlink.QdiscDel(qdisc)
			}
		}()
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: attrs.Index,
			Handle:    netlink.MakeHandle(0, 0x7ffe),
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  0x7ffe,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         "forward_tc_probe",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return unavailableCapability("TC BPF filter attach", err)
	}
	if err := netlink.FilterDel(filter); err != nil {
		return unavailableCapability("TC BPF filter cleanup", err)
	}
	return CapabilityCheck{Available: true}
}

func linkHasClsactQdisc(link netlink.Link) (bool, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return false, err
	}
	for _, qdisc := range qdiscs {
		if qdisc == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(qdisc.Type()), "clsact") {
			return true, nil
		}
	}
	return false, nil
}

func detectMapType(label string, typ ebpf.MapType) CapabilityCheck {
	if err := features.HaveMapType(typ); err != nil {
		return unavailableCapability(label, err)
	}
	return CapabilityCheck{Available: true}
}

func detectProgramType(label string, typ ebpf.ProgramType) CapabilityCheck {
	if err := features.HaveProgramType(typ); err != nil {
		return unavailableCapability(label, err)
	}
	return CapabilityCheck{Available: true}
}

func unavailableCapability(label string, err error) CapabilityCheck {
	return CapabilityCheck{
		Available: false,
		Reason:    normalizeCapabilityError(label, err),
	}
}

func normalizeCapabilityError(label string, err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	lower := strings.ToLower(text)
	switch {
	case errors.Is(err, ebpf.ErrNotSupported):
		return label + " is not supported by this kernel"
	case strings.Contains(lower, "operation not permitted"), strings.Contains(lower, "permission denied"), strings.Contains(lower, "prohibited for !root"):
		return label + " probe needs root/CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON privileges"
	case strings.Contains(lower, "function not implemented"), strings.Contains(lower, "not implemented"):
		return label + " syscall support is missing from this kernel"
	case strings.Contains(lower, "invalid argument"):
		return label + " probe was rejected by the kernel"
	case text == "":
		return label + " probe failed"
	default:
		return label + " probe failed: " + text
	}
}

func detectNetlinkCapabilities() NetlinkCapabilities {
	out := NetlinkCapabilities{}
	out.RouteSocket = probeNetlink("NETLINK_ROUTE socket", func() error {
		handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		handle.Close()
		return nil
	})
	out.LinkList = probeNetlink("netlink link list", func() error {
		_, err := netlink.LinkList()
		return err
	})
	out.RouteList = probeNetlink("netlink route list", func() error {
		_, err := netlink.RouteListFiltered(unix.AF_UNSPEC, &netlink.Route{}, 0)
		return err
	})
	out.LinkSubscribe = probeNetlinkSubscribe("netlink link subscription", func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{})
	})
	out.AddressSubscribe = probeNetlinkSubscribe("netlink address subscription", func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error {
		return netlink.AddrSubscribeWithOptions(ch, done, netlink.AddrSubscribeOptions{})
	})
	out.NeighborSubscribe = probeNetlinkSubscribe("netlink neighbor subscription", func(ch chan<- netlink.NeighUpdate, done <-chan struct{}) error {
		return netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{})
	})
	out.RouteSubscribe = probeNetlinkSubscribe("netlink route subscription", func(ch chan<- netlink.RouteUpdate, done <-chan struct{}) error {
		return netlink.RouteSubscribeWithOptions(ch, done, netlink.RouteSubscribeOptions{})
	})
	return out
}

func detectIPRouteCapabilities() IPRouteCapabilities {
	probe := ipcmd.Probe()
	return IPRouteCapabilities{
		Command:   CapabilityCheck{Available: probe.Command.Available, Reason: probe.Command.Reason},
		RuleShow:  CapabilityCheck{Available: probe.RuleShow.Available, Reason: probe.RuleShow.Reason},
		RouteShow: CapabilityCheck{Available: probe.RouteShow.Available, Reason: probe.RouteShow.Reason},
		Path:      probe.Path,
	}
}

func probeNetlink(label string, fn func() error) CapabilityCheck {
	if err := fn(); err != nil {
		return CapabilityCheck{
			Available: false,
			Reason:    normalizeNetlinkError(label, err),
		}
	}
	return CapabilityCheck{Available: true}
}

func probeNetlinkSubscribe[T any](label string, subscribe func(chan<- T, <-chan struct{}) error) CapabilityCheck {
	ch := make(chan T, 1)
	done := make(chan struct{})
	err := subscribe(ch, done)
	close(done)
	if err != nil {
		return CapabilityCheck{
			Available: false,
			Reason:    normalizeNetlinkError(label, err),
		}
	}
	return CapabilityCheck{Available: true}
}

func normalizeNetlinkError(label string, err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "operation not permitted"), strings.Contains(lower, "permission denied"):
		return label + " needs CAP_NET_ADMIN or sufficient netlink privileges"
	case strings.Contains(lower, "protocol not supported"), strings.Contains(lower, "address family not supported"):
		return label + " is not supported by this kernel"
	case text == "":
		return label + " probe failed"
	default:
		return label + " probe failed: " + text
	}
}

func detectKernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return charsToString(uts.Release[:])
}

func charsToString(chars []byte) string {
	var b strings.Builder
	for _, ch := range chars {
		if ch == 0 {
			break
		}
		b.WriteByte(ch)
	}
	return b.String()
}
