//go:build linux

package kernelcap

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/Unicode01/veer/internal/nlretry"
)

// The netdev generic netlink family, include/uapi/linux/netdev.h.
const (
	netdevFamilyName         = "netdev"
	netdevFamilyVersion      = 1
	netdevCmdDevGet          = 1
	netdevAttrDevIfindex     = 1
	netdevAttrDevXDPFeatures = 3
)

// DetectXDPNativeDevices reads each device's XDP features from the kernel's
// netdev family. It only reads: attaching a program in driver mode to find
// out makes many drivers rebuild their rings, and the link drops for a
// moment. Loopback is left out.
func DetectXDPNativeDevices() XDPNativeReport {
	family, err := netlink.GenlFamilyGet(netdevFamilyName)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return XDPNativeReport{Reason: "the kernel reports no per-device XDP features (needs Linux 6.3 or later)"}
		}
		return XDPNativeReport{Reason: "netdev netlink family lookup: " + err.Error()}
	}
	features, err := nlretry.Do(func() (map[int]uint64, error) {
		return dumpNetdevXDPFeatures(family.ID)
	})
	if err != nil {
		return XDPNativeReport{Reason: "netdev XDP feature dump: " + err.Error()}
	}
	links, err := nlretry.LinkList()
	if err != nil {
		return XDPNativeReport{Reason: "link list: " + err.Error()}
	}
	devices := make([]XDPNativeDevice, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || attrs.Flags&net.FlagLoopback != 0 {
			continue
		}
		flags, ok := features[attrs.Index]
		if !ok {
			// Created between the two dumps.
			continue
		}
		devices = append(devices, xdpNativeDeviceFromFeatures(attrs.Name, attrs.Index, link.Type(), flags))
	}
	sortXDPNativeDevices(devices)
	return XDPNativeReport{Available: true, Devices: devices}
}

// netdevDumpTimeout bounds each wait for the next part of the reply.
const netdevDumpTimeout = 2 * time.Second

// dumpNetdevXDPFeatures reads the reply up to NLMSG_DONE itself: the netdev
// family sends dump replies without NLM_F_MULTI on some kernels (6.12 does),
// and the netlink library's request stops after the first of them, which
// is loopback.
func dumpNetdevXDPFeatures(familyID uint16) (map[int]uint64, error) {
	sock, err := nl.Subscribe(unix.NETLINK_GENERIC)
	if err != nil {
		return nil, err
	}
	defer sock.Close()
	timeout := unix.NsecToTimeval(netdevDumpTimeout.Nanoseconds())
	if err := sock.SetReceiveTimeout(&timeout); err != nil {
		return nil, err
	}
	pid, err := sock.GetPid()
	if err != nil {
		return nil, err
	}
	req := netdevDevGetDumpRequest(familyID)
	if err := sock.Send(req); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	var msgs [][]byte
	interrupted := false
	for {
		replies, _, err := sock.Receive()
		if err != nil {
			return nil, fmt.Errorf("receive: %w", err)
		}
		for _, m := range replies {
			if m.Header.Seq != req.Seq || m.Header.Pid != pid {
				continue
			}
			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				interrupted = true
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE, unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if errno := int32(nl.NativeEndian().Uint32(m.Data[:4])); errno != 0 {
						return nil, fmt.Errorf("kernel: %w", syscall.Errno(-errno))
					}
				}
				if interrupted {
					return nil, netlink.ErrDumpInterrupted
				}
				return parseNetdevXDPFeatures(msgs)
			}
			msgs = append(msgs, m.Data)
		}
	}
}

// netdevDevGetDumpRequest asks for every device. It writes the genl header
// itself: nl.Genlmsg holds two bytes but serializes four, so its reserved
// field carries whatever memory follows it, and the netdev family answers a
// non-zero reserved field with EINVAL.
func netdevDevGetDumpRequest(familyID uint16) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(int(familyID), unix.NLM_F_DUMP)
	req.AddRawData([]byte{netdevCmdDevGet, netdevFamilyVersion, 0, 0})
	return req
}

// parseNetdevXDPFeatures maps ifindex to the netdev_xdp_act bits of each
// NETDEV_CMD_DEV_GET reply.
func parseNetdevXDPFeatures(msgs [][]byte) (map[int]uint64, error) {
	out := make(map[int]uint64, len(msgs))
	for _, msg := range msgs {
		if len(msg) < nl.SizeofGenlmsg {
			return nil, fmt.Errorf("netdev reply of %d bytes is shorter than its header", len(msg))
		}
		attrs, err := nl.ParseRouteAttr(msg[nl.SizeofGenlmsg:])
		if err != nil {
			return nil, fmt.Errorf("netdev reply attributes: %w", err)
		}
		index, features := 0, uint64(0)
		for _, attr := range attrs {
			switch attr.Attr.Type & nl.NLA_TYPE_MASK {
			case netdevAttrDevIfindex:
				if len(attr.Value) >= 4 {
					index = int(nl.NativeEndian().Uint32(attr.Value))
				}
			case netdevAttrDevXDPFeatures:
				if len(attr.Value) >= 8 {
					features = nl.NativeEndian().Uint64(attr.Value)
				}
			}
		}
		if index > 0 {
			out[index] = features
		}
	}
	return out, nil
}
