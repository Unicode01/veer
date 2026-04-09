//go:build linux

package app

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	packetSocketEtherTypeOffset                = 12
	packetSocketIPv6NextHeaderOffset           = 14 + 6
	packetSocketIPv6HopLimitOffset             = 14 + 7
	packetSocketIPv6ICMPTypeOffset             = 14 + 40
	packetSocketIPv6UDPSourcePortOffset        = 14 + 40
	packetSocketIPv6UDPDestPortOffset          = 14 + 42
	packetSocketAcceptBytes             uint32 = 0xffff
)

type ipv6ControlIdentity struct {
	SourceInterface string
	SourceMAC       net.HardwareAddr
	SourceIP        net.IP
}

func resolveIPv6ControlIdentityForInterface(iface *net.Interface) (ipv6ControlIdentity, error) {
	if iface == nil || iface.Index <= 0 {
		return ipv6ControlIdentity{}, fmt.Errorf("interface is unavailable")
	}
	srcIP, err := selectIPv6LinkLocalAddress(*iface)
	if err != nil {
		return ipv6ControlIdentity{}, err
	}
	if len(iface.HardwareAddr) < 6 {
		return ipv6ControlIdentity{}, fmt.Errorf("interface %q has no usable ethernet address", iface.Name)
	}
	return ipv6ControlIdentity{
		SourceInterface: iface.Name,
		SourceMAC:       append(net.HardwareAddr(nil), iface.HardwareAddr...),
		SourceIP:        append(net.IP(nil), srcIP...),
	}, nil
}

func resolveIPv6ControlIdentity(targetInterface string) (ipv6ControlIdentity, error) {
	iface, err := net.InterfaceByName(targetInterface)
	if err != nil {
		return ipv6ControlIdentity{}, err
	}
	if iface == nil || iface.Index <= 0 {
		return ipv6ControlIdentity{}, fmt.Errorf("interface %q is unavailable", targetInterface)
	}

	link, err := netlink.LinkByName(targetInterface)
	if err != nil {
		return ipv6ControlIdentity{}, fmt.Errorf("resolve link-local identity for %q: %w", targetInterface, err)
	}
	if link != nil && link.Attrs() != nil && link.Attrs().MasterIndex > 0 {
		master, err := net.InterfaceByIndex(link.Attrs().MasterIndex)
		if err == nil {
			if identity, identityErr := resolveIPv6ControlIdentityForInterface(master); identityErr == nil {
				return identity, nil
			}
		}
	}
	if identity, err := resolveIPv6ControlIdentityForInterface(iface); err == nil {
		return identity, nil
	}
	return ipv6ControlIdentity{}, fmt.Errorf("interface %q has no usable IPv6 link-local source identity", targetInterface)
}

func enablePacketSocketAllMulticast(fd int, ifIndex int) error {
	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_ALLMULTI,
	})
}

func enablePacketSocketPromiscuous(fd int, ifIndex int) error {
	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	})
}

type packetSocketEqualityCheck struct {
	Offset uint32
	Size   int
	Value  uint32
}

func buildPacketSocketEqualityFilter(checks []packetSocketEqualityCheck) []bpf.Instruction {
	if len(checks) == 0 {
		return []bpf.Instruction{bpf.RetConstant{Val: packetSocketAcceptBytes}}
	}

	insts := make([]bpf.Instruction, 0, len(checks)*2+2)
	rejectIndex := len(checks)*2 + 1
	for _, check := range checks {
		insts = append(insts, bpf.LoadAbsolute{Off: check.Offset, Size: check.Size})
		jumpIndex := len(insts)
		insts = append(insts, bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       check.Value,
			SkipFalse: uint8(rejectIndex - (jumpIndex + 1)),
		})
	}
	insts = append(insts,
		bpf.RetConstant{Val: packetSocketAcceptBytes},
		bpf.RetConstant{Val: 0},
	)
	return insts
}

func attachPacketSocketFilter(fd int, insts []bpf.Instruction) error {
	if len(insts) == 0 {
		return nil
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		return err
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, inst := range raw {
		filters[i] = unix.SockFilter{
			Code: inst.Op,
			Jt:   inst.Jt,
			Jf:   inst.Jf,
			K:    inst.K,
		}
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filters[0])),
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

func openPacketListenerSocket(interfaceName string, timeout time.Duration, filter []bpf.Instruction) (*net.Interface, int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, -1, err
	}
	if iface == nil || iface.Index <= 0 {
		return nil, -1, fmt.Errorf("interface %q is unavailable", interfaceName)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_ALL)))
	if err != nil {
		return nil, -1, err
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, -1, err
	}
	if err := enablePacketSocketAllMulticast(fd, iface.Index); err != nil {
		unix.Close(fd)
		return nil, -1, err
	}
	if err := enablePacketSocketPromiscuous(fd, iface.Index); err != nil {
		unix.Close(fd)
		return nil, -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: htonsUnix(unix.ETH_P_ALL),
	}); err != nil {
		unix.Close(fd)
		return nil, -1, err
	}
	if err := attachPacketSocketFilter(fd, filter); err != nil {
		unix.Close(fd)
		return nil, -1, err
	}
	return iface, fd, nil
}

func openIPv6PacketListenerSocket(interfaceName string, timeout time.Duration, filter []bpf.Instruction) (*net.Interface, int, error) {
	return openPacketListenerSocket(interfaceName, timeout, filter)
}
