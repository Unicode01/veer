//go:build linux

package netservice

import (
	"bytes"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The DHCP and router advertisement servers check, on every poll timeout and
// after every batch of frames, that each socket's interface is still the one
// it was opened on. net.InterfaceByName dumps every link in the namespace to
// find one by name, so on a host with dozens of guest taps those checks were
// the daemon's largest idle cost. Two ioctls answer the same question.

// ifreqIndex is struct ifreq with ifr_ifindex.
type ifreqIndex struct {
	name  [unix.IFNAMSIZ]byte
	index int32
	_     [20]byte
}

// ifreqHWAddr is struct ifreq with ifr_hwaddr, a struct sockaddr.
type ifreqHWAddr struct {
	name   [unix.IFNAMSIZ]byte
	family uint16
	data   [14]byte
	_      [8]byte
}

// interfaceByName returns the index and, for an ethernet interface, the
// hardware address of the named interface. The address is nil when it is
// all zeros, as net.InterfaceByName reports it.
func interfaceByName(name string) (*net.Interface, error) {
	if name == "" || len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", name, err)
	}
	defer unix.Close(fd)

	var index ifreqIndex
	copy(index.name[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFINDEX, uintptr(unsafe.Pointer(&index))); errno != 0 {
		if errno == unix.ENODEV {
			return nil, fmt.Errorf("no such network interface: %s", name)
		}
		return nil, fmt.Errorf("interface %s: %w", name, errno)
	}
	iface := &net.Interface{Index: int(index.index), Name: name}

	var hw ifreqHWAddr
	copy(hw.name[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFHWADDR, uintptr(unsafe.Pointer(&hw))); errno != 0 {
		return nil, fmt.Errorf("interface %s hardware address: %w", name, errno)
	}
	if hw.family == unix.ARPHRD_ETHER {
		mac := hw.data[:6]
		if !bytes.Equal(mac, make([]byte, 6)) {
			iface.HardwareAddr = append(net.HardwareAddr(nil), mac...)
		}
	}
	return iface, nil
}
