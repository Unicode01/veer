//go:build linux

package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The plugin API reads and sets the eight legacy offload groups (rx, tx, sg,
// tso, ufo, gso, gro, lro). Each group has its own legacy ethtool ioctl, the
// same ones `ethtool -k` reads the group states with, so one socket and a few
// ioctls replace an ethtool process per call: on a WAN repair tick those
// processes were about 40% of its time.

// ethFlagLRO is ETH_FLAG_LRO in linux/ethtool.h; LRO lives in the flags word.
const ethFlagLRO = 1 << 15

var pluginOffloadIoctls = []struct {
	name     string
	get, set uint32
}{
	{"rx", unix.ETHTOOL_GRXCSUM, unix.ETHTOOL_SRXCSUM},
	{"tx", unix.ETHTOOL_GTXCSUM, unix.ETHTOOL_STXCSUM},
	{"sg", unix.ETHTOOL_GSG, unix.ETHTOOL_SSG},
	{"tso", unix.ETHTOOL_GTSO, unix.ETHTOOL_STSO},
	{"ufo", unix.ETHTOOL_GUFO, unix.ETHTOOL_SUFO},
	{"gso", unix.ETHTOOL_GGSO, unix.ETHTOOL_SGSO},
	{"gro", unix.ETHTOOL_GGRO, unix.ETHTOOL_SGRO},
}

// ethtoolValue is struct ethtool_value.
type ethtoolValue struct {
	cmd  uint32
	data uint32
}

// ethtoolIfreq is struct ifreq with ifr_data set. The pointer keeps its own
// type so the value it points at stays visible to the garbage collector; the
// padding covers the rest of the union the kernel copies in.
type ethtoolIfreq struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [24]byte
}

type pluginOffloadDevice struct {
	fd   int
	name string
	ifr  [unix.IFNAMSIZ]byte
}

// openPluginOffloadDevice opens the ioctl socket in the calling thread's
// network namespace, where the interface is looked up.
func openPluginOffloadDevice(name string) (*pluginOffloadDevice, error) {
	if name == "" || len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open ethtool socket: %w", err)
	}
	dev := &pluginOffloadDevice{fd: fd, name: name}
	copy(dev.ifr[:], name)
	return dev, nil
}

func (dev *pluginOffloadDevice) Close() { _ = unix.Close(dev.fd) }

func (dev *pluginOffloadDevice) ethtool(cmd, data uint32) (uint32, error) {
	value := ethtoolValue{cmd: cmd, data: data}
	req := ethtoolIfreq{name: dev.ifr, data: unsafe.Pointer(&value)}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(dev.fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return 0, errno
	}
	return value.data, nil
}

// read returns the group states as `ethtool -k` reports them. A group the
// driver cannot report reads as off, as ethtool prints it; when nothing can
// be read the device has no offload information at all.
func (dev *pluginOffloadDevice) read() (map[string]bool, error) {
	out := make(map[string]bool, len(pluginOffloadIoctls)+1)
	var firstErr error
	readable := 0
	for _, group := range pluginOffloadIoctls {
		value, err := dev.ethtool(group.get, 0)
		if err != nil {
			if group.get == unix.ETHTOOL_GUFO && errors.Is(err, unix.EOPNOTSUPP) {
				// Linux 4.14 dropped UFO; ethtool skips it the same way.
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			out[group.name] = false
			continue
		}
		out[group.name] = value != 0
		readable++
	}
	flags, err := dev.ethtool(unix.ETHTOOL_GFLAGS, 0)
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
		out["lro"] = false
	} else {
		out["lro"] = flags&ethFlagLRO != 0
		readable++
	}
	if readable == 0 {
		if errors.Is(firstErr, unix.ENODEV) {
			return nil, fmt.Errorf("link not found: %s", dev.name)
		}
		return nil, fmt.Errorf("no offload information for %s: %v", dev.name, firstErr)
	}
	return out, nil
}

// set asks for each requested group state, then compares the result the way
// `ethtool -K` does: it fails only when a requested state was not reached and
// nothing on the device changed; a partly applied request succeeds. One case
// differs on purpose: a group the kernel no longer has (UFO, since 4.14)
// counts as off, so asking for it off succeeds where ethtool reports that it
// could not change the device.
func (dev *pluginOffloadDevice) set(want map[string]bool) error {
	before, err := dev.read()
	if err != nil {
		return err
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	var failures []string
	for _, name := range names {
		if err := dev.setGroup(name, want[name]); err != nil {
			failures = append(failures, name+": "+err.Error())
		}
	}
	after, err := dev.read()
	if err != nil {
		return err
	}
	var missed []string
	for _, name := range names {
		if after[name] != want[name] {
			missed = append(missed, name)
		}
	}
	if len(missed) == 0 {
		return nil
	}
	for name, state := range after {
		if before[name] != state {
			return nil
		}
	}
	detail := "cannot change " + strings.Join(missed, ", ")
	if len(failures) > 0 {
		detail += " (" + strings.Join(failures, "; ") + ")"
	}
	return fmt.Errorf("could not change any device features on %s: %s", dev.name, detail)
}

func (dev *pluginOffloadDevice) setGroup(name string, enabled bool) error {
	state := uint32(0)
	if enabled {
		state = 1
	}
	if name == "lro" {
		flags, err := dev.ethtool(unix.ETHTOOL_GFLAGS, 0)
		if err != nil {
			return err
		}
		if enabled {
			flags |= ethFlagLRO
		} else {
			flags &^= ethFlagLRO
		}
		_, err = dev.ethtool(unix.ETHTOOL_SFLAGS, flags)
		return err
	}
	for _, group := range pluginOffloadIoctls {
		if group.name == name {
			_, err := dev.ethtool(group.set, state)
			return err
		}
	}
	return fmt.Errorf("unsupported offload feature %q", name)
}
