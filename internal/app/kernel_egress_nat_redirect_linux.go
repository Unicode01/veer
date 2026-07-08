//go:build linux

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

func resolveKernelEgressNATPreparedL2Redirect(outLink netlink.Link) ([6]byte, [6]byte, error) {
	var srcMAC [6]byte
	var dstMAC [6]byte
	if outLink == nil || outLink.Attrs() == nil {
		return srcMAC, dstMAC, fmt.Errorf("invalid outbound interface")
	}
	attrs := outLink.Attrs()
	if !strings.EqualFold(strings.TrimSpace(outLink.Type()), "veth") {
		return srcMAC, dstMAC, fmt.Errorf("prepared_l2 redirect requires a veth outbound interface, got %q", outLink.Type())
	}
	if !isValidHardwareAddr(attrs.HardwareAddr) {
		return srcMAC, dstMAC, fmt.Errorf("outbound interface %q has no usable MAC", attrs.Name)
	}
	peerIndex, err := readLinuxInterfacePeerIndex(attrs.Name, attrs.Index)
	if err != nil {
		return srcMAC, dstMAC, err
	}
	peer, err := netlink.LinkByIndex(peerIndex)
	if err != nil {
		return srcMAC, dstMAC, fmt.Errorf("resolve veth peer ifindex %d for %q: %w", peerIndex, attrs.Name, err)
	}
	if peer == nil || peer.Attrs() == nil || !isValidHardwareAddr(peer.Attrs().HardwareAddr) {
		return srcMAC, dstMAC, fmt.Errorf("veth peer ifindex %d for %q has no usable MAC", peerIndex, attrs.Name)
	}
	return hardwareAddrToArray(attrs.HardwareAddr), hardwareAddrToArray(peer.Attrs().HardwareAddr), nil
}

func readLinuxInterfacePeerIndex(name string, selfIndex int) (int, error) {
	if strings.TrimSpace(name) == "" {
		return 0, fmt.Errorf("interface name is empty")
	}
	raw, err := os.ReadFile(filepath.Join("/sys/class/net", name, "iflink"))
	if err != nil {
		return 0, fmt.Errorf("read peer ifindex for %q: %w", name, err)
	}
	peerIndex, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("parse peer ifindex for %q: %w", name, err)
	}
	if peerIndex <= 0 || peerIndex == selfIndex {
		return 0, fmt.Errorf("interface %q does not expose a veth peer ifindex", name)
	}
	return peerIndex, nil
}
