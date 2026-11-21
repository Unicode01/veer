//go:build linux

package app

import (
	"encoding/binary"
	"errors"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Policy rules and device offloads have no subscription in the netlink
// library. These monitors listen on the routing rule groups and on ethtool's
// netlink monitor group and publish net.rule and net.offload, so a plugin
// that keeps rules or offloads in place can repair them when they change
// instead of polling for drift. Changes of either are rare; with no plugin
// subscribed a message is read and dropped.

const (
	pluginNetEventReceiveBuffer = 1 << 20
	pluginNetEventRetryMin      = time.Second
	pluginNetEventRetryMax      = 30 * time.Second
	// fibRuleHeaderLen is sizeof(struct fib_rule_hdr).
	fibRuleHeaderLen = 12
	nlaTypeMask      = 0x3fff
)

func (pm *ProcessManager) startPluginNetEventMonitors(stop <-chan struct{}) {
	go pm.runPluginNetEventMonitor(stop, "rule", openRuleEventSocket, pm.handleRuleEventMessages)
	go pm.runPluginNetEventMonitor(stop, "offload", openOffloadEventSocket, pm.handleOffloadEventMessages)
}

// runPluginNetEventMonitor reads one event socket until stop, opening it
// again with backoff when it fails. A socket that cannot be opened at all
// (no ethtool netlink in this kernel) ends the monitor.
func (pm *ProcessManager) runPluginNetEventMonitor(stop <-chan struct{}, kind string, open func() (*os.File, uint16, error), handle func(family uint16, msgs []syscall.NetlinkMessage)) {
	backoff := pluginNetEventRetryMin
	opened := false
	for {
		file, family, err := open()
		if err != nil {
			if !opened {
				log.Printf("plugin %s events unavailable: %v", kind, err)
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, pluginNetEventRetryMax)
			continue
		}
		opened, backoff = true, pluginNetEventRetryMin
		closed := make(chan struct{})
		go func() {
			select {
			case <-stop:
			case <-closed:
			}
			_ = file.Close()
		}()
		err = readPluginNetEvents(file, family, handle)
		close(closed)
		select {
		case <-stop:
			return
		default:
		}
		log.Printf("plugin %s events: %v; subscribing again", kind, err)
	}
}

func readPluginNetEvents(file *os.File, family uint16, handle func(uint16, []syscall.NetlinkMessage)) error {
	buf := make([]byte, 64<<10)
	for {
		n, err := file.Read(buf)
		if err != nil {
			if errors.Is(err, unix.ENOBUFS) {
				// Messages were dropped; the socket itself is fine.
				continue
			}
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		handle(family, msgs)
	}
}

// openNetlinkGroups opens a non-blocking netlink socket that has joined
// groups. The runtime poller reads it, so closing the file ends a read.
func openNetlinkGroups(protocol int, groups ...uint32) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, protocol)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	for _, group := range groups {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, int(group)); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, pluginNetEventReceiveBuffer)
	return os.NewFile(uintptr(fd), "netlink-events"), nil
}

func openRuleEventSocket() (*os.File, uint16, error) {
	file, err := openNetlinkGroups(unix.NETLINK_ROUTE, unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE)
	return file, 0, err
}

func openOffloadEventSocket() (*os.File, uint16, error) {
	family, err := netlink.GenlFamilyGet(unix.ETHTOOL_GENL_NAME)
	if err != nil {
		return nil, 0, err
	}
	group := uint32(0)
	for _, candidate := range family.Groups {
		if candidate.Name == unix.ETHTOOL_MCGRP_MONITOR_NAME {
			group = candidate.ID
		}
	}
	if group == 0 {
		return nil, 0, errors.New("ethtool netlink has no monitor group")
	}
	file, err := openNetlinkGroups(unix.NETLINK_GENERIC, group)
	return file, family.ID, err
}

func (pm *ProcessManager) handleRuleEventMessages(_ uint16, msgs []syscall.NetlinkMessage) {
	for _, msg := range msgs {
		if msg.Header.Type != unix.RTM_NEWRULE && msg.Header.Type != unix.RTM_DELRULE {
			continue
		}
		if payload, ok := pluginRuleEventPayload(msg); ok {
			pm.publishPluginSystemEventFor(pluginEventTopicNetRule, func() any { return payload })
		}
	}
}

func (pm *ProcessManager) handleOffloadEventMessages(family uint16, msgs []syscall.NetlinkMessage) {
	for _, msg := range msgs {
		if msg.Header.Type != family {
			continue
		}
		if payload, ok := pluginOffloadEventPayload(msg); ok {
			pm.publishPluginSystemEventFor(pluginEventTopicNetOffload, func() any { return payload })
		}
	}
}

// pluginRuleEventPayload describes an RTM_NEWRULE or RTM_DELRULE message.
func pluginRuleEventPayload(msg syscall.NetlinkMessage) (map[string]any, bool) {
	if len(msg.Data) < fibRuleHeaderLen {
		return nil, false
	}
	operation := "update"
	if msg.Header.Type == unix.RTM_DELRULE {
		operation = "delete"
	}
	payload := map[string]any{
		"operation": operation,
		"family":    int(msg.Data[0]),
		"table":     int(msg.Data[4]),
		"action":    int(msg.Data[7]),
	}
	for _, attr := range parseNetlinkAttrs(msg.Data[fibRuleHeaderLen:]) {
		switch attr.kind {
		case unix.FRA_PRIORITY:
			if len(attr.value) >= 4 {
				payload["priority"] = int(binary.NativeEndian.Uint32(attr.value))
			}
		case unix.FRA_TABLE:
			if len(attr.value) >= 4 {
				payload["table"] = int(binary.NativeEndian.Uint32(attr.value))
			}
		case unix.FRA_IIFNAME:
			payload["iif"] = netlinkAttrString(attr.value)
		case unix.FRA_OIFNAME:
			payload["oif"] = netlinkAttrString(attr.value)
		}
	}
	return payload, true
}

// pluginOffloadEventPayload describes an ETHTOOL_MSG_FEATURES_NTF message:
// the device whose offload features changed.
func pluginOffloadEventPayload(msg syscall.NetlinkMessage) (map[string]any, bool) {
	if len(msg.Data) < unix.GENL_HDRLEN || msg.Data[0] != unix.ETHTOOL_MSG_FEATURES_NTF {
		return nil, false
	}
	for _, attr := range parseNetlinkAttrs(msg.Data[unix.GENL_HDRLEN:]) {
		if attr.kind != unix.ETHTOOL_A_FEATURES_HEADER {
			continue
		}
		payload := map[string]any{"operation": "update"}
		for _, field := range parseNetlinkAttrs(attr.value) {
			switch field.kind {
			case unix.ETHTOOL_A_HEADER_DEV_INDEX:
				if len(field.value) >= 4 {
					payload["ifindex"] = int(binary.NativeEndian.Uint32(field.value))
				}
			case unix.ETHTOOL_A_HEADER_DEV_NAME:
				payload["interface"] = netlinkAttrString(field.value)
			}
		}
		if name, _ := payload["interface"].(string); name == "" {
			return nil, false
		}
		return payload, true
	}
	return nil, false
}

type netlinkAttr struct {
	kind  uint16
	value []byte
}

func parseNetlinkAttrs(data []byte) []netlinkAttr {
	var attrs []netlinkAttr
	for len(data) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(data[0:2]))
		if length < unix.SizeofRtAttr || length > len(data) {
			break
		}
		attrs = append(attrs, netlinkAttr{
			kind:  binary.NativeEndian.Uint16(data[2:4]) & nlaTypeMask,
			value: data[unix.SizeofRtAttr:length],
		})
		aligned := (length + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
	return attrs
}

func netlinkAttrString(value []byte) string {
	return strings.TrimRight(string(value), "\x00")
}
