//go:build linux

package nlretry

import (
	"errors"
	"net"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// netlink.AddrList(link, family) dumps every address in the namespace and
// drops the other links' in user space: the library never puts the link's
// index into the request. A host with many guest taps then pays for all of
// their addresses on every single-link read, and a loop over the links pays
// for them once per link. With NETLINK_GET_STRICT_CHK set (Linux 4.20+) the
// kernel honours ifa_index and dumps that one device, so AddrList asks for
// it that way and keeps the library's dump for kernels that refuse.

// strictAddrDumpRefused is set once the kernel turned the strict per-link
// dump down, so later reads go straight to the library's full dump.
var strictAddrDumpRefused atomic.Bool

// errStrictAddrDump marks a refusal of the strict request itself, as opposed
// to an error the full dump would hit as well.
type errStrictAddrDump struct{ err error }

func (e errStrictAddrDump) Error() string { return "strict address dump: " + e.err.Error() }
func (e errStrictAddrDump) Unwrap() error { return e.err }

// AddrList is netlink.AddrList, dumped again when interrupted. For a link
// with a known index it dumps only that link's addresses.
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	if link != nil && link.Attrs() != nil && link.Attrs().Index > 0 && !strictAddrDumpRefused.Load() {
		index := link.Attrs().Index
		addrs, err := Do(func() ([]netlink.Addr, error) { return linkAddrList(index, family) })
		var refused errStrictAddrDump
		if !errors.As(err, &refused) {
			return addrs, err
		}
		strictAddrDumpRefused.Store(true)
	}
	return Do(func() ([]netlink.Addr, error) { return netlink.AddrList(link, family) })
}

// AddrsByLinkIndex dumps the namespace's addresses once and groups them by
// link index, for callers that read the addresses of every link.
func AddrsByLinkIndex(family int) (map[int][]netlink.Addr, error) {
	addrs, err := Do(func() ([]netlink.Addr, error) { return netlink.AddrList(nil, family) })
	if err != nil {
		return nil, err
	}
	out := make(map[int][]netlink.Addr)
	for _, addr := range addrs {
		out[addr.LinkIndex] = append(out[addr.LinkIndex], addr)
	}
	return out, nil
}

// linkAddrList dumps the addresses of one link on a fresh socket in the
// calling thread's network namespace, as the library's own dump does.
func linkAddrList(index, family int) ([]netlink.Addr, error) {
	s, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := unix.SetsockoptInt(s.GetFd(), unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1); err != nil {
		return nil, errStrictAddrDump{err}
	}
	if err := s.SetSendTimeout(&nl.SocketTimeoutTv); err != nil {
		return nil, err
	}
	if err := s.SetReceiveTimeout(&nl.SocketTimeoutTv); err != nil {
		return nil, err
	}

	req := nl.NewNetlinkRequest(unix.RTM_GETADDR, unix.NLM_F_DUMP)
	msg := nl.NewIfAddrmsg(family)
	msg.Index = uint32(index)
	req.AddData(msg)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: s}}

	msgs, executeErr := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWADDR)
	if executeErr != nil && !errors.Is(executeErr, netlink.ErrDumpInterrupted) {
		// The full dump of a link that is gone finds nothing; the strict
		// one fails on the index instead.
		if errors.Is(executeErr, unix.ENODEV) {
			return nil, nil
		}
		if errors.Is(executeErr, unix.EINVAL) || errors.Is(executeErr, unix.EOPNOTSUPP) {
			return nil, errStrictAddrDump{executeErr}
		}
		return nil, executeErr
	}
	var res []netlink.Addr
	for _, m := range msgs {
		addr, msgFamily, err := parseAddrMessage(m)
		if err != nil {
			return res, err
		}
		// A kernel that ignores ifa_index for some family dumps them all:
		// filter as the library does.
		if addr.LinkIndex != index {
			continue
		}
		if family != netlink.FAMILY_ALL && msgFamily != family {
			continue
		}
		res = append(res, addr)
	}
	return res, executeErr
}

// parseAddrMessage is the netlink library's parseAddr (v1.3.1), which it
// does not export, so both dumps return the same addresses.
func parseAddrMessage(m []byte) (addr netlink.Addr, family int, err error) {
	msg := nl.DeserializeIfAddrmsg(m)
	family = -1
	addr.LinkIndex = -1

	attrs, err := nl.ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return addr, family, err
	}
	family = int(msg.Family)
	addr.LinkIndex = int(msg.Index)

	var local, dst *net.IPNet
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.IFA_ADDRESS:
			dst = &net.IPNet{
				IP:   attr.Value,
				Mask: net.CIDRMask(int(msg.Prefixlen), 8*len(attr.Value)),
			}
		case unix.IFA_LOCAL:
			// A local address next to a peer has no prefix of its own.
			n := 8 * len(attr.Value)
			local = &net.IPNet{IP: attr.Value, Mask: net.CIDRMask(n, n)}
		case unix.IFA_BROADCAST:
			addr.Broadcast = attr.Value
		case unix.IFA_LABEL:
			addr.Label = string(attr.Value[:len(attr.Value)-1])
		case unix.IFA_FLAGS:
			addr.Flags = int(nl.NativeEndian().Uint32(attr.Value[0:4]))
		case unix.IFA_CACHEINFO:
			ci := nl.DeserializeIfaCacheInfo(attr.Value)
			addr.PreferedLft = int(ci.Prefered)
			addr.ValidLft = int(ci.Valid)
		}
	}

	// IPv4 sends IFA_LOCAL and IFA_ADDRESS, the latter being the peer when
	// they differ; IPv6 sends IFA_ADDRESS alone unless it has a peer.
	if local != nil {
		if family == netlink.FAMILY_V4 && dst != nil && local.IP.Equal(dst.IP) {
			addr.IPNet = dst
		} else {
			addr.IPNet = local
			addr.Peer = dst
		}
	} else {
		addr.IPNet = dst
	}
	addr.Scope = int(msg.Scope)
	return addr, family, nil
}
