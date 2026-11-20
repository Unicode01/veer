//go:build linux

// Package nlretry wraps the netlink dumps Veer reads interfaces, addresses,
// routes, neighbours and rules with.
//
// A dump that ran while the kernel changed the table comes back flagged
// (NLM_F_DUMP_INTR): the netlink library then returns ErrDumpInterrupted
// together with a result that may miss entries or hold stale ones. On a
// router whose guests start and stop, interfaces and neighbours change all
// the time, so a single dump failing that way is routine: the panel answered
// such a request with HTTP 500 and a reconcile failed over it. Each function
// here dumps again a few times before it gives up and returns the error.
package nlretry

import (
	"errors"
	"time"

	"github.com/vishvananda/netlink"
)

// attempts bounds the retries: with the backoff below, the last dump starts
// about 127 ms after the first.
const attempts = 8

// Do runs dump until it is not interrupted, up to attempts times, and
// returns its first uninterrupted result. Any other error ends it at once.
func Do[T any](dump func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		value, err := dump()
		if err == nil {
			return value, nil
		}
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return zero, err
		}
		lastErr = err
		if attempt+1 < attempts {
			time.Sleep(time.Duration(1<<attempt) * time.Millisecond)
		}
	}
	return zero, lastErr
}

// LinkList is netlink.LinkList, dumped again when interrupted.
func LinkList() ([]netlink.Link, error) {
	return Do(netlink.LinkList)
}

// LinkByName is netlink.LinkByName, which dumps all links on kernels that
// cannot look one up by name.
func LinkByName(name string) (netlink.Link, error) {
	return Do(func() (netlink.Link, error) { return netlink.LinkByName(name) })
}

// AddrList is netlink.AddrList, dumped again when interrupted.
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return Do(func() ([]netlink.Addr, error) { return netlink.AddrList(link, family) })
}

// RouteList is netlink.RouteList, dumped again when interrupted.
func RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return Do(func() ([]netlink.Route, error) { return netlink.RouteList(link, family) })
}

// RouteListFiltered is netlink.RouteListFiltered, dumped again when
// interrupted.
func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return Do(func() ([]netlink.Route, error) { return netlink.RouteListFiltered(family, filter, filterMask) })
}

// NeighList is netlink.NeighList, dumped again when interrupted.
func NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return Do(func() ([]netlink.Neigh, error) { return netlink.NeighList(linkIndex, family) })
}

// NeighProxyList is netlink.NeighProxyList, dumped again when interrupted.
func NeighProxyList(linkIndex, family int) ([]netlink.Neigh, error) {
	return Do(func() ([]netlink.Neigh, error) { return netlink.NeighProxyList(linkIndex, family) })
}

// RuleList is netlink.RuleList, dumped again when interrupted.
func RuleList(family int) ([]netlink.Rule, error) {
	return Do(func() ([]netlink.Rule, error) { return netlink.RuleList(family) })
}
