//go:build linux

package app

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Unicode01/veer/internal/nlretry"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A bridge learns which port a guest is on from the frames the guest sends
// through it, and forgets after its ageing time (300 s by default). The kernel
// dataplane takes a guest's IPv4 traffic at the guest's bridge port, before
// the bridge sees it, so a guest whose traffic all goes that way is forgotten
// although it is busy. Whatever is then sent to it through the bridge
// (egress NAT and hairpin replies, forwards to it) floods every port of the
// bridge, until the guest sends something the dataplane leaves alone.
//
// The keepalive has the kernel confirm the stale neighbours of the bridges the
// dataplane is attached to or below (NTF_USE, as `ip neigh change ... use`):
// the kernel probes each with a unicast ARP request or neighbour
// solicitation, and the answer passes the bridge, which learns the guest's
// port again, or for the first time after it was forgotten. Neighbours the
// host itself talks to are confirmed by that traffic and left alone.

const (
	bridgeNeighborKeepaliveMaxEvery = 60 * time.Second
	bridgeNeighborKeepaliveMinEvery = time.Second
	// Without an ageing time to read, assume the kernel default.
	bridgeDefaultAgeingTime = 300 * time.Second
	// At most this many neighbours are touched per bridge and pass.
	bridgeNeighborKeepaliveLimit = 4096
)

// bridgeNeighborKeepalive runs the keepalive for one runtime, at most once
// per interval.
type bridgeNeighborKeepalive struct {
	mu   sync.Mutex
	next time.Time
}

// maybeRun runs the keepalive for the bridges of linkIndexes when it is due.
// linkIndexes is only called then.
func (k *bridgeNeighborKeepalive) maybeRun(now time.Time, linkIndexes func() []int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if now.Before(k.next) {
		return
	}
	k.next = now.Add(refreshBridgeNeighbors(linkIndexes()))
}

// bridgeNeighborKeepaliveEvery is how often the neighbours of a bridge with
// the given ageing time are confirmed: a quarter of it, so that a probe (sent
// some seconds after the touch, as the entry goes through DELAY) and its
// answer land well inside it.
func bridgeNeighborKeepaliveEvery(ageing time.Duration) time.Duration {
	every := ageing / 4
	if every > bridgeNeighborKeepaliveMaxEvery {
		return bridgeNeighborKeepaliveMaxEvery
	}
	if every < bridgeNeighborKeepaliveMinEvery {
		return bridgeNeighborKeepaliveMinEvery
	}
	return every
}

// refreshBridgeNeighbors confirms the stale neighbours of every bridge among
// linkIndexes or their masters and returns when to run again.
func refreshBridgeNeighbors(linkIndexes []int) time.Duration {
	next := bridgeNeighborKeepaliveMaxEvery
	for _, bridge := range bridgesOfLinks(linkIndexes) {
		ageing := bridgeAgeingTime(bridge.Attrs().Name)
		if ageing <= 0 {
			continue
		}
		if every := bridgeNeighborKeepaliveEvery(ageing); every < next {
			next = every
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			touchStaleNeighbors(bridge.Attrs().Index, family)
		}
	}
	return next
}

// bridgesOfLinks returns the bridges among linkIndexes and the bridges they
// are ports of, each once.
func bridgesOfLinks(linkIndexes []int) []netlink.Link {
	seen := make(map[int]struct{})
	var bridges []netlink.Link
	add := func(link netlink.Link) {
		if link == nil || link.Attrs() == nil || !isXDPBridgeLink(link) {
			return
		}
		if _, ok := seen[link.Attrs().Index]; ok {
			return
		}
		seen[link.Attrs().Index] = struct{}{}
		bridges = append(bridges, link)
	}
	for _, index := range linkIndexes {
		if index <= 0 {
			continue
		}
		link, err := netlink.LinkByIndex(index)
		if err != nil || link.Attrs() == nil {
			continue
		}
		if isXDPBridgeLink(link) {
			add(link)
			continue
		}
		if master := link.Attrs().MasterIndex; master > 0 {
			if parent, err := netlink.LinkByIndex(master); err == nil {
				add(parent)
			}
		}
	}
	return bridges
}

// bridgeAgeingTime reads a bridge's FDB ageing time; 0 means entries never
// age.
func bridgeAgeingTime(name string) time.Duration {
	raw, err := os.ReadFile(filepath.Join("/sys/class/net", name, "bridge", "ageing_time"))
	if err != nil {
		return bridgeDefaultAgeingTime
	}
	centiseconds, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || centiseconds < 0 {
		return bridgeDefaultAgeingTime
	}
	return time.Duration(centiseconds) * 10 * time.Millisecond
}

// touchStaleNeighbors asks the kernel to confirm the stale neighbours of one
// interface and family.
func touchStaleNeighbors(linkIndex int, family int) {
	neighbors, err := nlretry.NeighList(linkIndex, family)
	if err != nil {
		return
	}
	touched := 0
	for _, neighbor := range neighbors {
		if touched >= bridgeNeighborKeepaliveLimit {
			return
		}
		if neighbor.State&netlink.NUD_STALE == 0 || neighbor.IP == nil || len(neighbor.HardwareAddr) == 0 {
			continue
		}
		touch := netlink.Neigh{
			LinkIndex:    linkIndex,
			Family:       family,
			State:        neighbor.State,
			Flags:        unix.NTF_USE | (neighbor.Flags & unix.NTF_ROUTER),
			IP:           neighbor.IP,
			HardwareAddr: neighbor.HardwareAddr,
		}
		_ = netlink.NeighSet(&touch)
		touched++
	}
}
