package netservice

import (
	"sync/atomic"
	"time"
)

// The DHCP and RA servers check after every receive and poll timeout
// whether their sockets still match the interfaces; for DHCPv4 that lists
// every link. While the daemon's netlink monitor reports link and address
// changes, a check that saw no change since its last lookup is skipped, with
// a lookup at least every interfaceRecheckEvery as a safety net. Without the
// monitor every check looks the interfaces up, as before.
var (
	interfaceEventsAvailable atomic.Bool
	interfaceGeneration      atomic.Uint64
)

const interfaceRecheckEvery = time.Minute

// SetInterfaceEventsAvailable tells the servers whether NoteInterfaceChange
// is being called for every link and address change.
func SetInterfaceEventsAvailable(available bool) {
	interfaceGeneration.Add(1)
	interfaceEventsAvailable.Store(available)
}

// NoteInterfaceChange reports a link or address change.
func NoteInterfaceChange() {
	interfaceGeneration.Add(1)
}

// interfaceCheckGate remembers the last interface lookup of one socket set.
type interfaceCheckGate struct {
	generation uint64
	checkedAt  time.Time
	valid      bool
}

// run calls check unless nothing changed since its last call returned false,
// and returns what check returned (false when skipped).
func (g *interfaceCheckGate) run(now time.Time, check func() bool) bool {
	generation := interfaceGeneration.Load()
	if interfaceEventsAvailable.Load() && g.valid && generation == g.generation && now.Sub(g.checkedAt) < interfaceRecheckEvery {
		return false
	}
	if check() {
		g.valid = false
		return true
	}
	*g = interfaceCheckGate{generation: generation, checkedAt: now, valid: true}
	return false
}
