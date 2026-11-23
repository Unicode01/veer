//go:build linux

package app

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// fakeKernelNetlinkSubscriptions hands out link channels the test closes, the
// way the netlink library closes one when a receive fails (ENOBUFS after a
// burst). The other three are unavailable.
func fakeKernelNetlinkSubscriptions(t *testing.T, links ...chan netlink.LinkUpdate) *atomic.Int32 {
	t.Helper()
	calls := new(atomic.Int32)
	saved := kernelNetlinkSubscribe
	t.Cleanup(func() { kernelNetlinkSubscribe = saved })
	kernelNetlinkSubscribe = kernelNetlinkSubscriptions{
		link: func(<-chan struct{}) chan netlink.LinkUpdate {
			n := int(calls.Add(1))
			if n > len(links) {
				return nil
			}
			return links[n-1]
		},
		addr:  func(<-chan struct{}) chan netlink.AddrUpdate { return nil },
		neigh: func(<-chan struct{}) chan netlink.NeighUpdate { return nil },
		route: func(<-chan struct{}) chan netlink.RouteUpdate { return nil },
	}
	return calls
}

func TestKernelNetlinkMonitorResubscribesAnEndedSubscription(t *testing.T) {
	first, second := make(chan netlink.LinkUpdate), make(chan netlink.LinkUpdate)
	calls := fakeKernelNetlinkSubscriptions(t, first, second)

	pm := &ProcessManager{}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		pm.runKernelNetlinkMonitor(stop)
		close(done)
	}()

	close(first) // the subscription ends on a receive error
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the monitor did not subscribe again after its link subscription ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Changes made while it was down were never seen: both reconciles are due.
	for {
		pm.mu.Lock()
		redistribute, reload := pm.redistributePending, pm.managedRuntimeReloadPending
		source := pm.managedRuntimeReloadLastRequestSource
		pm.mu.Unlock()
		if redistribute && reload {
			if source != "netlink_resubscribe" {
				t.Fatalf("managed network reload source = %q, want netlink_resubscribe", source)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after subscribing again: redistribute pending %t, managed network reload pending %t", redistribute, reload)
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the monitor did not return after stop")
	}
}

func TestKernelNetlinkMonitorDoesNotResubscribeWhenStopping(t *testing.T) {
	first := make(chan netlink.LinkUpdate)
	calls := fakeKernelNetlinkSubscriptions(t, first)

	pm := &ProcessManager{}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		pm.runKernelNetlinkMonitor(stop)
		close(done)
	}()
	for calls.Load() < 1 {
		time.Sleep(time.Millisecond)
	}

	// Stopping closes the subscription too; that is no reason to reopen it.
	close(stop)
	close(first)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the monitor did not return after stop")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("link subscribed %d times, want 1", got)
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.redistributePending || pm.managedRuntimeReloadPending {
		t.Fatal("stopping the monitor requested a reconcile")
	}
}
