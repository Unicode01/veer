package app

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestUDPNATEntryBudgetBoundsConcurrentAcquisition(t *testing.T) {
	const limit = int64(8)
	budget := udpNATEntryBudget{limit: limit}

	var acquired atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if budget.tryAcquire() {
				acquired.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := acquired.Load(); got != limit {
		t.Fatalf("acquired = %d, want %d", got, limit)
	}
	if got := budget.activeEntries(); got != limit {
		t.Fatalf("active entries = %d, want %d", got, limit)
	}
	if budget.tryAcquire() {
		t.Fatal("tryAcquire succeeded after reaching the limit")
	}

	for range limit {
		budget.release()
	}
	if got := budget.activeEntries(); got != 0 {
		t.Fatalf("active entries after release = %d, want 0", got)
	}
	budget.release()
	if got := budget.activeEntries(); got != 0 {
		t.Fatalf("active entries after extra release = %d, want 0", got)
	}
}

func TestUserspaceUDPBindingStopReleasesNATBudget(t *testing.T) {
	tests := []struct {
		name  string
		start func(t *testing.T, backendPort, forwardPort int, stats *ruleStats) interface{ Stop() }
	}{
		{
			name: "rule",
			start: func(t *testing.T, backendPort, forwardPort int, stats *ruleStats) interface{ Stop() } {
				binding, err := startRuleBinding(0, Rule{
					ID:       1001,
					InIP:     "127.0.0.1",
					InPort:   forwardPort,
					OutIP:    "127.0.0.1",
					OutPort:  backendPort,
					Protocol: "udp",
				}, stats)
				if err != nil {
					t.Fatalf("startRuleBinding(): %v", err)
				}
				return binding
			},
		},
		{
			name: "range",
			start: func(t *testing.T, backendPort, forwardPort int, stats *ruleStats) interface{ Stop() } {
				binding, err := startRangeBinding(0, PortRange{
					ID:           1002,
					InIP:         "127.0.0.1",
					StartPort:    forwardPort,
					EndPort:      forwardPort,
					OutIP:        "127.0.0.1",
					OutStartPort: backendPort,
					Protocol:     "udp",
				}, stats)
				if err != nil {
					t.Fatalf("startRangeBinding(): %v", err)
				}
				return binding
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline := userspaceUDPNATBudget.activeEntries()
			backendPort := startUDPEchoServer(t, "udp4", "127.0.0.1")
			forwardPort := reserveUDPPortOnHost(t, "udp4", "127.0.0.1")
			stats := &ruleStats{}
			binding := tt.start(t, backendPort, forwardPort, stats)
			t.Cleanup(binding.Stop)

			assertUDPEcho(t, "udp4", "127.0.0.1", forwardPort, []byte("budget-release"))
			if got := userspaceUDPNATBudget.activeEntries(); got != baseline+1 {
				t.Fatalf("active entries after UDP flow = %d, want %d", got, baseline+1)
			}

			binding.Stop()
			if got := userspaceUDPNATBudget.activeEntries(); got != baseline {
				t.Fatalf("active entries after binding stop = %d, want %d", got, baseline)
			}
			if got := atomic.LoadInt64(&stats.natTableSize); got != 0 {
				t.Fatalf("NAT table size after binding stop = %d, want 0", got)
			}
		})
	}
}
