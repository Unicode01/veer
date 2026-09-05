package app

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestUserspaceBindingCanceledIsNotHealthy(t *testing.T) {
	g, err := newUserspaceBindingGroup([]Rule{{InIP: "127.0.0.1", InPort: 0, Protocol: "tcp"}}, &ruleStats{})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	waitUserspaceBindingStatus(t, g, 1, false)
	g.cancel()
	if bound, err := g.Status(); bound != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled binding status=(%d, %v)", bound, err)
	}
}

func waitUserspaceBindingStatus(t *testing.T, g *userspaceBindingGroup, bound int, degraded bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := g.Status()
		if got == bound && (err != nil) == degraded {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("binding status=(%d, %v), want (%d, degraded=%v)", got, err, bound, degraded)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUserspaceRepairPreservesHealthyProtocolAndTCPConnection(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.Copy(conn, conn)
	}()
	backendPort := backend.Addr().(*net.TCPAddr).Port
	occupied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.LocalAddr().(*net.UDPAddr).Port
	rule := Rule{ID: 1, InIP: "127.0.0.1", InPort: port, OutIP: "127.0.0.1", OutPort: backendPort, Protocol: "tcp+udp"}
	binding, degraded, err := startRuleBindingWithDegradedState(0, rule, &ruleStats{})
	if err != nil || degraded == nil {
		t.Fatalf("start=%v, degraded=%v", err, degraded)
	}
	defer binding.Stop()
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	echo := func() {
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "ping" {
			t.Fatalf("echo=%q", buf)
		}
	}
	echo()
	tcp := binding.group.endpoints[0].closer
	occupied.Close()
	keep := map[int64]struct{}{1: {}}
	start, stop := retryUnavailableRuleBindings(keep, nil, nil, []Rule{rule}, map[int64]*ruleBinding{1: binding})
	if len(start)+len(stop) != 0 || binding.group.endpoints[0].closer != tcp {
		t.Fatal("healthy TCP listener replaced")
	}
	waitUserspaceBindingStatus(t, binding.group, 2, false)
	echo()
	binding.group.mu.Lock()
	udp := binding.group.endpoints[1].closer
	udp.Close()
	binding.group.mu.Unlock()
	waitUserspaceBindingStatus(t, binding.group, 1, true)
	binding.group.Repair()
	waitUserspaceBindingStatus(t, binding.group, 2, false)
	if binding.group.endpoints[0].closer != tcp {
		t.Fatal("runtime UDP failure replaced healthy TCP")
	}
	echo()
}

func TestUserspaceRangeRepairsOnlyDeadEndpoint(t *testing.T) {
	occupied, startPort, endPort := reserveAdjacentTCPPortsForTest(t)
	occupied.Close()
	b, _, err := startRangeBindingWithDegradedState(0, PortRange{ID: 1, InIP: "127.0.0.1", StartPort: startPort, EndPort: endPort, OutIP: "127.0.0.1", OutStartPort: 9, Protocol: "tcp"}, &ruleStats{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	b.group.mu.Lock()
	first, second := b.group.endpoints[0].closer, b.group.endpoints[1].closer
	first.Close()
	b.group.mu.Unlock()
	waitUserspaceBindingStatus(t, b.group, 1, true)
	b.group.Repair()
	waitUserspaceBindingStatus(t, b.group, 2, false)
	if b.group.endpoints[0].closer == first || b.group.endpoints[1].closer != second {
		t.Fatal("incorrect range endpoint replaced")
	}
	b.group.mu.Lock()
	for i := range b.group.endpoints {
		b.group.endpoints[i].closer.Close()
	}
	b.group.mu.Unlock()
	waitUserspaceBindingStatus(t, b.group, 0, true)
	b.group.Repair()
	waitUserspaceBindingStatus(t, b.group, 2, false)
}

func TestUserspaceListenerBudgetIsAtomicAndRejectsHugeFallback(t *testing.T) {
	budget := &udpNATEntryBudget{limit: 16}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if budget.tryAcquireN(3) {
				budget.releaseN(3)
			}
		}()
	}
	wg.Wait()
	if budget.activeEntries() != 0 || budget.tryAcquireN(17) || budget.tryAcquireN(-1) {
		t.Fatal("invalid budget accounting")
	}
	before := userspaceListenerBudget.activeEntries()
	b, _, err := startRangeBindingWithDegradedState(0, PortRange{InIP: "127.0.0.1", StartPort: 1, EndPort: 65535, OutIP: "127.0.0.1", OutStartPort: 1, Protocol: "tcp+udp"}, &ruleStats{})
	if b != nil {
		b.Stop()
	}
	if err == nil || userspaceListenerBudget.activeEntries() != before {
		t.Fatal("huge fallback allocated listeners")
	}
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type failingAcceptListener struct{ calls int }

func (l *failingAcceptListener) Accept() (net.Conn, error) {
	l.calls++
	return nil, temporaryAcceptError{}
}
func (*failingAcceptListener) Close() error   { return nil }
func (*failingAcceptListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestUserspaceAcceptTemporaryFailureBacksOffAndCancels(t *testing.T) {
	ln := &failingAcceptListener{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := acceptUserspaceTCP(ctx, ln)
	if err == nil || ln.calls > 6 {
		t.Fatalf("accept spun: calls=%d error=%v", ln.calls, err)
	}
}
