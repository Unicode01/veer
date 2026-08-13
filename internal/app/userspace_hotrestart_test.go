package app

import (
	"bufio"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestShouldStartMissingUserspaceWorker(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name  string
		ready bool
		wi    *WorkerInfo
		want  bool
	}{
		{name: "nil", ready: true, wi: nil},
		{name: "not-ready", wi: &WorkerInfo{lastStart: now.Add(-time.Hour)}},
		{name: "reconnect-grace", ready: true, wi: &WorkerInfo{lastStart: now}},
		{name: "missing", ready: true, wi: &WorkerInfo{lastStart: now.Add(-userspaceWorkerReconnectGrace - time.Millisecond)}, want: true},
		{name: "starting", ready: true, wi: &WorkerInfo{starting: true, lastStart: now.Add(-time.Hour)}},
		{name: "process", ready: true, wi: &WorkerInfo{process: &osProcessForTest, lastStart: now.Add(-time.Hour)}},
		{name: "connection", ready: true, wi: &WorkerInfo{conn: testNoopConn{}, lastStart: now.Add(-time.Hour)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldStartMissingUserspaceWorker(tc.wi, now, tc.ready); got != tc.want {
				t.Fatalf("shouldStartMissingUserspaceWorker() = %t, want %t", got, tc.want)
			}
		})
	}
}

var osProcessForTest = os.Process{Pid: 1}

type testNoopConn struct{ net.Conn }

type writeObservedConn struct {
	net.Conn
	mu             sync.Mutex
	writes         int
	secondWriteHit chan struct{}
}

func (conn *writeObservedConn) Write(payload []byte) (int, error) {
	conn.mu.Lock()
	conn.writes++
	if conn.writes == 2 {
		close(conn.secondWriteHit)
	}
	conn.mu.Unlock()
	return conn.Conn.Write(payload)
}

func TestWorkerRegistrationFailureTemporarilyAffectsReadiness(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	pm := &ProcessManager{
		ready: true,
		ruleWorkers: map[int]*WorkerInfo{
			1: {rules: []Rule{{ID: 1}}, conn: server},
		},
	}
	if !pm.isReady() {
		t.Fatal("isReady() = false before registration failure")
	}

	pm.noteWorkerRegistrationFailure(IPCMessage{Type: "register", WorkerIndex: 1})
	if pm.isReady() {
		t.Fatal("isReady() = true immediately after registration failure")
	}
	pm.mu.Lock()
	pm.lastWorkerRegistrationFailureAt = time.Now().Add(-workerRegistrationFailureUnhealthyFor - time.Millisecond)
	pm.mu.Unlock()
	if !pm.isReady() {
		t.Fatal("isReady() = false after registration failure health window")
	}
}

func TestReplacedRuleConnectionCannotClearCurrentConnection(t *testing.T) {
	wi := &WorkerInfo{workerIndex: 1, kind: workerKindRule}
	pm := &ProcessManager{
		ruleWorkers: map[int]*WorkerInfo{1: wi},
	}

	oldPipe, oldClient := net.Pipe()
	oldServer := &writeObservedConn{Conn: oldPipe, secondWriteHit: make(chan struct{})}
	defer oldClient.Close()
	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		defer oldServer.Close()
		pm.handleRuleWorkerConn(oldServer, bufio.NewScanner(oldServer), 1, "old")
	}()
	assertWorkerConfigReceived(t, oldClient)
	blockedWriteDone := make(chan struct{})
	go func() {
		defer close(blockedWriteDone)
		pm.sendRuleConfig(wi)
	}()
	select {
	case <-oldServer.secondWriteHit:
	case <-time.After(time.Second):
		t.Fatal("old rule connection did not begin its blocked write")
	}

	newServer, newClient := net.Pipe()
	defer newClient.Close()
	newDone := make(chan struct{})
	go func() {
		defer close(newDone)
		defer newServer.Close()
		pm.handleRuleWorkerConn(newServer, bufio.NewScanner(newServer), 1, "new")
	}()
	assertWorkerConfigReceived(t, newClient)
	select {
	case <-blockedWriteDone:
	case <-time.After(time.Second):
		t.Fatal("closing the replaced connection did not unblock its writer")
	}

	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("replaced rule connection handler did not exit")
	}
	pm.mu.Lock()
	current := wi.conn
	pm.mu.Unlock()
	if current != newServer {
		t.Fatalf("current connection = %p, want replacement %p", current, newServer)
	}

	_ = newClient.Close()
	select {
	case <-newDone:
	case <-time.After(time.Second):
		t.Fatal("current rule connection handler did not exit")
	}
}

func TestReplacedRuleConnectionIgnoresBufferedStatus(t *testing.T) {
	wi := &WorkerInfo{workerIndex: 1, kind: workerKindRule}
	pm := &ProcessManager{ruleWorkers: map[int]*WorkerInfo{1: wi}}
	oldServer, oldClient := net.Pipe()
	defer oldClient.Close()
	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		defer oldServer.Close()
		pm.handleRuleWorkerConn(oldServer, bufio.NewScanner(oldServer), 1, "old")
	}()
	assertWorkerConfigReceived(t, oldClient)

	replacement, replacementPeer := net.Pipe()
	defer replacement.Close()
	defer replacementPeer.Close()
	pm.mu.Lock()
	statusWritten := make(chan error, 1)
	go func() {
		_, err := oldClient.Write([]byte("{\"type\":\"status\",\"status\":\"draining\"}\n"))
		statusWritten <- err
	}()
	select {
	case err := <-statusWritten:
		if err != nil {
			pm.mu.Unlock()
			t.Fatalf("write buffered status: %v", err)
		}
	case <-time.After(time.Second):
		pm.mu.Unlock()
		t.Fatal("old connection did not read buffered status")
	}
	wi.conn = replacement
	pm.mu.Unlock()
	closeReplacedWorkerConnection(oldServer, replacement)

	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("replaced handler did not exit after buffered status")
	}
	pm.mu.Lock()
	current := wi.conn
	drainingCount := len(pm.drainingWorkers)
	pm.mu.Unlock()
	if current != replacement || drainingCount != 0 {
		t.Fatalf("buffered old status changed replacement slot: current=%p draining=%d", current, drainingCount)
	}
}

func TestDetachWorkerInfoUnblocksControlWrite(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	wi := &WorkerInfo{conn: server}
	writeStarted := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		wi.writeMu.Lock()
		close(writeStarted)
		_, _ = server.Write([]byte("blocked"))
		wi.writeMu.Unlock()
		close(writeDone)
	}()
	<-writeStarted

	detachDone := make(chan struct{})
	go func() {
		detachWorkerInfo(wi)
		close(detachDone)
	}()
	for name, done := range map[string]<-chan struct{}{
		"detach": detachDone,
		"writer": writeDone,
	} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s remained blocked after detach", name)
		}
	}
}

func TestKillWorkerInfoBoundsBlockedControlWrite(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	wi := &WorkerInfo{conn: server}
	writeStarted := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		wi.writeMu.Lock()
		close(writeStarted)
		_, _ = server.Write([]byte("blocked"))
		wi.writeMu.Unlock()
		close(writeDone)
	}()
	<-writeStarted

	killDone := make(chan struct{})
	go func() {
		killWorkerInfo(wi)
		close(killDone)
	}()
	for name, done := range map[string]<-chan struct{}{
		"kill":   killDone,
		"writer": writeDone,
	} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s remained blocked while stopping worker", name)
		}
	}
}

func TestKillWorkerInfoUsesConnectionSnapshotWhenBlockedWriteClearsField(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	wi := &WorkerInfo{conn: server}
	writeStarted := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		wi.writeMu.Lock()
		close(writeStarted)
		_, _ = server.Write([]byte("blocked"))
		wi.conn = nil
		wi.writeMu.Unlock()
		close(writeDone)
	}()
	<-writeStarted

	killDone := make(chan struct{})
	go func() {
		killWorkerInfo(wi)
		close(killDone)
	}()
	for name, done := range map[string]<-chan struct{}{
		"kill":   killDone,
		"writer": writeDone,
	} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s remained blocked while stopping worker", name)
		}
	}
}

func assertWorkerConfigReceived(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set worker config deadline: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read worker config: %v", err)
	}
	if line == "" {
		t.Fatal("worker config is empty")
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear worker config deadline: %v", err)
	}
}
