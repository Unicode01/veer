package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDataplaneReconcileRequiresCurrentWorkerGeneration(t *testing.T) {
	wi := &WorkerInfo{conn: testNoopConn{}, running: true, desiredGeneration: 2, appliedGeneration: 1}
	pm := &ProcessManager{
		ready: true, desiredGeneration: 2, preparedGeneration: 2, appliedGeneration: 1,
		ruleWorkers: map[int]*WorkerInfo{0: wi}, rangeWorkers: map[int]*WorkerInfo{}, enabledEgressNATs: map[int64]bool{},
	}

	if pm.isReady() {
		t.Fatal("isReady() = true before current generation ACK")
	}
	pm.mu.Lock()
	noteWorkerGenerationStatusLocked(wi, IPCMessage{Generation: 1, Status: "running"}, true)
	pm.refreshDataplaneAppliedLocked(time.Now())
	pm.mu.Unlock()
	if pm.isReady() {
		t.Fatal("isReady() = true after stale generation ACK")
	}

	pm.mu.Lock()
	noteWorkerGenerationStatusLocked(wi, IPCMessage{Generation: 2, Status: "running"}, true)
	pm.refreshDataplaneAppliedLocked(time.Now())
	pm.mu.Unlock()
	if !pm.isReady() {
		t.Fatal("isReady() = false after current generation ACK")
	}
}

func TestDataplaneReconcileWorkerErrorMakesAppliedGenerationUnready(t *testing.T) {
	wi := &WorkerInfo{
		conn: testNoopConn{}, running: true, desiredGeneration: 3, appliedGeneration: 3,
		errored: true, lastError: "listen failed",
	}
	pm := &ProcessManager{
		ready: true, desiredGeneration: 3, preparedGeneration: 3, appliedGeneration: 3,
		ruleWorkers: map[int]*WorkerInfo{0: wi}, rangeWorkers: map[int]*WorkerInfo{}, enabledEgressNATs: map[int64]bool{},
	}

	if pm.isReady() {
		t.Fatal("isReady() = true for errored current-generation worker")
	}
	status := pm.dataplaneReconcileStatus()
	if status.Status != "error" || !strings.Contains(status.LastError, "listen failed") {
		t.Fatalf("dataplane status = %+v, want worker error", status)
	}
}

func TestWriteIPCCompletesShortWrites(t *testing.T) {
	conn := &shortWriteConn{maxWrite: 3}
	want := IPCMessage{Type: "config", Generation: 42, Rules: []Rule{{ID: 7}}}
	if err := writeIPCWithTimeout(conn, want, 0); err != nil {
		t.Fatalf("writeIPCWithTimeout() error = %v", err)
	}
	if conn.writeCalls < 2 {
		t.Fatalf("write calls = %d, want multiple short writes", conn.writeCalls)
	}
	var got IPCMessage
	if err := json.Unmarshal(bytes.TrimSpace(conn.buf.Bytes()), &got); err != nil {
		t.Fatalf("decode written IPC: %v", err)
	}
	if got.Type != want.Type || got.Generation != want.Generation || len(got.Rules) != 1 || got.Rules[0].ID != 7 {
		t.Fatalf("written IPC = %+v, want %+v", got, want)
	}
}

func TestWriteIPCReportsZeroLengthWrite(t *testing.T) {
	err := writeIPCWithTimeout(&shortWriteConn{zeroWrite: true}, IPCMessage{Type: "config"}, 0)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeIPCWithTimeout() error = %v, want io.ErrShortWrite", err)
	}
}

func TestWorkerConfigACKTimeoutSchedulesRetryOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	wi := &WorkerInfo{
		conn:              testNoopConn{},
		desiredGeneration: 9,
		appliedGeneration: 8,
		configSentAt:      now.Add(-workerConfigACKTimeout),
	}
	if !markWorkerConfigACKTimeout(wi, now) {
		t.Fatal("markWorkerConfigACKTimeout() = false, want timeout")
	}
	if !wi.errored || wi.retryCount != 1 || wi.nextRetry.IsZero() || !strings.Contains(wi.lastError, "generation 9") {
		t.Fatalf("worker after ACK timeout = %+v", wi)
	}
	if markWorkerConfigACKTimeout(wi, now.Add(time.Second)) {
		t.Fatal("markWorkerConfigACKTimeout() repeated without another send")
	}
}

func TestAdvanceWorkerGenerationRejectsOlderGeneration(t *testing.T) {
	wi := &WorkerInfo{
		conn:              testNoopConn{},
		running:           true,
		desiredGeneration: 5,
		appliedGeneration: 5,
	}
	if advanceWorkerGenerationLocked(wi, 4, true) {
		t.Fatal("advanceWorkerGenerationLocked() requested send for stale generation")
	}
	if wi.desiredGeneration != 5 || wi.appliedGeneration != 5 {
		t.Fatalf("worker generations = desired:%d applied:%d, want 5/5", wi.desiredGeneration, wi.appliedGeneration)
	}
}

func TestStaleAssignmentGenerationCannotReplaceNewerWorkerConfig(t *testing.T) {
	current := Rule{ID: 7, InIP: "127.0.0.1", InPort: 10007, OutIP: "127.0.0.1", OutPort: 22, Protocol: "tcp", Enabled: true}
	stale := current
	stale.OutPort = 23
	wi := &WorkerInfo{rules: []Rule{current}, desiredGeneration: 2, appliedGeneration: 2}
	pm := &ProcessManager{
		desiredGeneration: 2,
		ruleWorkers:       map[int]*WorkerInfo{0: wi},
		rangeWorkers:      map[int]*WorkerInfo{},
	}

	pm.applyRuleAssignmentsGeneration([][]Rule{{stale}}, 1)

	if got := pm.ruleWorkers[0].rules[0].OutPort; got != current.OutPort {
		t.Fatalf("stale generation replaced worker config: out_port=%d, want %d", got, current.OutPort)
	}
	if pm.ruleWorkers[0].desiredGeneration != 2 {
		t.Fatalf("desired generation = %d, want 2", pm.ruleWorkers[0].desiredGeneration)
	}
}

func TestRegisterIPCConnectionPublishesOnlyAfterRegistrationWrite(t *testing.T) {
	conn := &shortWriteConn{maxWrite: 2}
	var connMu sync.Mutex
	var published net.Conn

	if err := registerIPCConnection(conn, IPCMessage{Type: "register", WorkerIndex: 3}, &connMu, &published); err != nil {
		t.Fatalf("registerIPCConnection() error = %v", err)
	}
	if published != conn {
		t.Fatalf("published connection = %T, want registration connection", published)
	}
	var got IPCMessage
	if err := json.Unmarshal(bytes.TrimSpace(conn.buf.Bytes()), &got); err != nil {
		t.Fatalf("decode registration IPC: %v", err)
	}
	if got.Type != "register" || got.WorkerIndex != 3 {
		t.Fatalf("registration IPC = %+v", got)
	}
}

func TestRegisterIPCConnectionDoesNotPublishFailedWrite(t *testing.T) {
	conn := &shortWriteConn{zeroWrite: true}
	var connMu sync.Mutex
	var published net.Conn

	err := registerIPCConnection(conn, IPCMessage{Type: "register"}, &connMu, &published)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("registerIPCConnection() error = %v, want io.ErrShortWrite", err)
	}
	if published != nil {
		t.Fatalf("failed registration published connection %T", published)
	}
}

type shortWriteConn struct {
	buf        bytes.Buffer
	maxWrite   int
	writeCalls int
	zeroWrite  bool
}

func (c *shortWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *shortWriteConn) Close() error                     { return nil }
func (c *shortWriteConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *shortWriteConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }

func (c *shortWriteConn) Write(p []byte) (int, error) {
	c.writeCalls++
	if c.zeroWrite {
		return 0, nil
	}
	limit := len(p)
	if c.maxWrite > 0 && limit > c.maxWrite {
		limit = c.maxWrite
	}
	return c.buf.Write(p[:limit])
}

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }
