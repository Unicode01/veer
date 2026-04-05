package app

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newPipeScanner(conn net.Conn) *bufio.Scanner {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	return scanner
}

func readPipeMessage(t *testing.T, scanner *bufio.Scanner) IPCMessage {
	t.Helper()
	if !scanner.Scan() {
		t.Fatal("scanner.Scan() = false, want IPC message")
	}
	var msg IPCMessage
	if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
		t.Fatalf("unmarshal IPC message: %v", err)
	}
	return msg
}

func writePipeMessage(t *testing.T, conn net.Conn, msg IPCMessage) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal IPC message: %v", err)
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write IPC message: %v", err)
	}
}

func TestHandleRangeWorkerConnErrorSchedulesRetry(t *testing.T) {
	pm := &ProcessManager{
		binaryHash: "manager-hash",
		rangeWorkers: map[int]*WorkerInfo{
			0: {
				workerIndex:  0,
				kind:         workerKindRange,
				ranges:       []PortRange{{ID: 7, InIP: "198.51.100.10", StartPort: 10000, EndPort: 10000, OutIP: "203.0.113.10", OutStartPort: 20000, Protocol: "tcp"}},
				failedRanges: make(map[int64]bool),
				rangeStats:   make(map[int64]RangeStatsReport),
			},
		},
	}

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		pm.handleRangeWorkerConn(server, newPipeScanner(server), 0, "worker-hash")
		close(done)
	}()

	msg := readPipeMessage(t, newPipeScanner(client))
	if msg.Type != "range_config" || len(msg.PortRanges) != 1 || msg.PortRanges[0].ID != 7 {
		t.Fatalf("initial IPC message = %#v, want range_config for range 7", msg)
	}

	writePipeMessage(t, client, IPCMessage{
		Type:           "status",
		Status:         "error",
		Error:          "all 1 port range bindings failed",
		FailedRangeIDs: []int64{7},
	})
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleRangeWorkerConn() did not exit after client close")
	}

	wi := pm.rangeWorkers[0]
	if wi == nil {
		t.Fatal("range worker missing after handler exit")
	}
	if !wi.errored {
		t.Fatal("range worker errored = false, want true")
	}
	if wi.retryCount != 1 {
		t.Fatalf("range worker retryCount = %d, want 1", wi.retryCount)
	}
	if wi.nextRetry.IsZero() {
		t.Fatal("range worker nextRetry is zero, want scheduled retry")
	}
	if !wi.failedRanges[7] {
		t.Fatal("range worker failedRanges missing range 7")
	}
	if wi.binaryHash != "worker-hash" {
		t.Fatalf("range worker binaryHash = %q, want worker-hash", wi.binaryHash)
	}
	if wi.lastMessageAt.IsZero() {
		t.Fatal("range worker lastMessageAt is zero, want updated timestamp")
	}
}

func TestHandleSharedProxyConnDegradedStatusSchedulesRetry(t *testing.T) {
	db := openTestDB(t)
	siteID, err := dbAddSite(db, &Site{
		Domain:      "example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.10",
		BackendHTTP: 8080,
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("dbAddSite() error = %v", err)
	}

	pm := &ProcessManager{
		db:         db,
		binaryHash: "manager-hash",
		sharedProxy: &WorkerInfo{
			kind:        workerKindShared,
			failedSites: make(map[int64]bool),
		},
	}

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		pm.handleSharedProxyConn(server, newPipeScanner(server), "proxy-hash")
		close(done)
	}()

	msg := readPipeMessage(t, newPipeScanner(client))
	if msg.Type != "sites_config" || len(msg.Sites) != 1 || msg.Sites[0].ID != siteID {
		t.Fatalf("initial IPC message = %#v, want sites_config for site %d", msg, siteID)
	}

	writePipeMessage(t, client, IPCMessage{
		Type:          "status",
		Status:        "running",
		Error:         "listener unavailable: 0.0.0.0:80",
		FailedSiteIDs: []int64{siteID},
	})
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleSharedProxyConn() did not exit after client close")
	}

	if pm.sharedProxy == nil {
		t.Fatal("shared proxy missing after handler exit")
	}
	if !pm.sharedProxy.errored {
		t.Fatal("shared proxy errored = false, want true")
	}
	if pm.sharedProxy.retryCount != 1 {
		t.Fatalf("shared proxy retryCount = %d, want 1", pm.sharedProxy.retryCount)
	}
	if pm.sharedProxy.nextRetry.IsZero() {
		t.Fatal("shared proxy nextRetry is zero, want scheduled retry")
	}
	if !pm.sharedProxy.failedSites[siteID] {
		t.Fatalf("shared proxy failedSites missing site %d", siteID)
	}
	if pm.sharedProxy.binaryHash != "proxy-hash" {
		t.Fatalf("shared proxy binaryHash = %q, want proxy-hash", pm.sharedProxy.binaryHash)
	}
}

func TestHandleListSitesMarksSharedProxyFailures(t *testing.T) {
	db := openTestDB(t)
	firstID, err := dbAddSite(db, &Site{
		Domain:      "bad.example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.11",
		BackendHTTP: 8080,
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("dbAddSite(first) error = %v", err)
	}
	secondID, err := dbAddSite(db, &Site{
		Domain:      "ok.example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.12",
		BackendHTTP: 8081,
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("dbAddSite(second) error = %v", err)
	}

	pm := &ProcessManager{
		sharedProxy: &WorkerInfo{
			running:     true,
			errored:     true,
			failedSites: map[int64]bool{firstID: true},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
	rec := httptest.NewRecorder()
	handleListSites(rec, req, db, pm)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleListSites() status = %d, want 200", rec.Code)
	}

	var statuses []SiteStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &statuses); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	got := make(map[int64]string, len(statuses))
	for _, status := range statuses {
		got[status.ID] = status.Status
	}

	if got[firstID] != "error" {
		t.Fatalf("site %d status = %q, want error", firstID, got[firstID])
	}
	if got[secondID] != "running" {
		t.Fatalf("site %d status = %q, want running", secondID, got[secondID])
	}
}

func TestShouldRecoverStaleWorkerControl(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	now := time.Now()
	wi := &WorkerInfo{
		conn:          server,
		lastMessageAt: now.Add(-workerControlStaleTimeout - time.Second),
	}

	if !shouldRecoverStaleWorkerControl(wi, now) {
		t.Fatal("shouldRecoverStaleWorkerControl() = false, want true for stale worker")
	}
	if shouldRecoverStaleWorkerControl(wi, now) {
		t.Fatal("shouldRecoverStaleWorkerControl() = true twice without debounce, want false")
	}

	wi.staleRecoverAt = now.Add(-workerControlStaleRecoverEvery - time.Second)
	if !shouldRecoverStaleWorkerControl(wi, now) {
		t.Fatal("shouldRecoverStaleWorkerControl() = false after debounce window, want true")
	}

	fresh := &WorkerInfo{
		conn:          server,
		lastMessageAt: now,
	}
	if shouldRecoverStaleWorkerControl(fresh, now) {
		t.Fatal("shouldRecoverStaleWorkerControl() = true for fresh worker, want false")
	}
}
