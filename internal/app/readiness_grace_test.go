package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadinessHoldsWhileAReconcileSettles(t *testing.T) {
	pm := &ProcessManager{ready: true}
	readyAt := func(now time.Time) bool {
		pm.mu.Lock()
		defer pm.mu.Unlock()
		return pm.isReadyLocked(now)
	}

	// Nothing applied yet: the first reconcile still has to finish.
	first := pm.beginDataplaneReconcile()
	if readyAt(time.Now()) {
		t.Fatal("ready before the first generation was applied")
	}
	pm.markDataplaneReconcilePrepared(first)
	if !readyAt(time.Now()) {
		t.Fatal("not ready after the first generation was applied")
	}

	// A later reconcile keeps readiness while it settles, but not forever.
	second := pm.beginDataplaneReconcile()
	started := time.Now()
	if !readyAt(started) || !readyAt(started.Add(readinessReconcileGrace-time.Second)) {
		t.Fatal("a reconcile on top of an applied generation made the service unready")
	}
	if readyAt(started.Add(readinessReconcileGrace + time.Second)) {
		t.Fatalf("still ready with a reconcile pending past %s", readinessReconcileGrace)
	}

	// The clock starts when the applied state was left, not at each new
	// generation queued on top of a pending one.
	pm.beginDataplaneReconcile()
	if readyAt(started.Add(readinessReconcileGrace + time.Second)) {
		t.Fatal("a generation queued on a pending one restarted the grace period")
	}

	// A failure counts at once.
	pm.markDataplaneReconcileFailed(pm.desiredGeneration, errors.New("attach failed"))
	if readyAt(time.Now()) {
		t.Fatal("ready while the pending reconcile failed")
	}

	pm.markDataplaneReconcilePrepared(pm.desiredGeneration)
	if !readyAt(time.Now()) {
		t.Fatal("not ready once the pending generations were applied")
	}
	pm.mu.Lock()
	since := pm.reconcilePendingSince
	pm.mu.Unlock()
	if !since.IsZero() || second == 0 {
		t.Fatalf("pending clock = %v after the apply, want it cleared", since)
	}
}

func TestWorkerReadyForGenerationWhileSettling(t *testing.T) {
	behind := &WorkerInfo{desiredGeneration: 4, appliedGeneration: 3}
	if workerReadyForGeneration(behind, 4, false) {
		t.Fatal("a worker behind the desired generation counted as ready outside a settling reconcile")
	}
	if !workerReadyForGeneration(behind, 4, true) {
		t.Fatal("a worker still applying the new generation made a settling reconcile unready")
	}
	if workerReadyForGeneration(&WorkerInfo{desiredGeneration: 4, appliedGeneration: 3, errored: true}, 4, true) {
		t.Fatal("a failed worker counted as ready while settling")
	}
}

func TestBuildAPIHandlerReadyzStaysReadyWhileReconcileSettles(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{}
	pm.setReady(true)
	pm.markDataplaneReconcilePrepared(pm.beginDataplaneReconcile())
	pm.beginDataplaneReconcile()
	handler := buildAPIHandler(&Config{WebBind: "127.0.0.1", WebPort: 8080, WebToken: "test-token"}, db, pm)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz while a reconcile settles = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp struct {
		Status    string `json:"status"`
		Ready     bool   `json:"ready"`
		Dataplane struct {
			Status             string `json:"status"`
			PendingGenerations uint64 `json:"pending_generations"`
		} `json:"dataplane"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /readyz: %v", err)
	}
	if !resp.Ready || resp.Status != "ready" || resp.Dataplane.Status != "pending" || resp.Dataplane.PendingGenerations != 1 {
		t.Fatalf("/readyz = %+v, want ready with the pending generation still reported", resp)
	}
}
