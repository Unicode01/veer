//go:build linux

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeUserspaceWorkerHandoffStateForTest(t *testing.T, sockPath string, state userspaceWorkerHandoffState, mode os.FileMode) {
	t.Helper()
	path := userspaceWorkerHandoffPath(sockPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create handoff directory: %v", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal handoff state: %v", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write handoff state: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod handoff state: %v", err)
	}
}

func TestLoadUserspaceWorkerHandoffValidatesProcessIdentity(t *testing.T) {
	helper := startUserspaceHandoffHelperProcess(t, "load-identity")
	startTicks, err := kernelProcessStartTicks(helper.cmd.Process.Pid)
	if err != nil {
		t.Fatalf("read helper process identity: %v", err)
	}
	sockPath := filepath.Join(t.TempDir(), "control.sock")
	state := userspaceWorkerHandoffState{
		FormatVersion: userspaceWorkerHandoffFormatVersion,
		OwnerPID:      os.Getpid(),
		CreatedAt:     time.Now().UTC(),
		Workers: []userspaceWorkerHandoffRecord{
			{
				Kind:       workerKindRule,
				Index:      3,
				PID:        helper.cmd.Process.Pid,
				StartTicks: startTicks,
				BinaryHash: "worker-hash",
			},
		},
	}
	writeUserspaceWorkerHandoffStateForTest(t, sockPath, state, 0o600)

	loaded, err := loadUserspaceWorkerHandoff(sockPath, true)
	if err != nil {
		t.Fatalf("load valid handoff: %v", err)
	}
	record, ok := loaded[userspaceWorkerHandoffKey{Kind: workerKindRule, Index: 3}]
	if !ok || record.process == nil || record.PID != helper.cmd.Process.Pid || record.StartTicks != startTicks {
		t.Fatalf("loaded handoff record = %+v, present=%t", record, ok)
	}

	state.Workers[0].StartTicks++
	writeUserspaceWorkerHandoffStateForTest(t, sockPath, state, 0o600)
	loaded, err = loadUserspaceWorkerHandoff(sockPath, true)
	if err != nil {
		t.Fatalf("load stale handoff: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("stale handoff loaded records = %+v, want none", loaded)
	}
}

func TestLoadUserspaceWorkerHandoffRejectsInsecurePermissions(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "control.sock")
	writeUserspaceWorkerHandoffStateForTest(t, sockPath, userspaceWorkerHandoffState{
		FormatVersion: userspaceWorkerHandoffFormatVersion,
	}, 0o644)

	if _, err := loadUserspaceWorkerHandoff(sockPath, true); err == nil {
		t.Fatal("loadUserspaceWorkerHandoff() error = nil, want insecure permissions rejection")
	}
}

func TestPrepareUserspaceWorkerHandoffRejectsReusedPID(t *testing.T) {
	helper := startUserspaceHandoffHelperProcess(t, "reused-pid")
	startTicks, err := kernelProcessStartTicks(helper.cmd.Process.Pid)
	if err != nil {
		t.Fatalf("read helper process identity: %v", err)
	}
	worker := &WorkerInfo{
		workerIndex:       4,
		kind:              workerKindRange,
		process:           helper.cmd.Process,
		processStartTicks: startTicks + 1,
		adoptedProcess:    true,
	}

	if _, err := prepareUserspaceWorkerHandoff(filepath.Join(t.TempDir(), "control.sock"), []*WorkerInfo{worker}); err == nil {
		t.Fatal("prepareUserspaceWorkerHandoff() error = nil, want reused PID rejection")
	}
}

func TestRestorePreservedWorkerClaimsOnlyMatchingSlot(t *testing.T) {
	startTicks, err := kernelProcessStartTicks(os.Getpid())
	if err != nil {
		t.Fatalf("read test process identity: %v", err)
	}
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("find test process: %v", err)
	}
	key := userspaceWorkerHandoffKey{Kind: workerKindRule, Index: 6}
	pm := &ProcessManager{preservedWorkers: map[userspaceWorkerHandoffKey]userspaceWorkerHandoffRecord{
		key: {
			Kind:       key.Kind,
			Index:      key.Index,
			PID:        os.Getpid(),
			StartTicks: startTicks,
			BinaryHash: "preserved-hash",
			process:    process,
		},
	}}

	if pm.restorePreservedWorkerLocked(&WorkerInfo{kind: workerKindRange, workerIndex: key.Index}) {
		t.Fatal("restorePreservedWorkerLocked() restored a worker into the wrong kind")
	}
	worker := &WorkerInfo{kind: key.Kind, workerIndex: key.Index}
	if !pm.restorePreservedWorkerLocked(worker) {
		t.Fatal("restorePreservedWorkerLocked() = false for matching slot")
	}
	if worker.process == nil || worker.process.Pid != os.Getpid() || worker.processStartTicks != startTicks || !worker.adoptedProcess || worker.binaryHash != "preserved-hash" {
		t.Fatalf("restored worker = %+v", worker)
	}
	if len(pm.preservedWorkers) != 0 {
		t.Fatalf("claimed handoff records = %+v, want empty", pm.preservedWorkers)
	}
}
