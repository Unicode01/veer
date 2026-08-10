package app

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	userspaceWorkerHandoffFormatVersion = 1
	userspaceWorkerHandoffFileName      = "userspace-workers.json"
)

type userspaceWorkerHandoffKey struct {
	Kind  string
	Index int
}

type userspaceWorkerHandoffRecord struct {
	Kind       string `json:"kind"`
	Index      int    `json:"index"`
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	BinaryHash string `json:"binary_hash,omitempty"`

	process *os.Process
}

type userspaceWorkerHandoffState struct {
	FormatVersion int                            `json:"format_version"`
	OwnerPID      int                            `json:"owner_pid"`
	CreatedAt     time.Time                      `json:"created_at"`
	Workers       []userspaceWorkerHandoffRecord `json:"workers"`
}

func userspaceWorkerHandoffPath(sockPath string) string {
	if sockPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(sockPath), userspaceWorkerHandoffFileName)
}

func userspaceWorkerKey(kind string, index int) (userspaceWorkerHandoffKey, error) {
	switch kind {
	case workerKindRule, workerKindRange:
		if index < 0 {
			return userspaceWorkerHandoffKey{}, fmt.Errorf("invalid %s worker index %d", kind, index)
		}
		return userspaceWorkerHandoffKey{Kind: kind, Index: index}, nil
	case workerKindShared:
		return userspaceWorkerHandoffKey{Kind: kind}, nil
	default:
		return userspaceWorkerHandoffKey{}, fmt.Errorf("unsupported worker kind %q", kind)
	}
}

func (pm *ProcessManager) restorePreservedWorkerLocked(wi *WorkerInfo) bool {
	if pm == nil || wi == nil || len(pm.preservedWorkers) == 0 {
		return false
	}
	key, err := userspaceWorkerKey(wi.kind, wi.workerIndex)
	if err != nil {
		return false
	}
	record, ok := pm.preservedWorkers[key]
	if !ok || record.process == nil || record.PID <= 0 || record.StartTicks == 0 {
		return false
	}
	delete(pm.preservedWorkers, key)
	wi.process = record.process
	wi.processStartTicks = record.StartTicks
	wi.adoptedProcess = true
	wi.binaryHash = record.BinaryHash
	wi.lastStart = time.Now()
	return true
}

func (pm *ProcessManager) stopUnclaimedPreservedWorkers() {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	records := make([]userspaceWorkerHandoffRecord, 0, len(pm.preservedWorkers))
	for _, record := range pm.preservedWorkers {
		records = append(records, record)
	}
	pm.preservedWorkers = nil
	pm.mu.Unlock()

	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		return records[i].Index < records[j].Index
	})
	if len(records) > 0 {
		log.Printf("userspace worker handoff: stopping %d unclaimed process(es)", len(records))
	}
	for _, record := range records {
		stopUserspaceHandoffProcess(record, 3*time.Second)
	}
}

func refreshAdoptedWorkerProcess(wi *WorkerInfo) {
	if wi == nil || !wi.adoptedProcess || wi.process == nil {
		return
	}
	if userspaceWorkerProcessIdentityAlive(wi.process.Pid, wi.processStartTicks) {
		return
	}
	wi.process = nil
	wi.processStartTicks = 0
	wi.adoptedProcess = false
	wi.running = false
}

func userspaceWorkerControlReady(wi *WorkerInfo) bool {
	return wi != nil && wi.conn != nil
}

func shouldStartMissingUserspaceWorker(wi *WorkerInfo, now time.Time, ready bool) bool {
	if !ready || wi == nil || wi.starting || wi.process != nil || wi.conn != nil {
		return false
	}
	return now.Sub(wi.lastStart) > userspaceWorkerReconnectGrace
}
