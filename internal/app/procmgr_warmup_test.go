package app

import (
	"testing"
	"time"
)

func TestWaitForUserspaceWorkersRequiresRunningState(t *testing.T) {
	pm := &ProcessManager{
		ruleWorkers: map[int]*WorkerInfo{
			0: {
				rules:   []Rule{{ID: 1}},
				errored: true,
			},
		},
		rangeWorkers: map[int]*WorkerInfo{},
	}

	if pm.waitForUserspaceWorkers([]int{0}, nil, time.Millisecond) {
		t.Fatal("waitForUserspaceWorkers() = true for errored non-running worker, want false")
	}

	pm.ruleWorkers[0].running = true
	pm.ruleWorkers[0].errored = false

	if !pm.waitForUserspaceWorkers([]int{0}, nil, time.Millisecond) {
		t.Fatal("waitForUserspaceWorkers() = false for running worker, want true")
	}
}
