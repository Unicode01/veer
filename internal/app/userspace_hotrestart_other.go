//go:build !linux

package app

import (
	"os"
	"time"
)

func prepareUserspaceWorkerHandoff(string, []*WorkerInfo) ([]*WorkerInfo, error) {
	return nil, nil
}

func loadUserspaceWorkerHandoff(string, bool) (map[userspaceWorkerHandoffKey]userspaceWorkerHandoffRecord, error) {
	return nil, nil
}

func removeUserspaceWorkerHandoff(string) {}

func validateUserspaceWorkerProcessIdentity(int, uint64) error {
	return nil
}

func userspaceWorkerProcessIdentityAlive(int, uint64) bool {
	return false
}

func stopUserspaceHandoffProcess(record userspaceWorkerHandoffRecord, _ time.Duration) {
	if record.process != nil {
		_ = record.process.Signal(os.Interrupt)
	}
}
