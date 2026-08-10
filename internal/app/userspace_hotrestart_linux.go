//go:build linux

package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

const userspaceWorkerHandoffMaxBytes = 1 << 20

func prepareUserspaceWorkerHandoff(sockPath string, workers []*WorkerInfo) ([]*WorkerInfo, error) {
	path := userspaceWorkerHandoffPath(sockPath)
	if path == "" {
		return nil, fmt.Errorf("userspace worker handoff path is empty")
	}

	records := make([]userspaceWorkerHandoffRecord, 0, len(workers))
	preserved := make([]*WorkerInfo, 0, len(workers))
	seen := make(map[userspaceWorkerHandoffKey]struct{}, len(workers))
	for _, wi := range workers {
		if wi == nil || (wi.process == nil && wi.conn == nil) {
			continue
		}
		key, err := userspaceWorkerKey(wi.kind, wi.workerIndex)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate userspace worker handoff slot %s[%d]", key.Kind, key.Index)
		}
		if wi.process == nil || wi.process.Pid <= 0 {
			return nil, fmt.Errorf("%s worker[%d] has no process identity", key.Kind, key.Index)
		}
		startTicks, err := kernelProcessStartTicks(wi.process.Pid)
		if err != nil {
			return nil, fmt.Errorf("read %s worker[%d] process identity: %w", key.Kind, key.Index, err)
		}
		if wi.adoptedProcess && wi.processStartTicks != 0 && wi.processStartTicks != startTicks {
			return nil, fmt.Errorf("%s worker[%d] pid %d was reused", key.Kind, key.Index, wi.process.Pid)
		}
		seen[key] = struct{}{}
		records = append(records, userspaceWorkerHandoffRecord{
			Kind:       key.Kind,
			Index:      key.Index,
			PID:        wi.process.Pid,
			StartTicks: startTicks,
			BinaryHash: wi.binaryHash,
		})
		preserved = append(preserved, wi)
	}

	if len(records) == 0 {
		removeUserspaceWorkerHandoff(sockPath)
		return nil, nil
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		return records[i].Index < records[j].Index
	})
	state := userspaceWorkerHandoffState{
		FormatVersion: userspaceWorkerHandoffFormatVersion,
		OwnerPID:      os.Getpid(),
		CreatedAt:     time.Now().UTC(),
		Workers:       records,
	}
	data, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal userspace worker handoff: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create userspace worker handoff directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure userspace worker handoff directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".userspace-workers-*")
	if err != nil {
		return nil, fmt.Errorf("create userspace worker handoff temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secure userspace worker handoff temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write userspace worker handoff: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("sync userspace worker handoff: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close userspace worker handoff: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, fmt.Errorf("publish userspace worker handoff: %w", err)
	}
	return preserved, nil
}

func loadUserspaceWorkerHandoff(sockPath string, enabled bool) (map[userspaceWorkerHandoffKey]userspaceWorkerHandoffRecord, error) {
	path := userspaceWorkerHandoffPath(sockPath)
	if path == "" {
		return nil, nil
	}
	if !enabled {
		_ = os.Remove(path)
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect userspace worker handoff: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("userspace worker handoff is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("userspace worker handoff permissions are %#o, want no group or other access", info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("userspace worker handoff owner uid is %d, want %d", stat.Uid, os.Geteuid())
	}
	if info.Size() > userspaceWorkerHandoffMaxBytes {
		return nil, fmt.Errorf("userspace worker handoff is too large: %d bytes", info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read userspace worker handoff: %w", err)
	}
	var state userspaceWorkerHandoffState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode userspace worker handoff: %w", err)
	}
	if state.FormatVersion != userspaceWorkerHandoffFormatVersion {
		return nil, fmt.Errorf("userspace worker handoff format is %d, want %d", state.FormatVersion, userspaceWorkerHandoffFormatVersion)
	}
	if len(state.Workers) > 4096 {
		return nil, fmt.Errorf("userspace worker handoff contains too many workers: %d", len(state.Workers))
	}

	loaded := make(map[userspaceWorkerHandoffKey]userspaceWorkerHandoffRecord, len(state.Workers))
	for _, record := range state.Workers {
		key, err := userspaceWorkerKey(record.Kind, record.Index)
		if err != nil {
			return nil, err
		}
		if _, exists := loaded[key]; exists {
			return nil, fmt.Errorf("duplicate userspace worker handoff slot %s[%d]", key.Kind, key.Index)
		}
		if record.PID <= 0 || record.StartTicks == 0 {
			return nil, fmt.Errorf("invalid process identity for %s worker[%d]", key.Kind, key.Index)
		}
		startTicks, err := kernelProcessStartTicks(record.PID)
		if err != nil || startTicks != record.StartTicks {
			continue
		}
		process, err := os.FindProcess(record.PID)
		if err != nil {
			continue
		}
		record.process = process
		loaded[key] = record
	}
	if len(loaded) == 0 {
		return nil, nil
	}
	return loaded, nil
}

func removeUserspaceWorkerHandoff(sockPath string) {
	if path := userspaceWorkerHandoffPath(sockPath); path != "" {
		_ = os.Remove(path)
	}
}

func validateUserspaceWorkerProcessIdentity(pid int, startTicks uint64) error {
	if startTicks == 0 {
		return nil
	}
	current, err := kernelProcessStartTicks(pid)
	if err != nil {
		return err
	}
	if current != startTicks {
		return fmt.Errorf("peer pid %d start time changed", pid)
	}
	return nil
}

func userspaceWorkerProcessIdentityAlive(pid int, startTicks uint64) bool {
	return validateUserspaceWorkerProcessIdentity(pid, startTicks) == nil
}

func stopUserspaceHandoffProcess(record userspaceWorkerHandoffRecord, timeout time.Duration) {
	if record.process == nil || !userspaceWorkerProcessIdentityAlive(record.PID, record.StartTicks) {
		return
	}
	_ = record.process.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !userspaceWorkerProcessIdentityAlive(record.PID, record.StartTicks) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	if userspaceWorkerProcessIdentityAlive(record.PID, record.StartTicks) {
		_ = record.process.Kill()
	}
}
