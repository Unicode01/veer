package app

import (
	"sort"
	"strings"
	"time"
)

func normalizeKernelRuntimeNoteKey(key string) string {
	return strings.TrimSpace(key)
}

func (pm *ProcessManager) snapshotKernelRuntimeDismissedNoteKeysLocked() []string {
	if pm == nil || len(pm.kernelRuntimeDismissedNoteKeys) == 0 {
		return nil
	}
	keys := make([]string, 0, len(pm.kernelRuntimeDismissedNoteKeys))
	for key := range pm.kernelRuntimeDismissedNoteKeys {
		key = normalizeKernelRuntimeNoteKey(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	return keys
}

func (pm *ProcessManager) snapshotKernelRuntimeDismissedNoteKeys() []string {
	if pm == nil {
		return nil
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.snapshotKernelRuntimeDismissedNoteKeysLocked()
}

func (pm *ProcessManager) dismissKernelRuntimeNote(key string) []string {
	if pm == nil {
		return nil
	}
	key = normalizeKernelRuntimeNoteKey(key)
	if key == "" {
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.kernelRuntimeDismissedNoteKeys == nil {
		pm.kernelRuntimeDismissedNoteKeys = make(map[string]struct{})
	}
	pm.kernelRuntimeDismissedNoteKeys[key] = struct{}{}
	pm.kernelRuntimeSnapshot = KernelRuntimeResponse{}
	pm.kernelRuntimeSnapshotAt = time.Time{}
	return pm.snapshotKernelRuntimeDismissedNoteKeysLocked()
}
