package app

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var errDataplaneReconcileSuperseded = errors.New("dataplane reconcile generation superseded")

type DataplaneReconcileStatus struct {
	Status             string `json:"status"`
	DesiredGeneration  uint64 `json:"desired_generation"`
	AppliedGeneration  uint64 `json:"applied_generation"`
	PendingGenerations uint64 `json:"pending_generations"`
	RetryCount         int    `json:"retry_count,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	LastAttemptAt      string `json:"last_attempt_at,omitempty"`
	LastAppliedAt      string `json:"last_applied_at,omitempty"`
}

type PluginReconcileStatus struct {
	Status        string `json:"status"`
	RetryCount    int    `json:"retry_count,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	LastAppliedAt string `json:"last_applied_at,omitempty"`
}

func (pm *ProcessManager) beginDataplaneReconcile() uint64 {
	if pm == nil {
		return 0
	}
	pm.mu.Lock()
	pm.desiredGeneration++
	generation := pm.desiredGeneration
	pm.mu.Unlock()
	return generation
}

func (pm *ProcessManager) markDataplaneReconcileAttempt(generation uint64) {
	if pm == nil || generation == 0 {
		return
	}
	pm.mu.Lock()
	if generation == pm.desiredGeneration {
		pm.reconcileLastAttemptAt = time.Now()
	}
	pm.mu.Unlock()
}

func (pm *ProcessManager) markDataplaneReconcilePrepared(generation uint64) {
	if pm == nil || generation == 0 {
		return
	}
	pm.mu.Lock()
	if generation > pm.preparedGeneration {
		pm.preparedGeneration = generation
	}
	if generation == pm.desiredGeneration {
		pm.reconcileLastError = ""
		pm.reconcileRetryCount = 0
		pm.refreshDataplaneAppliedLocked(time.Now())
	}
	pm.mu.Unlock()
}

func (pm *ProcessManager) markDataplaneReconcileFailed(generation uint64, err error) {
	if pm == nil || generation == 0 || err == nil {
		return
	}
	pm.mu.Lock()
	current := generation == pm.desiredGeneration && !pm.shuttingDown
	retryCount := 0
	if current {
		pm.reconcileLastError = strings.TrimSpace(err.Error())
		pm.reconcileRetryCount++
		retryCount = pm.reconcileRetryCount
	}
	pm.mu.Unlock()
	if current {
		pm.requestRedistributeRetry(generation, nextDataplaneReconcileRetryDelay(retryCount))
	}
}

func nextDataplaneReconcileRetryDelay(retryCount int) time.Duration {
	if retryCount <= 1 {
		return redistributeRetryDelay
	}
	delay := redistributeRetryDelay
	for i := 1; i < retryCount; i++ {
		if delay >= workerRetryMaxDelay/2 {
			return workerRetryMaxDelay
		}
		delay *= 2
	}
	if delay > workerRetryMaxDelay {
		return workerRetryMaxDelay
	}
	return delay
}

func (pm *ProcessManager) refreshDataplaneAppliedLocked(now time.Time) {
	if pm == nil || pm.desiredGeneration == 0 || pm.preparedGeneration < pm.desiredGeneration {
		return
	}
	generation := pm.desiredGeneration
	for _, workers := range []map[int]*WorkerInfo{pm.ruleWorkers, pm.rangeWorkers} {
		for _, wi := range workers {
			if !workerGenerationApplied(wi, generation) {
				return
			}
		}
	}
	if pm.sharedProxy != nil && !workerGenerationApplied(pm.sharedProxy, generation) {
		return
	}
	pm.appliedGeneration = generation
	pm.reconcileLastError = ""
	pm.reconcileRetryCount = 0
	pm.reconcileLastAppliedAt = now
}

func workerGenerationApplied(wi *WorkerInfo, generation uint64) bool {
	if wi == nil {
		return true
	}
	return wi.desiredGeneration == generation && wi.appliedGeneration >= generation && !wi.errored
}

func workerConfigFullyApplied(wi *WorkerInfo) bool {
	if wi == nil || wi.conn == nil || !wi.running || wi.errored {
		return false
	}
	return len(wi.failedRules) == 0 && len(wi.failedRanges) == 0 && len(wi.failedSites) == 0
}

func advanceWorkerGenerationLocked(wi *WorkerInfo, generation uint64, configChanged bool) bool {
	if wi == nil || generation == 0 {
		return false
	}
	if generation < wi.desiredGeneration {
		return false
	}
	previousDesired := wi.desiredGeneration
	previousApplied := wi.appliedGeneration
	wi.desiredGeneration = generation
	if !configChanged && previousApplied >= previousDesired && workerConfigFullyApplied(wi) {
		wi.appliedGeneration = generation
		return false
	}
	return wi.conn != nil
}

func noteWorkerGenerationStatusLocked(wi *WorkerInfo, status IPCMessage, fullyApplied bool) {
	if wi == nil || status.Generation == 0 || status.Generation != wi.desiredGeneration {
		return
	}
	wi.configSentAt = time.Time{}
	if fullyApplied {
		wi.appliedGeneration = status.Generation
	}
}

func (pm *ProcessManager) dataplaneReconcileStatus() DataplaneReconcileStatus {
	if pm == nil {
		return DataplaneReconcileStatus{Status: "unavailable"}
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.dataplaneReconcileStatusLocked()
}

func (pm *ProcessManager) dataplaneReconcileStatusLocked() DataplaneReconcileStatus {
	desired := pm.desiredGeneration
	applied := pm.appliedGeneration
	status := "applied"
	lastError := strings.TrimSpace(pm.reconcileLastError)
	if lastError == "" {
		lastError = pm.workerReconcileErrorLocked()
	}
	if lastError != "" {
		status = "error"
	} else if applied < desired {
		status = "pending"
	}
	pending := uint64(0)
	if desired > applied {
		pending = desired - applied
	}
	return DataplaneReconcileStatus{
		Status:             status,
		DesiredGeneration:  desired,
		AppliedGeneration:  applied,
		PendingGenerations: pending,
		RetryCount:         pm.reconcileRetryCount,
		LastError:          lastError,
		LastAttemptAt:      reconcileTimestamp(pm.reconcileLastAttemptAt),
		LastAppliedAt:      reconcileTimestamp(pm.reconcileLastAppliedAt),
	}
}

func (pm *ProcessManager) pluginReconcileStatus() PluginReconcileStatus {
	if pm == nil {
		return PluginReconcileStatus{Status: "unavailable"}
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.pluginReconcileStatusLocked()
}

func (pm *ProcessManager) pluginReconcileStatusLocked() PluginReconcileStatus {
	status := "applied"
	if strings.TrimSpace(pm.pluginReconcileLastError) != "" {
		status = "error"
	}
	return PluginReconcileStatus{
		Status:        status,
		RetryCount:    pm.pluginReconcileRetryCount,
		LastError:     strings.TrimSpace(pm.pluginReconcileLastError),
		LastAttemptAt: reconcileTimestamp(pm.pluginReconcileLastAttemptAt),
		LastAppliedAt: reconcileTimestamp(pm.pluginReconcileLastAppliedAt),
	}
}

func (pm *ProcessManager) readinessReconcileSnapshot() (bool, DataplaneReconcileStatus, PluginReconcileStatus) {
	if pm == nil {
		return false, DataplaneReconcileStatus{Status: "unavailable"}, PluginReconcileStatus{Status: "unavailable"}
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.isReadyLocked(time.Now()), pm.dataplaneReconcileStatusLocked(), pm.pluginReconcileStatusLocked()
}

func reconcileTimestamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (pm *ProcessManager) workerReconcileErrorLocked() string {
	for idx, wi := range pm.ruleWorkers {
		if wi != nil && wi.errored {
			return workerReconcileError(fmt.Sprintf("rule worker[%d]", idx), wi)
		}
	}
	for idx, wi := range pm.rangeWorkers {
		if wi != nil && wi.errored {
			return workerReconcileError(fmt.Sprintf("range worker[%d]", idx), wi)
		}
	}
	if pm.sharedProxy != nil && pm.sharedProxy.errored {
		return workerReconcileError("shared proxy", pm.sharedProxy)
	}
	return ""
}

func workerReconcileError(name string, wi *WorkerInfo) string {
	message := strings.TrimSpace(wi.lastError)
	if message == "" {
		message = "configuration was not fully applied"
	}
	return name + ": " + message
}
