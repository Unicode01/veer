package app

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	pluginControlCircuitFailureThreshold = 5
	pluginControlCircuitBaseBackoff      = time.Second
	pluginControlCircuitMaxBackoff       = time.Minute
)

type PluginControlCircuitState struct {
	Key                 string  `json:"key"`
	Status              string  `json:"status"`
	Calls               uint64  `json:"calls"`
	Successes           uint64  `json:"successes"`
	Failures            uint64  `json:"failures"`
	Rejected            uint64  `json:"rejected"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
	FailureRate         float64 `json:"failure_rate"`
	AverageDurationMS   float64 `json:"average_duration_ms"`
	MaxDurationMS       float64 `json:"max_duration_ms"`
	OpenUntil           string  `json:"open_until,omitempty"`
	LastFailureAt       string  `json:"last_failure_at,omitempty"`
	LastError           string  `json:"last_error,omitempty"`
}

type PluginControlHealthState struct {
	Status            string                      `json:"status"`
	Calls             uint64                      `json:"calls"`
	Successes         uint64                      `json:"successes"`
	Failures          uint64                      `json:"failures"`
	Rejected          uint64                      `json:"rejected"`
	FailureRate       float64                     `json:"failure_rate"`
	AverageDurationMS float64                     `json:"average_duration_ms"`
	MaxDurationMS     float64                     `json:"max_duration_ms"`
	OpenCircuits      int                         `json:"open_circuits"`
	LastFailureAt     string                      `json:"last_failure_at,omitempty"`
	LastError         string                      `json:"last_error,omitempty"`
	LogEntries        uint64                      `json:"log_entries"`
	DroppedLogs       uint64                      `json:"dropped_logs"`
	Circuits          []PluginControlCircuitState `json:"circuits,omitempty"`
}

type pluginControlCircuitRuntime struct {
	pluginID            string
	key                 string
	calls               uint64
	successes           uint64
	failures            uint64
	rejected            uint64
	consecutiveFailures int
	openCount           int
	halfOpen            bool
	openUntil           time.Time
	totalDuration       time.Duration
	maxDuration         time.Duration
	lastFailureAt       time.Time
	lastError           string
}

type pluginControlInvocation struct {
	pluginID string
	key      string
	started  time.Time
	tracked  bool
	probe    bool
}

func (rt *gojaPluginControlRuntime) beginPluginControlInvocation(plugin LoadedPlugin, event pluginControlEvent, now time.Time) (pluginControlInvocation, error) {
	invocation := pluginControlInvocation{pluginID: plugin.ID, key: pluginControlCircuitKey(event), started: now}
	if rt == nil || !pluginControlCircuitTracks(event) || plugin.ID == "" {
		return invocation, nil
	}
	invocation.tracked = true
	mapKey := plugin.ID + "\x00" + invocation.key
	rt.circuitMu.Lock()
	defer rt.circuitMu.Unlock()
	if rt.controlCircuits == nil {
		rt.controlCircuits = make(map[string]*pluginControlCircuitRuntime)
	}
	circuit := rt.controlCircuits[mapKey]
	if circuit == nil {
		circuit = &pluginControlCircuitRuntime{pluginID: plugin.ID, key: invocation.key}
		rt.controlCircuits[mapKey] = circuit
	}
	if !circuit.openUntil.IsZero() {
		if now.Before(circuit.openUntil) {
			circuit.rejected++
			return invocation, fmt.Errorf("plugin control circuit %s is open until %s", invocation.key, circuit.openUntil.UTC().Format(time.RFC3339Nano))
		}
		if circuit.halfOpen {
			circuit.rejected++
			return invocation, fmt.Errorf("plugin control circuit %s is waiting for its recovery probe", invocation.key)
		}
		circuit.halfOpen = true
		invocation.probe = true
	}
	circuit.calls++
	return invocation, nil
}

func (rt *gojaPluginControlRuntime) finishPluginControlInvocation(invocation pluginControlInvocation, callErr error, now time.Time) {
	if rt == nil || !invocation.tracked {
		return
	}
	duration := now.Sub(invocation.started)
	if duration < 0 {
		duration = 0
	}
	mapKey := invocation.pluginID + "\x00" + invocation.key
	rt.circuitMu.Lock()
	defer rt.circuitMu.Unlock()
	circuit := rt.controlCircuits[mapKey]
	if circuit == nil {
		return
	}
	circuit.totalDuration += duration
	if duration > circuit.maxDuration {
		circuit.maxDuration = duration
	}
	if callErr == nil {
		circuit.successes++
		circuit.consecutiveFailures = 0
		circuit.openCount = 0
		circuit.halfOpen = false
		circuit.openUntil = time.Time{}
		circuit.lastError = ""
		return
	}
	circuit.failures++
	circuit.consecutiveFailures++
	circuit.lastFailureAt = now
	circuit.lastError = boundedPluginControlHealthError(callErr.Error())
	if !invocation.probe && circuit.consecutiveFailures < pluginControlCircuitFailureThreshold {
		return
	}
	circuit.openCount++
	circuit.halfOpen = false
	circuit.openUntil = now.Add(pluginControlCircuitBackoff(circuit.openCount))
}

func pluginControlCircuitTracks(event pluginControlEvent) bool {
	switch event.Kind {
	case "", "register", "deactivate", "resource_migrate", "ebpf_state_migrate", "upgrade_probe", "upgrade_restore", "upgrade_snapshot":
		return false
	default:
		return true
	}
}

func pluginControlCircuitKey(event pluginControlEvent) string {
	switch event.Kind {
	case "event":
		if event.BusEvent != nil {
			key := "event:" + event.BusEvent.Topic
			if event.BusEvent.SubscriptionID != "" {
				key += ":" + event.BusEvent.SubscriptionID
			}
			return key
		}
	case "worker":
		if event.Worker != nil {
			return "worker:" + event.Worker.Name + ":" + event.Worker.Handler
		}
	}
	return pluginControlEventKey(event)
}

func pluginControlCircuitBackoff(openCount int) time.Duration {
	if openCount < 1 {
		openCount = 1
	}
	delay := pluginControlCircuitBaseBackoff
	for i := 1; i < openCount && delay < pluginControlCircuitMaxBackoff; i++ {
		if delay > pluginControlCircuitMaxBackoff/2 {
			return pluginControlCircuitMaxBackoff
		}
		delay *= 2
	}
	if delay > pluginControlCircuitMaxBackoff {
		return pluginControlCircuitMaxBackoff
	}
	return delay
}

func boundedPluginControlHealthError(message string) string {
	message = strings.TrimSpace(message)
	if len(message) <= pluginControlMaxLogMessageBytes {
		return message
	}
	return message[:pluginControlMaxLogMessageBytes] + "...<truncated>"
}

func (rt *gojaPluginControlRuntime) pluginControlHealthSnapshot(pluginID string) PluginControlHealthState {
	health := PluginControlHealthState{Status: "healthy"}
	if rt == nil {
		return health
	}
	now := time.Now()
	degraded := false
	rt.circuitMu.Lock()
	for _, circuit := range rt.controlCircuits {
		if circuit.pluginID != pluginID {
			continue
		}
		state := pluginControlCircuitSnapshot(circuit, now)
		health.Calls += state.Calls
		health.Successes += state.Successes
		health.Failures += state.Failures
		health.Rejected += state.Rejected
		if state.Status == "open" || state.Status == "half_open" {
			health.OpenCircuits++
		}
		if state.ConsecutiveFailures > 0 {
			degraded = true
		}
		if state.MaxDurationMS > health.MaxDurationMS {
			health.MaxDurationMS = state.MaxDurationMS
		}
		if state.LastFailureAt > health.LastFailureAt {
			health.LastFailureAt = state.LastFailureAt
			health.LastError = state.LastError
		}
		health.Circuits = append(health.Circuits, state)
	}
	rt.circuitMu.Unlock()
	if health.Calls > 0 {
		health.FailureRate = float64(health.Failures) / float64(health.Calls)
		var total float64
		for _, circuit := range health.Circuits {
			total += circuit.AverageDurationMS * float64(circuit.Calls)
		}
		health.AverageDurationMS = total / float64(health.Calls)
	}
	if health.OpenCircuits > 0 {
		health.Status = "quarantined"
	} else if degraded {
		health.Status = "degraded"
	}
	logs := rt.pluginLogState(pluginID)
	health.LogEntries = logs.Entries
	health.DroppedLogs = logs.Dropped
	sort.Slice(health.Circuits, func(i, j int) bool { return health.Circuits[i].Key < health.Circuits[j].Key })
	return health
}

func (rt *gojaPluginControlRuntime) reconcilePluginControlCircuits(previous, current map[string]LoadedPlugin) {
	if rt == nil {
		return
	}
	rt.circuitMu.Lock()
	for key, circuit := range rt.controlCircuits {
		before, hadBefore := previous[circuit.pluginID]
		after, hasAfter := current[circuit.pluginID]
		if !hasAfter || !hadBefore || before.Version != after.Version || before.sourceFingerprint != after.sourceFingerprint {
			delete(rt.controlCircuits, key)
		}
	}
	rt.circuitMu.Unlock()
}

func pluginControlCircuitSnapshot(circuit *pluginControlCircuitRuntime, now time.Time) PluginControlCircuitState {
	state := PluginControlCircuitState{
		Key: circuit.key, Status: "closed", Calls: circuit.calls, Successes: circuit.successes, Failures: circuit.failures,
		Rejected: circuit.rejected, ConsecutiveFailures: circuit.consecutiveFailures, MaxDurationMS: float64(circuit.maxDuration) / float64(time.Millisecond),
		LastError: circuit.lastError,
	}
	if circuit.calls > 0 {
		state.FailureRate = float64(circuit.failures) / float64(circuit.calls)
		state.AverageDurationMS = float64(circuit.totalDuration) / float64(time.Millisecond) / float64(circuit.calls)
	}
	if !circuit.openUntil.IsZero() {
		state.OpenUntil = circuit.openUntil.UTC().Format(time.RFC3339Nano)
		if circuit.halfOpen || !now.Before(circuit.openUntil) {
			state.Status = "half_open"
		} else {
			state.Status = "open"
		}
	}
	if !circuit.lastFailureAt.IsZero() {
		state.LastFailureAt = circuit.lastFailureAt.UTC().Format(time.RFC3339Nano)
	}
	return state
}

func (rt *gojaPluginControlRuntime) clearPluginControlCircuits(pluginID string) {
	if rt == nil {
		return
	}
	rt.circuitMu.Lock()
	for key, circuit := range rt.controlCircuits {
		if circuit.pluginID == pluginID {
			delete(rt.controlCircuits, key)
		}
	}
	rt.circuitMu.Unlock()
}

func (rt *gojaPluginControlRuntime) clearAllPluginControlCircuits() {
	if rt == nil {
		return
	}
	rt.circuitMu.Lock()
	rt.controlCircuits = nil
	rt.circuitMu.Unlock()
}
