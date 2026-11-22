package app

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pluginNativeWorkerEnv          = "VEER_PLUGIN_WORKER"
	pluginNativeWorkerStartTimeout = 10 * time.Second
	pluginNativeWorkerStopGrace    = 500 * time.Millisecond
	pluginNativeMaxCallsPerEvent   = pluginHostMaxCallsPerEvent
)

var errPluginNativeUnsupported = errors.New("native plugins are not supported on this platform")

// pluginNativeWorkerPool runs the worker processes that load native plugins.
// Plugins that declare worker "shared" share one process; "dedicated"
// plugins and plugins demoted after a crash or hang get their own; any
// other name is a group several plugins share.
type pluginNativeWorkerPool struct {
	mu      sync.Mutex
	cfg     *Config
	workers map[string]*pluginNativeWorker
	demoted map[string]string
	closed  bool
	// limitWarned keeps a missing cgroup setup to one log line.
	limitWarned atomic.Bool
}

func newPluginNativeWorkerPool(cfg *Config) *pluginNativeWorkerPool {
	return &pluginNativeWorkerPool{
		cfg:     cfg,
		workers: make(map[string]*pluginNativeWorker),
		demoted: make(map[string]string),
	}
}

func (pool *pluginNativeWorkerPool) groupFor(plugin LoadedPlugin) string {
	pool.mu.Lock()
	_, demoted := pool.demoted[plugin.ID]
	pool.mu.Unlock()
	worker := pluginNativeWorkerShared
	if plugin.Control != nil && plugin.Control.Worker != "" {
		worker = plugin.Control.Worker
	}
	if demoted || worker == pluginNativeWorkerDedicated {
		return "dedicated:" + plugin.ID
	}
	if worker == pluginNativeWorkerShared {
		return pluginNativeWorkerShared
	}
	return "group:" + worker
}

// demote moves a plugin that crashed or hung its worker into a worker of
// its own, so it cannot take its neighbours down again.
func (pool *pluginNativeWorkerPool) demote(pluginID string, reason string) {
	pool.mu.Lock()
	if _, exists := pool.demoted[pluginID]; !exists {
		pool.demoted[pluginID] = reason
		log.Printf("plugin %s moved to a dedicated worker: %s", pluginID, reason)
	}
	pool.mu.Unlock()
}

func (pool *pluginNativeWorkerPool) demotionReason(pluginID string) string {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.demoted[pluginID]
}

// load starts or reuses the plugin's worker and creates an instance in it.
func (pool *pluginNativeWorkerPool) load(plugin LoadedPlugin, hooks pluginNativeInstanceHooks, deadline time.Time) (*pluginNativeInstance, error) {
	if plugin.nativeLibraryPath == "" {
		triple := pluginNativeHostTriple()
		if triple == "" {
			return nil, errPluginNativeUnsupported
		}
		return nil, fmt.Errorf("plugin %s has no native library for %s", plugin.ID, triple)
	}
	for attempt := 0; attempt < 2; attempt++ {
		worker, err := pool.worker(pool.groupFor(plugin), deadline)
		if err != nil {
			return nil, err
		}
		instance, restart, err := worker.load(plugin, hooks, deadline)
		if err == nil {
			return instance, nil
		}
		if !restart {
			return nil, err
		}
		// The library changed after this worker mapped an older copy:
		// restart the worker so every plugin in it loads its current build.
		worker.stop(err.Error())
	}
	return nil, fmt.Errorf("plugin %s: worker restart did not pick up the new library", plugin.ID)
}

func (pool *pluginNativeWorkerPool) worker(group string, deadline time.Time) (*pluginNativeWorker, error) {
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return nil, errPluginRuntimeTargetNotLoaded
	}
	if existing := pool.workers[group]; existing != nil && existing.alive() {
		pool.mu.Unlock()
		return existing, nil
	}
	pool.mu.Unlock()

	worker, err := startPluginNativeWorker(pool, group, deadline)
	if err != nil {
		return nil, err
	}
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		worker.stop("plugin runtime closed")
		return nil, errPluginRuntimeTargetNotLoaded
	}
	if existing := pool.workers[group]; existing != nil && existing.alive() {
		pool.mu.Unlock()
		worker.stop("another worker for this group started first")
		return existing, nil
	}
	pool.workers[group] = worker
	pool.mu.Unlock()
	return worker, nil
}

func (pool *pluginNativeWorkerPool) forget(worker *pluginNativeWorker) {
	pool.mu.Lock()
	if pool.workers[worker.group] == worker {
		delete(pool.workers, worker.group)
	}
	pool.mu.Unlock()
}

func (pool *pluginNativeWorkerPool) Close() {
	pool.mu.Lock()
	pool.closed = true
	workers := make([]*pluginNativeWorker, 0, len(pool.workers))
	for _, worker := range pool.workers {
		workers = append(workers, worker)
	}
	pool.workers = make(map[string]*pluginNativeWorker)
	pool.mu.Unlock()
	for _, worker := range workers {
		worker.stop("plugin runtime closed")
	}
}

// snapshot reports the running workers for the plugin runtime status.
func (pool *pluginNativeWorkerPool) snapshot() []PluginNativeWorkerState {
	pool.mu.Lock()
	workers := make([]*pluginNativeWorker, 0, len(pool.workers))
	for _, worker := range pool.workers {
		workers = append(workers, worker)
	}
	pool.mu.Unlock()
	states := make([]PluginNativeWorkerState, 0, len(workers))
	for _, worker := range workers {
		states = append(states, worker.state())
	}
	return states
}

// PluginNativeWorkerState describes one native plugin worker process.
type PluginNativeWorkerState struct {
	Group     string    `json:"group"`
	PID       int       `json:"pid"`
	Plugins   []string  `json:"plugins"`
	StartedAt time.Time `json:"started_at"`
	RSSBytes  uint64    `json:"rss_bytes,omitempty"`
}

type pluginNativeInstanceHooks struct {
	// post receives a wake message the plugin posted from any thread.
	post func(payload []byte)
	// log receives a log line from the plugin.
	log func(level int32, message string)
}
