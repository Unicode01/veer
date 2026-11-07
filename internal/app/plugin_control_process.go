package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

const pluginProcessConfigLimit = 1 << 20

var pluginProcessIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Managed processes belong to a plugin control generation, not an action's
// deadline. They never inherit the privileged service environment or a shell.
type pluginProcessRequest struct {
	ID            string   `json:"id"`
	Command       string   `json:"command"`
	Args          []string `json:"args"`
	Stdin         string   `json:"stdin"`
	Config        string   `json:"config"`
	Restart       string   `json:"restart"`
	MaxRestarts   int      `json:"max_restarts"`
	StopTimeoutMS int      `json:"stop_timeout_ms"`
}

type pluginProcessStatus struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	PID       int    `json:"pid"`
	Starts    int    `json:"starts"`
	ExitCode  int    `json:"exit_code"`
	StartedAt int64  `json:"started_at"`
}

func (status pluginProcessStatus) value() map[string]any {
	return map[string]any{"id": status.ID, "state": status.State, "pid": status.PID, "starts": status.Starts,
		"exit_code": status.ExitCode, "started_at": status.StartedAt}
}

type pluginProcessRegistry struct {
	mu       sync.Mutex
	closed   bool
	entries  map[string]*pluginManagedProcess
	cfg      *Config
	binaries *pluginBinaryStore
}

type pluginManagedProcess struct {
	mu          sync.Mutex
	status      pluginProcessStatus
	fingerprint [32]byte
	generation  string
	command     string
	stop        chan struct{}
	done        chan struct{}
	stopOnce    sync.Once
	restart     chan struct{}
	maxRestarts int
	stdout      pluginProcessLog
	stderr      pluginProcessLog
	limitOwner  string
	limitConfig *Config
}

type pluginProcessLog struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (log *pluginProcessLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	n := len(data)
	const limit = pluginExecMaxOutputBytes
	if len(data) >= limit {
		log.data = append(log.data[:0], data[len(data)-limit:]...)
		log.truncated = true
	} else {
		if excess := len(log.data) + len(data) - limit; excess > 0 {
			copy(log.data, log.data[excess:])
			log.data = log.data[:len(log.data)-excess]
			log.truncated = true
		}
		log.data = append(log.data, data...)
	}
	return n, nil
}

func (log *pluginProcessLog) snapshot() (string, bool) {
	log.mu.Lock()
	defer log.mu.Unlock()
	return strings.ToValidUTF8(string(log.data), "�"), log.truncated
}

func validatePluginProcessRequest(req *pluginProcessRequest) error {
	if !pluginProcessIDPattern.MatchString(req.ID) {
		return fmt.Errorf("invalid process id")
	}
	if _, err := validatePluginExecRequest(pluginExecRequest{Command: req.Command, Args: req.Args, Stdin: req.Stdin}); err != nil {
		return err
	}
	if len(req.Config) > pluginProcessConfigLimit {
		return fmt.Errorf("config exceeds %d bytes", pluginProcessConfigLimit)
	}
	if req.Restart == "" {
		req.Restart = "never"
	}
	if req.Restart != "never" && req.Restart != "on-failure" {
		return fmt.Errorf("restart must be never or on-failure")
	}
	if req.MaxRestarts < 0 || req.MaxRestarts > 10 {
		return fmt.Errorf("max_restarts must be between 0 and 10")
	}
	if req.StopTimeoutMS == 0 {
		req.StopTimeoutMS = 1000
	}
	if req.StopTimeoutMS < 1 || req.StopTimeoutMS > 3000 {
		return fmt.Errorf("stop_timeout_ms must be between 1 and 3000")
	}
	for _, arg := range req.Args {
		if strings.Contains(arg, "{config}") && req.Config == "" {
			return fmt.Errorf("{config} requires nonempty config")
		}
	}
	return nil
}

func (h *pluginControlHost) managedProcessRegistry(api string) *pluginProcessRegistry {
	h.requirePermission("exec")
	if !h.cfg.PluginExecEnabled() {
		h.throwf("%s is disabled while remote plugin installation is enabled", api)
	}
	if runtime.GOOS != "linux" {
		h.throwf("%s requires Linux", api)
	}
	if h.workerVM || h.runtime == nil {
		h.throwf("%s requires a main plugin runtime", api)
	}
	if !h.executionDeadline.IsZero() && !time.Now().Before(h.executionDeadline) {
		h.throwf("%s: plugin execution deadline exceeded", api)
	}
	return h.runtime.processRegistry
}

func (h *pluginControlHost) processStart(call goja.FunctionCall) goja.Value {
	const api = "process.start"
	registry := h.managedProcessRegistry(api)
	data, err := json.Marshal(h.requiredObjectArg(call, 0, "request").Export())
	if err != nil || len(data) > 2*pluginProcessConfigLimit {
		h.throwf("%s: request is too large or invalid", api)
	}
	var req pluginProcessRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.throwf("%s: invalid request", api)
	}
	if err := validatePluginProcessRequest(&req); err != nil {
		h.throwf("%s: %v", api, err)
	}
	status, err := registry.Start(h.plugin.ID, h.controlGeneration, req, h.executionStop)
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	recordPluginAudit(h.db, h.plugin.ID, api, "control", outcome, map[string]any{"id": req.ID, "command": req.Command})
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(status.value())
}

func (h *pluginControlHost) processStatus(call goja.FunctionCall) goja.Value {
	r := h.managedProcessRegistry("process.status")
	id := h.processIDArg(call)
	p := r.get(h.plugin.ID, id)
	if p == nil {
		return h.vm.ToValue((pluginProcessStatus{ID: id, State: "stopped", ExitCode: -1}).value())
	}
	return h.vm.ToValue(p.snapshot().value())
}

func (h *pluginControlHost) processList(call goja.FunctionCall) goja.Value {
	r := h.managedProcessRegistry("process.list")
	r.mu.Lock()
	items := make([]pluginProcessStatus, 0)
	for key, p := range r.entries {
		if strings.HasPrefix(key, h.plugin.ID+"/") {
			items = append(items, p.snapshot())
		}
	}
	r.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	values := make([]map[string]any, 0, len(items))
	for _, item := range items {
		values = append(values, item.value())
	}
	return h.vm.ToValue(values)
}

func (h *pluginControlHost) processLogs(call goja.FunctionCall) goja.Value {
	r := h.managedProcessRegistry("process.logs")
	p := r.get(h.plugin.ID, h.processIDArg(call))
	if p == nil {
		h.throwf("process.logs: process not found")
	}
	stdout, outTruncated := p.stdout.snapshot()
	stderr, errTruncated := p.stderr.snapshot()
	return h.vm.ToValue(map[string]any{"stdout": stdout, "stderr": stderr, "truncated": outTruncated || errTruncated})
}

func (h *pluginControlHost) processStop(call goja.FunctionCall) goja.Value {
	r := h.managedProcessRegistry("process.stop")
	id := h.processIDArg(call)
	status := r.Stop(h.plugin.ID, id)
	recordPluginAudit(h.db, h.plugin.ID, "process.stop", "control", "success", map[string]any{"id": id})
	return h.vm.ToValue(status.value())
}

func (h *pluginControlHost) processRestart(call goja.FunctionCall) goja.Value {
	r := h.managedProcessRegistry("process.restart")
	id := h.processIDArg(call)
	p := r.get(h.plugin.ID, id)
	if p == nil {
		h.throwf("process.restart: process not found")
	}
	status, err := p.requestRestart()
	if err != nil {
		h.throwf("process.restart: %v", err)
	}
	recordPluginAudit(h.db, h.plugin.ID, "process.restart", "control", "success", map[string]any{"id": id})
	return h.vm.ToValue(status.value())
}

// Explicit health recovery uses the same lifetime budget as failed exits.
// Repeated reconciliation cannot turn a broken dependency into a restart loop.
func (p *pluginManagedProcess) requestRestart() (pluginProcessStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status.State == "restarting" || p.status.State == "backoff" {
		return p.status, nil
	}
	if p.status.Starts > p.maxRestarts {
		return p.status, fmt.Errorf("restart budget exhausted")
	}
	if p.status.State != "running" {
		return p.status, fmt.Errorf("process is not running")
	}
	p.status.State = "restarting"
	p.restart <- struct{}{}
	return p.status, nil
}

func (r *pluginProcessRegistry) get(owner, id string) *pluginManagedProcess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[owner+"/"+id]
}

func (h *pluginControlHost) processIDArg(call goja.FunctionCall) string {
	id, ok := call.Argument(0).Export().(string)
	if !ok || !pluginProcessIDPattern.MatchString(id) {
		h.throwf("invalid process id")
	}
	return id
}

func (p *pluginManagedProcess) snapshot() pluginProcessStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

func (p *pluginManagedProcess) close() { p.stopOnce.Do(func() { close(p.stop) }) }

func (r *pluginProcessRegistry) Start(owner, generation string, req pluginProcessRequest, ownerStop <-chan struct{}) (pluginProcessStatus, error) {
	if err := validatePluginProcessRequest(&req); err != nil {
		return pluginProcessStatus{}, err
	}
	encoded, _ := json.Marshal(req)
	fingerprint := sha256.Sum256(encoded)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return pluginProcessStatus{}, fmt.Errorf("process registry is closed")
	}
	select {
	case <-ownerStop:
		return pluginProcessStatus{}, fmt.Errorf("plugin has stopped")
	default:
	}
	key, count := owner+"/"+req.ID, 0
	if old := r.entries[key]; old != nil {
		if old.generation != generation || old.fingerprint != fingerprint {
			return pluginProcessStatus{}, fmt.Errorf("process id is already owned by another specification or generation; stop it first")
		}
		return old.snapshot(), nil
	}
	for name := range r.entries {
		if strings.HasPrefix(name, owner+"/") {
			count++
		}
	}
	if count >= 8 || len(r.entries) >= 32 {
		return pluginProcessStatus{}, fmt.Errorf("managed process limit reached")
	}
	dir, err := newPluginManagedProcessDirectory()
	if err != nil {
		return pluginProcessStatus{}, fmt.Errorf("create private process directory: %w", err)
	}
	if req.Config != "" {
		if err := os.WriteFile(filepath.Join(dir, "config"), []byte(req.Config), 0600); err != nil {
			_ = os.RemoveAll(dir)
			return pluginProcessStatus{}, fmt.Errorf("write private process configuration: %w", err)
		}
	}
	limitIdentity := sha256.Sum256([]byte(key))
	p := &pluginManagedProcess{
		generation: generation, fingerprint: fingerprint, command: req.Command,
		stop: make(chan struct{}), done: make(chan struct{}), restart: make(chan struct{}, 1),
		maxRestarts: req.MaxRestarts,
		status:      pluginProcessStatus{ID: req.ID, State: "starting", ExitCode: -1},
		limitOwner:  fmt.Sprintf("managed-%x", limitIdentity[:24]), limitConfig: r.cfg,
	}
	cmd, cleanup, err := p.launch(req, dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return p.snapshot(), err
	}
	if r.entries == nil {
		r.entries = make(map[string]*pluginManagedProcess)
	}
	r.entries[key] = p
	go p.supervise(req, dir, cmd, cleanup, ownerStop)
	return p.snapshot(), nil
}

func (p *pluginManagedProcess) launch(req pluginProcessRequest, dir string) (*exec.Cmd, func(), error) {
	args := append([]string(nil), req.Args...)
	for i := range args {
		args[i] = strings.ReplaceAll(args[i], "{config}", filepath.Join(dir, "config"))
	}
	cmd := exec.Command(req.Command, args...) // #nosec G204 -- trusted local exec permission.
	cmd.Env, cmd.Dir, cmd.Stdin = pluginExecEnvironment(), dir, strings.NewReader(req.Stdin)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = &p.stdout, &p.stderr, 100*time.Millisecond
	cleanup := configurePluginExecCommand(cmd)
	cmd.Cancel = nil // The supervisor owns cancellation, rather than CommandContext.
	preparePluginManagedProcess(cmd)
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("start executable: %w", err)
	}
	limitCleanup, err := limitPluginManagedProcess(cmd, p.limitOwner, p.limitConfig)
	if err != nil {
		cleanup()
		_ = cmd.Wait()
		return nil, nil, err
	}
	processCleanup := cleanup
	cleanup = func() { processCleanup(); limitCleanup() }
	p.mu.Lock()
	p.status.State, p.status.PID, p.status.ExitCode = "running", cmd.Process.Pid, -1
	p.status.Starts++
	p.status.StartedAt = time.Now().UnixMilli()
	p.mu.Unlock()
	return cmd, cleanup, nil
}

func (p *pluginManagedProcess) supervise(req pluginProcessRequest, dir string, cmd *exec.Cmd, cleanup func(), ownerStop <-chan struct{}) {
	defer close(p.done)
	defer os.RemoveAll(dir)
	for {
		wait := make(chan error, 1)
		go func() { wait <- cmd.Wait() }()
		stopping, requested := false, false
		select {
		case <-wait:
		case <-p.restart:
			requested = true
		case <-p.stop:
			stopping = true
		case <-ownerStop:
			stopping = true
		}
		if stopping || requested {
			p.mu.Lock()
			p.status.State = "restarting"
			if stopping {
				p.status.State = "stopping"
			}
			p.mu.Unlock()
			terminatePluginManagedProcess(cmd)
			timer := time.NewTimer(time.Duration(req.StopTimeoutMS) * time.Millisecond)
			select {
			case <-wait:
			case <-timer.C:
				cleanup()
				<-wait
			}
			timer.Stop()
		}
		cleanup() // Reap descendants even if the leader exited on its own.
		p.mu.Lock()
		// A health request may race the leader's natural exit. Consume it here
		// before publishing the next state, never in a later generation.
		select {
		case <-p.restart:
			requested = true
		default:
		}
		p.status.PID = 0
		p.status.ExitCode = cmd.ProcessState.ExitCode()
		p.status.State = "exited"
		if stopping {
			p.status.State = "stopped"
		}
		restart := !stopping && (requested || (req.Restart == "on-failure" && p.status.ExitCode != 0)) && p.status.Starts <= req.MaxRestarts
		if restart {
			p.status.State = "backoff"
		}
		starts := p.status.Starts
		p.mu.Unlock()
		if !restart {
			return
		}
		delay := time.Second << min(starts-1, 4)
		timer := time.NewTimer(delay)
		select {
		case <-p.stop:
			timer.Stop()
			p.mu.Lock()
			p.status.State = "stopped"
			p.mu.Unlock()
			return
		case <-ownerStop:
			timer.Stop()
			p.mu.Lock()
			p.status.State = "stopped"
			p.mu.Unlock()
			return
		case <-timer.C:
		}
		var err error
		cmd, cleanup, err = p.launch(req, dir)
		if err != nil {
			p.mu.Lock()
			p.status.State = "failed"
			p.mu.Unlock()
			return
		}
	}
}

func (r *pluginProcessRegistry) Stop(owner, id string) pluginProcessStatus {
	p := r.get(owner, id)
	if p == nil {
		return pluginProcessStatus{ID: id, State: "stopped", ExitCode: -1}
	}
	p.close()
	<-p.done
	r.mu.Lock()
	if r.entries[owner+"/"+id] == p {
		delete(r.entries, owner+"/"+id)
	}
	r.mu.Unlock()
	return p.snapshot()
}

func (r *pluginProcessRegistry) ClosePlugin(owner string) {
	r.mu.Lock()
	binaries := r.binaries
	var ids []string
	for key, p := range r.entries {
		if strings.HasPrefix(key, owner+"/") {
			ids = append(ids, p.snapshot().ID)
			p.close()
		}
	}
	r.mu.Unlock()
	if binaries != nil {
		binaries.cancelOwner(owner, false)
	}
	for _, id := range ids {
		r.Stop(owner, id)
	}
}

func (r *pluginProcessRegistry) CloseAll() {
	r.mu.Lock()
	r.closed = true
	binaries := r.binaries
	entries := make([]*pluginManagedProcess, 0, len(r.entries))
	for _, p := range r.entries {
		entries = append(entries, p)
		p.close()
	}
	r.mu.Unlock()
	if binaries != nil {
		binaries.cancelOwner("", true)
	}
	for _, p := range entries {
		<-p.done
	}
	r.mu.Lock()
	r.entries = nil
	r.mu.Unlock()
}

func (r *pluginProcessRegistry) binaryInUse(path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, process := range r.entries {
		if process.command == path {
			return true
		}
	}
	return false
}
