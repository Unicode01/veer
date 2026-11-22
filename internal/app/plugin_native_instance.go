package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// pluginNativeWorker is one veer-plugin-worker process. Its control socket
// carries LOAD and SHUTDOWN to the worker, and the hello, wake messages and
// log lines back. Every instance has a socket of its own (see
// pluginNativeInstance), so a message costs one wake-up in each direction.
type pluginNativeWorker struct {
	pool      *pluginNativeWorkerPool
	group     string
	command   *exec.Cmd
	conn      net.Conn
	startedAt time.Time

	writeMu sync.Mutex

	mu        sync.Mutex
	instances map[uint32]*pluginNativeInstance

	nextID       atomic.Uint64
	nextInstance atomic.Uint32

	done     chan struct{}
	doneOnce sync.Once
	// exited closes once the process is reaped; done can close earlier, when
	// the worker drops its socket while it is still exiting.
	exited   chan struct{}
	exitErr  atomic.Value
	stopping atomic.Bool
}

type pluginNativeWorkerHello struct {
	ABIMajor int    `json:"abi_major"`
	ABIMinor int    `json:"abi_minor"`
	Version  string `json:"version"`
	PID      int    `json:"pid"`
}

func startPluginNativeWorker(pool *pluginNativeWorkerPool, group string, deadline time.Time) (*pluginNativeWorker, error) {
	executable, err := pluginNativeWorkerExecutable()
	if err != nil {
		return nil, err
	}
	command, conn, stderr, err := spawnPluginNativeWorker(executable, pool.cfg)
	if err != nil {
		return nil, err
	}
	worker := &pluginNativeWorker{
		pool:      pool,
		group:     group,
		command:   command,
		conn:      conn,
		startedAt: time.Now(),
		instances: make(map[uint32]*pluginNativeInstance),
		done:      make(chan struct{}),
		exited:    make(chan struct{}),
	}
	if pool.cfg != nil {
		// A delegated service cgroup can only enable controllers for the
		// worker cgroups once Veer itself has moved into a leaf of its own.
		limitErr := preparePluginHostResourceLimitRoot()
		var cleanup func()
		var warning string
		if limitErr == nil {
			cleanup, warning, limitErr = attachPluginHostResourceLimits(command.Process.Pid, "worker-"+strings.ReplaceAll(group, ":", "-"), pluginHostResourceLimitsFromConfig(pool.cfg))
		}
		if limitErr != nil {
			if pool.limitWarned.CompareAndSwap(false, true) {
				log.Printf("plugin worker resource limits unavailable: %v", limitErr)
			}
		} else {
			if warning != "" {
				log.Printf("plugin worker %s resource limits partially applied: %s", group, warning)
			}
			if cleanup != nil {
				// A cgroup can only be removed once it has no processes.
				go func() {
					<-worker.exited
					cleanup()
				}()
			}
		}
	}
	hello := make(chan pluginNativeFrame, 1)
	go worker.readLoop(hello)
	go worker.stderrLoop(stderr)
	go worker.waitLoop()

	wait := time.Until(deadline)
	if wait <= 0 || wait > pluginNativeWorkerStartTimeout {
		wait = pluginNativeWorkerStartTimeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case frame := <-hello:
		var info pluginNativeWorkerHello
		if err := json.Unmarshal(frame.Payload, &info); err != nil {
			worker.stop("invalid hello")
			return nil, fmt.Errorf("plugin worker %s sent an invalid hello: %w", group, err)
		}
		if info.ABIMajor != pluginNativeABIMajor {
			worker.stop("ABI mismatch")
			return nil, fmt.Errorf("plugin worker %s speaks plugin ABI %d, host needs %d", group, info.ABIMajor, pluginNativeABIMajor)
		}
		return worker, nil
	case <-worker.done:
		return nil, worker.failure()
	case <-timer.C:
		worker.stop("start timed out")
		return nil, pluginHostProcessError(fmt.Errorf("plugin worker %s did not start in time", group))
	}
}

// pluginNativeWorkerExecutable finds veer-plugin-worker: $VEER_PLUGIN_WORKER,
// the copy built into this binary, or a file next to the veer executable.
func pluginNativeWorkerExecutable() (string, error) {
	if path := strings.TrimSpace(os.Getenv(pluginNativeWorkerEnv)); path != "" {
		return path, nil
	}
	if path, err := extractEmbeddedPluginNativeWorker(); err == nil && path != "" {
		return path, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	executable, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "veer-plugin-worker")
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("veer-plugin-worker is not available for %s", pluginNativeHostTriple())
}

func (worker *pluginNativeWorker) alive() bool {
	select {
	case <-worker.done:
		return false
	default:
		return !worker.stopping.Load()
	}
}

func (worker *pluginNativeWorker) failure() error {
	if value := worker.exitErr.Load(); value != nil {
		if err, ok := value.(error); ok {
			return err
		}
	}
	return errPluginHostProcessExited
}

func (worker *pluginNativeWorker) finish(err error) {
	worker.doneOnce.Do(func() {
		if err == nil {
			err = errPluginHostProcessExited
		}
		worker.exitErr.Store(pluginHostProcessError(err))
		close(worker.done)
		_ = worker.conn.Close()
		worker.mu.Lock()
		instances := make([]*pluginNativeInstance, 0, len(worker.instances))
		for _, instance := range worker.instances {
			instances = append(instances, instance)
		}
		worker.mu.Unlock()
		// Wake any handler still waiting on an instance socket.
		for _, instance := range instances {
			_ = instance.conn.Close()
		}
		worker.pool.forget(worker)
	})
}

// readLoop serves the control socket.
func (worker *pluginNativeWorker) readLoop(hello chan<- pluginNativeFrame) {
	reader := newPluginNativeFrameReader(worker.conn, pluginNativeMaxWorkerFrameBytes)
	for {
		frame, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				worker.finish(fmt.Errorf("plugin worker %s closed its connection", worker.group))
			} else {
				worker.finish(fmt.Errorf("read plugin worker %s: %w", worker.group, err))
			}
			_ = worker.command.Process.Kill()
			return
		}
		switch frame.Type {
		case pluginNativeFrameHello:
			select {
			case hello <- frame:
			default:
			}
		case pluginNativeFramePost:
			if instance := worker.instance(frame.Instance); instance != nil && instance.hooks.post != nil {
				payload := append([]byte(nil), frame.Payload...)
				go instance.hooks.post(payload)
			}
		case pluginNativeFrameLog:
			if instance := worker.instance(frame.Instance); instance != nil && instance.hooks.log != nil {
				instance.hooks.log(frame.Status, string(frame.Payload))
			}
		default:
			worker.finish(fmt.Errorf("plugin worker %s sent unexpected control frame type %d", worker.group, frame.Type))
			_ = worker.command.Process.Kill()
			return
		}
	}
}

func (worker *pluginNativeWorker) stderrLoop(stderr io.ReadCloser) {
	if stderr == nil {
		return
	}
	defer stderr.Close()
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	lines := 0
	for scanner.Scan() {
		if lines < 256 {
			log.Printf("plugin worker %s: %s", worker.group, boundedPluginHostError(scanner.Text()))
		}
		lines++
	}
}

func (worker *pluginNativeWorker) waitLoop() {
	err := worker.command.Wait()
	close(worker.exited)
	if err == nil {
		err = fmt.Errorf("plugin worker %s exited", worker.group)
	} else {
		err = fmt.Errorf("plugin worker %s exited: %w", worker.group, err)
	}
	worker.finish(err)
}

func (worker *pluginNativeWorker) instance(id uint32) *pluginNativeInstance {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.instances[id]
}

func (worker *pluginNativeWorker) sendControl(frame pluginNativeFrame, attach *os.File) error {
	data := encodePluginNativeFrame(frame)
	worker.writeMu.Lock()
	defer worker.writeMu.Unlock()
	select {
	case <-worker.done:
		return worker.failure()
	default:
	}
	var err error
	if attach != nil {
		err = sendPluginNativeFrameWithFile(worker.conn, data, attach)
	} else {
		_, err = worker.conn.Write(data)
	}
	if err != nil {
		worker.finish(fmt.Errorf("write plugin worker %s: %w", worker.group, err))
		return worker.failure()
	}
	return nil
}

// load creates an instance: a fresh socket pair, one end sent to the
// worker with the LOAD frame, the other kept for this instance's messages.
func (worker *pluginNativeWorker) load(plugin LoadedPlugin, hooks pluginNativeInstanceHooks, deadline time.Time) (*pluginNativeInstance, bool, error) {
	id := worker.nextInstance.Add(1)
	conn, child, err := pluginNativeSocketPair()
	if err != nil {
		return nil, false, err
	}
	defer child.Close()
	instance := &pluginNativeInstance{
		worker:   worker,
		id:       id,
		pluginID: plugin.ID,
		hooks:    hooks,
		conn:     conn,
		reader:   newPluginNativeFrameReader(conn, pluginNativeMaxWorkerFrameBytes),
	}
	// The worker serves the plugin's system-call methods itself and checks
	// them against the same declarations the host would.
	var permissions []string
	var netAccess []PluginNetAccess
	var namespaceAccess []string
	if plugin.Control != nil {
		permissions = plugin.Control.Permissions
		netAccess = plugin.Control.NetAccess
		namespaceAccess = plugin.Control.NamespaceAccess
	}
	config, err := json.Marshal(map[string]any{
		"plugin": map[string]any{
			"id":      plugin.ID,
			"name":    plugin.Name,
			"version": plugin.Version,
		},
		"root":             plugin.rootDir,
		"instance":         id,
		"library_sha256":   plugin.nativeLibrarySHA256,
		"permissions":      permissions,
		"net_access":       netAccess,
		"namespace_access": namespaceAccess,
		"worker_methods":   hooks.localMethods,
	})
	if err != nil {
		_ = conn.Close()
		return nil, false, err
	}
	worker.mu.Lock()
	worker.instances[id] = instance
	worker.mu.Unlock()
	fail := func() {
		worker.mu.Lock()
		delete(worker.instances, id)
		worker.mu.Unlock()
		_ = conn.Close()
	}
	requestID := worker.nextID.Add(1)
	if err := worker.sendControl(pluginNativeFrame{
		Type: pluginNativeFrameLoad, Instance: id, ID: requestID,
		Name: []byte(plugin.nativeLibraryPath), Payload: config,
	}, child); err != nil {
		fail()
		return nil, false, err
	}
	_ = conn.SetReadDeadline(deadline)
	frame, err := instance.reader.Read()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		fail()
		if !worker.alive() {
			return nil, false, worker.failure()
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			worker.stop("plugin load timed out")
			return nil, false, pluginHostProcessError(fmt.Errorf("loading native plugin %s timed out", plugin.ID))
		}
		return nil, false, pluginHostProcessError(fmt.Errorf("load native plugin %s: %w", plugin.ID, err))
	}
	if frame.Type != pluginNativeFrameLoaded || frame.Reference != requestID {
		fail()
		worker.stop("protocol violation")
		return nil, false, pluginHostProcessError(fmt.Errorf("plugin worker %s answered LOAD with frame type %d", worker.group, frame.Type))
	}
	if frame.Status == pluginNativeStatusOK {
		return instance, false, nil
	}
	fail()
	message := strings.TrimSpace(string(frame.Payload))
	if message == "" {
		message = fmt.Sprintf("status %d", frame.Status)
	}
	return nil, frame.Status == pluginNativeStatusShutdown, fmt.Errorf("load native plugin %s: %s", plugin.ID, boundedPluginHostError(message))
}

func (worker *pluginNativeWorker) stop(reason string) {
	if !worker.stopping.CompareAndSwap(false, true) {
		return
	}
	worker.pool.forget(worker)
	_ = worker.sendControl(pluginNativeFrame{Type: pluginNativeFrameShutdown}, nil)
	select {
	case <-worker.done:
		return
	case <-time.After(pluginNativeWorkerStopGrace):
	}
	if worker.command.Process != nil {
		_ = worker.command.Process.Kill()
	}
	worker.finish(fmt.Errorf("plugin worker %s stopped: %s", worker.group, reason))
}

func (worker *pluginNativeWorker) state() PluginNativeWorkerState {
	worker.mu.Lock()
	plugins := make([]string, 0, len(worker.instances))
	for _, instance := range worker.instances {
		plugins = append(plugins, instance.pluginID)
	}
	worker.mu.Unlock()
	state := PluginNativeWorkerState{Group: worker.group, Plugins: plugins, StartedAt: worker.startedAt}
	if worker.command.Process != nil {
		state.PID = worker.command.Process.Pid
		if rss, err := pluginHostProcessRSS(state.PID); err == nil {
			state.RSSBytes = rss
		}
	}
	return state
}

// pluginNativeInstance is one plugin loaded in a worker. Its socket carries
// only this instance's messages, and only the owning plugin VM uses it.
type pluginNativeInstance struct {
	worker   *pluginNativeWorker
	id       uint32
	pluginID string
	hooks    pluginNativeInstanceHooks
	conn     net.Conn
	reader   *pluginNativeFrameReader
	nextID   uint64
	closed   atomic.Bool
}

// pluginNativeCallHandler serves one host API call from the plugin and
// returns a status and a payload: JSON on success, an error message
// otherwise.
type pluginNativeCallHandler func(method string, arguments []byte) (int32, []byte)

func (instance *pluginNativeInstance) write(frame pluginNativeFrame) error {
	data := encodePluginNativeFrame(frame)
	if len(data)-4 > pluginNativeMaxHostFrameBytes {
		return fmt.Errorf("plugin message of %d bytes exceeds %d", len(data)-4, pluginNativeMaxHostFrameBytes)
	}
	if _, err := instance.conn.Write(data); err != nil {
		return instance.connectionError(err)
	}
	return nil
}

func (instance *pluginNativeInstance) connectionError(err error) error {
	if !instance.worker.alive() {
		return instance.worker.failure()
	}
	return pluginHostProcessError(fmt.Errorf("native plugin %s connection: %w", instance.pluginID, err))
}

// exchange delivers one message and serves the plugin's host calls until
// its result arrives.
func (instance *pluginNativeInstance) exchange(kind uint32, handler string, payload []byte, calls pluginNativeCallHandler, deadline time.Time) (int32, []byte, error) {
	if instance.closed.Load() {
		return 0, nil, pluginHostProcessError(fmt.Errorf("native plugin %s instance is closed", instance.pluginID))
	}
	instance.nextID++
	requestID := instance.nextID
	// The worker bounds its own waits (raw frames, sockets) by the handler's
	// deadline, which a MSG carries in its reference.
	var deadlineMillis uint64
	if !deadline.IsZero() {
		deadlineMillis = uint64(deadline.UnixMilli())
	}
	if err := instance.write(pluginNativeFrame{
		Type: pluginNativeFrameMsg, Instance: instance.id, ID: requestID, Reference: deadlineMillis,
		Status: int32(kind), Name: []byte(handler), Payload: payload,
	}); err != nil {
		instance.noteWorkerFailure("its worker failed while it was handling " + handler)
		return 0, nil, err
	}
	_ = instance.conn.SetReadDeadline(deadline)
	defer instance.conn.SetReadDeadline(time.Time{})
	served := 0
	for {
		frame, err := instance.reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				instance.noteWorkerFailure("its " + handler + " handler timed out")
				instance.worker.stop("plugin handler timed out")
				return 0, nil, pluginHostProcessError(fmt.Errorf("native plugin %s handler %s timed out", instance.pluginID, handler))
			}
			instance.noteWorkerFailure("its worker exited while it was handling " + handler)
			return 0, nil, instance.connectionError(err)
		}
		switch frame.Type {
		case pluginNativeFrameResult:
			if frame.Reference == requestID {
				return frame.Status, frame.Payload, nil
			}
		case pluginNativeFrameCall:
			if frame.Reference != requestID {
				if err := instance.write(pluginNativeFrame{
					Type: pluginNativeFrameCallReply, Instance: instance.id, Reference: frame.ID,
					Status: pluginNativeStatusPerm, Payload: []byte("host call does not belong to the running handler"),
				}); err != nil {
					return 0, nil, err
				}
				continue
			}
			served++
			if served > pluginNativeMaxCallsPerEvent {
				instance.noteWorkerFailure("it exceeded the host call limit")
				instance.worker.stop("plugin exceeded the host call limit")
				return 0, nil, pluginHostProcessError(fmt.Errorf("native plugin %s exceeded %d host calls in one handler", instance.pluginID, pluginNativeMaxCallsPerEvent))
			}
			status, reply := calls(string(frame.Name), frame.Payload)
			if err := instance.write(pluginNativeFrame{
				Type: pluginNativeFrameCallReply, Instance: instance.id, Reference: frame.ID,
				Status: status, Payload: reply,
			}); err != nil {
				instance.noteWorkerFailure("its worker failed while it was handling " + handler)
				return 0, nil, err
			}
		default:
			instance.worker.stop("protocol violation")
			return 0, nil, pluginHostProcessError(fmt.Errorf("native plugin %s sent unexpected frame type %d", instance.pluginID, frame.Type))
		}
	}
}

// noteWorkerFailure demotes the plugin when it took a shared worker down.
func (instance *pluginNativeInstance) noteWorkerFailure(reason string) {
	if !strings.HasPrefix(instance.worker.group, "dedicated:") {
		instance.worker.pool.demote(instance.pluginID, reason)
	}
}

func (instance *pluginNativeInstance) unload(deadline time.Time) {
	if !instance.closed.CompareAndSwap(false, true) {
		return
	}
	worker := instance.worker
	defer func() {
		worker.mu.Lock()
		delete(worker.instances, instance.id)
		worker.mu.Unlock()
		_ = instance.conn.Close()
	}()
	if !worker.alive() {
		return
	}
	instance.nextID++
	requestID := instance.nextID
	if err := instance.write(pluginNativeFrame{Type: pluginNativeFrameUnload, Instance: instance.id, ID: requestID}); err != nil {
		return
	}
	_ = instance.conn.SetReadDeadline(deadline)
	for {
		frame, err := instance.reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				worker.stop("plugin unload timed out")
			}
			return
		}
		if frame.Type == pluginNativeFrameUnloaded {
			return
		}
	}
}
