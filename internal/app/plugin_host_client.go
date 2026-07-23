package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errPluginHostProcessExited = errors.New("isolated plugin host exited")

const (
	pluginHostFilesystemRootEnv = "VEER_PLUGIN_HOST_FILESYSTEM_ROOT"
	pluginHostMessageQueueSize  = 0
)

type pluginHostCallBroker interface {
	callPluginHostMethod(method string, arguments []any) (value any, undefined bool, err error)
}

type pluginHostClient struct {
	pluginID    string
	mode        string
	worker      string
	command     *exec.Cmd
	stdin       io.WriteCloser
	messages    chan pluginHostMessage
	errors      chan error
	done        chan struct{}
	writeMu     sync.Mutex
	closeOnce   sync.Once
	doneOnce    sync.Once
	cleanupOnce sync.Once
	nextID      atomic.Uint64
	closing     atomic.Bool
	cleanup     func()
	budgetMu    sync.Mutex
	callBudget  *int

	lastRSS       atomic.Uint64
	resourceError atomic.Value
	sandboxState  atomic.Value
	rssLimit      uint64
}

func startPluginHostClient(cfg *Config, plugin LoadedPlugin, mode, workerName, source string, broker pluginHostCallBroker) (*pluginHostClient, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve plugin host executable: %w", err)
	}
	arguments := []string{"--plugin-host"}
	environment := minimalPluginHostEnvironment(false)
	if cfg != nil && cfg.pluginHostTestMode {
		arguments = []string{"-test.run=^TestPluginHostProcessEntrypoint$"}
		environment = minimalPluginHostEnvironment(true)
	}
	command := exec.Command(executable, arguments...)
	command.Env = environment
	if err := configurePluginHostCommand(command); err != nil {
		return nil, err
	}
	if err := preparePluginHostResourceLimitRoot(); err != nil && cfg.PluginMinimumSandboxLevel() == pluginSandboxLevelFull {
		return nil, fmt.Errorf("plugin host hard resource limits are required: %w", err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open plugin host stdin: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open plugin host stdout: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("open plugin host stderr: %w", err)
	}
	filesystemRoot, filesystemCleanup, err := preparePluginHostFilesystemRoot()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("prepare plugin host filesystem root: %w", err)
	}
	if filesystemRoot != "" {
		command.Env = append(command.Env, pluginHostFilesystemRootEnv+"="+filesystemRoot)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		filesystemCleanup()
		return nil, fmt.Errorf("start isolated plugin host: %w", err)
	}
	client := &pluginHostClient{
		pluginID: plugin.ID,
		mode:     mode,
		worker:   workerName,
		command:  command,
		stdin:    stdin,
		messages: make(chan pluginHostMessage, pluginHostMessageQueueSize),
		errors:   make(chan error, 4),
		done:     make(chan struct{}),
		cleanup:  filesystemCleanup,
		rssLimit: pluginHostResourceLimitsFromConfig(cfg).ProcessRSSBytes,
	}
	if cleanup, limitWarning, limitErr := attachPluginHostResourceLimits(command.Process.Pid, plugin.ID, pluginHostResourceLimitsFromConfig(cfg)); limitErr != nil {
		if cfg.PluginMinimumSandboxLevel() == pluginSandboxLevelFull {
			_ = stdin.Close()
			_ = stdout.Close()
			_ = stderr.Close()
			_ = command.Process.Kill()
			_ = command.Wait()
			client.cleanupOnce.Do(client.cleanup)
			return nil, fmt.Errorf("plugin host hard resource limits are required: %w", limitErr)
		}
		client.resourceError.Store(limitErr.Error())
		log.Printf("plugin host %s resource limits degraded: %v", plugin.ID, limitErr)
	} else if cleanup != nil {
		client.cleanup = combinePluginHostCleanup(client.cleanup, cleanup)
		if limitWarning != "" {
			client.resourceError.Store(limitWarning)
			log.Printf("plugin host %s resource limits partially degraded: %s", plugin.ID, limitWarning)
		}
	}
	go client.readLoop(stdout)
	go client.stderrLoop(stderr)
	go client.waitLoop()
	go client.monitorResources()

	mainModuleID, err := pluginControlMainModuleID(plugin)
	if err != nil {
		client.Close()
		return nil, err
	}
	request := pluginHostInitRequest{
		ProtocolVersion:     pluginHostProtocolVersion,
		Source:              source,
		Filename:            plugin.Control.Main,
		MainModuleID:        mainModuleID,
		MaxCallStack:        pluginControlMaxCallStackDepth,
		TimeoutMS:           pluginControlTimeout.Milliseconds(),
		MinimumSandboxLevel: cfg.PluginMinimumSandboxLevel(),
	}
	payload, err := marshalPluginHostPayload(request)
	if err != nil {
		client.Close()
		return nil, err
	}
	deadline := time.Now().Add(pluginControlExecutionLockTimeout)
	response, err := client.exchange(pluginHostMessage{Type: pluginHostMessageTypeInit, Payload: payload}, broker, deadline, new(int))
	if err != nil {
		client.Close()
		return nil, err
	}
	if response.Type != pluginHostMessageTypeInitReply || !response.OK {
		client.Close()
		if response.Error == "" {
			response.Error = "plugin host initialization failed"
		}
		return nil, errors.New(response.Error)
	}
	var initResponse pluginHostInitResponse
	if err := decodePluginHostPayload(response.Payload, &initResponse); err != nil {
		client.Close()
		return nil, fmt.Errorf("decode plugin host sandbox handshake: %w", err)
	}
	if strings.TrimSpace(initResponse.Sandbox.Platform) == "" || strings.TrimSpace(initResponse.Sandbox.Level) == "" {
		client.Close()
		return nil, fmt.Errorf("plugin host sandbox handshake is incomplete")
	}
	client.sandboxState.Store(initResponse.Sandbox)
	return client, nil
}

func combinePluginHostCleanup(first, second func()) func() {
	return func() {
		if second != nil {
			second()
		}
		if first != nil {
			first()
		}
	}
}

func (client *pluginHostClient) SandboxState() PluginHostSandboxState {
	if client == nil {
		return PluginHostSandboxState{}
	}
	value := client.sandboxState.Load()
	if value == nil {
		return PluginHostSandboxState{}
	}
	state, _ := value.(PluginHostSandboxState)
	state.Degraded = append([]string(nil), state.Degraded...)
	return state
}

func minimalPluginHostEnvironment(testMode bool) []string {
	values := []string{
		"GOMAXPROCS=1",
		"GOMEMLIMIT=192MiB",
		"VEER_PLUGIN_HOST=1",
	}
	if testMode {
		values = append(values, "VEER_PLUGIN_HOST_TEST=1")
	}
	for _, name := range []string{"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL", "TZ"} {
		if value := os.Getenv(name); value != "" {
			values = append(values, name+"="+value)
		}
	}
	return values
}

func (client *pluginHostClient) readLoop(stdout io.ReadCloser) {
	defer stdout.Close()
	reader := newPluginHostFrameReader(stdout, pluginHostMaxChildFrameBytes)
	for {
		message, err := reader.Read()
		if err != nil {
			client.reportError(pluginHostProcessError(fmt.Errorf("read plugin host response: %w", err)))
			return
		}
		select {
		case client.messages <- message:
		case <-client.done:
			return
		}
	}
}

func (client *pluginHostClient) stderrLoop(stderr io.ReadCloser) {
	defer stderr.Close()
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	lines := 0
	for scanner.Scan() {
		if lines < 64 {
			log.Printf("plugin host %s/%s stderr: %s", client.pluginID, client.workerLabel(), boundedPluginHostError(scanner.Text()))
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		if !client.closing.Load() {
			log.Printf("plugin host %s/%s stderr reader failed: %v", client.pluginID, client.workerLabel(), err)
		}
	}
}

func (client *pluginHostClient) waitLoop() {
	err := client.command.Wait()
	if err == nil {
		err = errPluginHostProcessExited
	} else {
		err = fmt.Errorf("%w: %v", errPluginHostProcessExited, err)
	}
	client.reportError(err)
	client.doneOnce.Do(func() { close(client.done) })
	client.cleanupOnce.Do(client.cleanup)
}

func pluginHostProcessError(err error) error {
	if err == nil {
		return errPluginHostProcessExited
	}
	if errors.Is(err, errPluginHostProcessExited) {
		return err
	}
	return fmt.Errorf("%w: %v", errPluginHostProcessExited, err)
}

func (client *pluginHostClient) reportError(err error) {
	if err == nil {
		return
	}
	select {
	case client.errors <- err:
	default:
	}
}

func (client *pluginHostClient) workerLabel() string {
	if client.worker != "" {
		return client.worker
	}
	if client.mode != "" {
		return client.mode
	}
	return "control"
}

func (client *pluginHostClient) monitorResources() {
	limit := client.rssLimit
	if limit == 0 || client.command == nil || client.command.Process == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-client.done:
			return
		case <-ticker.C:
			rss, err := pluginHostProcessRSS(client.command.Process.Pid)
			if err != nil {
				continue
			}
			client.lastRSS.Store(rss)
			if rss <= limit {
				continue
			}
			reason := fmt.Sprintf("plugin host RSS %d exceeds limit %d", rss, limit)
			client.resourceError.Store(reason)
			client.reportError(pluginHostProcessError(errors.New(reason)))
			_ = client.command.Process.Kill()
			return
		}
	}
}

func (client *pluginHostClient) runEvent(request pluginHostEventRequest, broker pluginHostCallBroker, deadline time.Time, nested bool) (pluginHostEventResponse, error) {
	payload, err := marshalPluginHostPayload(request)
	if err != nil {
		return pluginHostEventResponse{}, err
	}
	messageType := pluginHostMessageTypeEvent
	if nested {
		messageType = pluginHostMessageTypeNested
	}
	calls, release, err := client.acquireEventCallBudget(nested)
	if err != nil {
		return pluginHostEventResponse{}, client.failProtocol(err)
	}
	defer release()
	response, err := client.exchange(pluginHostMessage{Type: messageType, Payload: payload}, broker, deadline, calls)
	if err != nil {
		return pluginHostEventResponse{}, err
	}
	if response.Type != pluginHostMessageTypeResult {
		return pluginHostEventResponse{}, client.failProtocol(fmt.Errorf("unexpected plugin host event response %q", response.Type))
	}
	if !response.OK {
		return pluginHostEventResponse{}, errors.New(boundedPluginHostError(response.Error))
	}
	var result pluginHostEventResponse
	if err := decodePluginHostPayload(response.Payload, &result); err != nil {
		return pluginHostEventResponse{}, client.failProtocol(fmt.Errorf("decode plugin host event result: %w", err))
	}
	return result, nil
}

func (client *pluginHostClient) acquireEventCallBudget(nested bool) (*int, func(), error) {
	client.budgetMu.Lock()
	defer client.budgetMu.Unlock()
	if nested {
		if client.callBudget == nil {
			return nil, func() {}, fmt.Errorf("nested plugin event has no active call budget")
		}
		return client.callBudget, func() {}, nil
	}
	if client.callBudget != nil {
		return nil, func() {}, fmt.Errorf("concurrent plugin host events are not allowed")
	}
	calls := new(int)
	client.callBudget = calls
	return calls, func() {
		client.budgetMu.Lock()
		if client.callBudget == calls {
			client.callBudget = nil
		}
		client.budgetMu.Unlock()
	}, nil
}

func (client *pluginHostClient) exchange(message pluginHostMessage, broker pluginHostCallBroker, deadline time.Time, calls *int) (pluginHostMessage, error) {
	if client == nil {
		return pluginHostMessage{}, errPluginRuntimeTargetNotLoaded
	}
	if !deadline.After(time.Now()) {
		return pluginHostMessage{}, fmt.Errorf("plugin host request deadline exceeded")
	}
	message.ID = client.nextID.Add(1)
	if err := client.send(message); err != nil {
		return pluginHostMessage{}, err
	}
	for {
		timer := time.NewTimer(max(time.Until(deadline), time.Millisecond))
		select {
		case response := <-client.messages:
			timer.Stop()
			if response.Type == pluginHostMessageTypeHostCall {
				if response.ReplyTo != message.ID {
					return pluginHostMessage{}, client.failProtocol(fmt.Errorf("plugin host call belongs to request %d, want %d", response.ReplyTo, message.ID))
				}
				(*calls)++
				if *calls > pluginHostMaxCallsPerEvent {
					return pluginHostMessage{}, client.failProtocol(fmt.Errorf("plugin host call limit exceeded: %d", pluginHostMaxCallsPerEvent))
				}
				if err := client.handleHostCall(response, broker); err != nil {
					return pluginHostMessage{}, err
				}
				continue
			}
			if response.ReplyTo != message.ID {
				return pluginHostMessage{}, client.failProtocol(fmt.Errorf("plugin host response belongs to request %d, want %d", response.ReplyTo, message.ID))
			}
			return response, nil
		case err := <-client.errors:
			timer.Stop()
			return pluginHostMessage{}, err
		case <-client.done:
			timer.Stop()
			return pluginHostMessage{}, errPluginHostProcessExited
		case <-timer.C:
			client.Interrupt("plugin host request timed out")
			if client.command != nil && client.command.Process != nil {
				_ = client.command.Process.Kill()
			}
			return pluginHostMessage{}, pluginHostProcessError(fmt.Errorf("plugin host request timed out"))
		}
	}
}

func (client *pluginHostClient) handleHostCall(message pluginHostMessage, broker pluginHostCallBroker) error {
	if message.ID == 0 || message.Method == "" {
		return client.failProtocol(fmt.Errorf("invalid plugin host call identity"))
	}
	if !pluginHostMethodAllowed(message.Method) {
		return client.failProtocol(fmt.Errorf("plugin host requested unknown method %q", message.Method))
	}
	var request pluginHostCallRequest
	if err := decodePluginHostPayload(message.Payload, &request); err != nil {
		return client.failProtocol(err)
	}
	if err := validatePluginHostJSONValue(request.Arguments, 0); err != nil {
		return client.failProtocol(err)
	}
	if broker == nil {
		return client.sendHostError(message.ID, fmt.Errorf("plugin host capability broker is unavailable"))
	}
	value, undefined, callErr := broker.callPluginHostMethod(message.Method, request.Arguments)
	if callErr != nil {
		return client.sendHostError(message.ID, callErr)
	}
	response := pluginHostMessage{Type: pluginHostMessageTypeHostReply, ReplyTo: message.ID, OK: true, Undefined: undefined}
	if !undefined {
		raw, err := json.Marshal(value)
		if err != nil {
			return client.sendHostError(message.ID, fmt.Errorf("encode %s result: %w", message.Method, err))
		}
		payload, err := marshalPluginHostPayload(pluginHostCallResponse{Value: raw})
		if err != nil {
			return client.sendHostError(message.ID, err)
		}
		response.Payload = payload
	}
	return client.send(response)
}

func (client *pluginHostClient) sendHostError(replyTo uint64, err error) error {
	return client.send(pluginHostMessage{
		Type: pluginHostMessageTypeHostReply, ReplyTo: replyTo, OK: false, Error: boundedPluginHostError(err.Error()),
	})
}

func (client *pluginHostClient) send(message pluginHostMessage) error {
	if client.closing.Load() {
		return errPluginHostProcessExited
	}
	select {
	case <-client.done:
		return errPluginHostProcessExited
	default:
	}
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if err := writePluginHostFrame(client.stdin, message, pluginHostMaxParentFrameBytes); err != nil {
		return pluginHostProcessError(fmt.Errorf("write plugin host request: %w", err))
	}
	return nil
}

func (client *pluginHostClient) failProtocol(err error) error {
	fatalErr := pluginHostProcessError(fmt.Errorf("plugin host protocol violation: %w", err))
	client.reportError(fatalErr)
	if client.command != nil && client.command.Process != nil {
		_ = client.command.Process.Kill()
	}
	return fatalErr
}

func (client *pluginHostClient) Interrupt(reason string) {
	if client == nil {
		return
	}
	_ = client.send(pluginHostMessage{Type: pluginHostMessageTypeInterrupt, Error: boundedPluginHostError(reason)})
}

func (client *pluginHostClient) Close() {
	if client == nil {
		return
	}
	client.closeOnce.Do(func() {
		client.closing.Store(true)
		client.writeMu.Lock()
		_ = writePluginHostFrame(client.stdin, pluginHostMessage{Type: pluginHostMessageTypeShutdown}, pluginHostMaxParentFrameBytes)
		_ = client.stdin.Close()
		client.writeMu.Unlock()
		select {
		case <-client.done:
			return
		case <-time.After(100 * time.Millisecond):
		}
		if client.command != nil && client.command.Process != nil {
			_ = client.command.Process.Kill()
		}
		select {
		case <-client.done:
		case <-time.After(2 * time.Second):
		}
	})
}

func (client *pluginHostClient) Isolated() bool {
	return client != nil
}

func (client *pluginHostClient) RSS() uint64 {
	if client == nil {
		return 0
	}
	return client.lastRSS.Load()
}

func (client *pluginHostClient) ResourceError() string {
	if client == nil {
		return ""
	}
	value := client.resourceError.Load()
	text, _ := value.(string)
	return text
}

func (client *pluginHostClient) PID() int {
	if client == nil || client.command == nil || client.command.Process == nil {
		return 0
	}
	return client.command.Process.Pid
}

func (client *pluginHostClient) Running() bool {
	if client == nil {
		return false
	}
	select {
	case <-client.done:
		return false
	default:
		return true
	}
}

func pluginHostPlatformLabel() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}
