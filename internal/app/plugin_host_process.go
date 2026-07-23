package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja"
)

const pluginHostChildGoMemoryLimit = 192 << 20

type pluginHostProcessServer struct {
	reader *pluginHostFrameReader
	writer io.Writer

	writeMu  sync.Mutex
	stop     chan struct{}
	stopOnce sync.Once

	commands chan pluginHostMessage
	nested   chan pluginHostMessage

	pendingMu sync.Mutex
	pending   map[uint64]chan pluginHostMessage
	nextID    atomic.Uint64

	runtimeMu sync.Mutex
	runtime   *goja.Runtime
	module    *goja.Object
	deadline  time.Time
	requestID uint64
	sandbox   PluginHostSandboxState
}

func runPluginHostProcess() error {
	// Landlock is attached to the calling thread. Keep all untrusted Goja
	// execution on that thread for the lifetime of the host process.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	debug.SetMemoryLimit(pluginHostChildGoMemoryLimit)
	sandbox, err := applyPluginHostChildSandbox()
	if err != nil {
		return fmt.Errorf("apply plugin host sandbox: %w", err)
	}
	server := &pluginHostProcessServer{
		reader:   newPluginHostFrameReader(os.Stdin, pluginHostMaxParentFrameBytes),
		writer:   os.Stdout,
		stop:     make(chan struct{}),
		commands: make(chan pluginHostMessage, 4),
		nested:   make(chan pluginHostMessage, pluginControlMaxNestedEvents),
		pending:  make(map[uint64]chan pluginHostMessage),
		sandbox:  sandbox,
	}
	return server.serve()
}

func (server *pluginHostProcessServer) serve() error {
	readDone := make(chan error, 1)
	go func() { readDone <- server.readLoop() }()

	initialized := false
	for {
		select {
		case <-server.stop:
			return nil
		case err := <-readDone:
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		case message := <-server.commands:
			switch message.Type {
			case pluginHostMessageTypeInit:
				if initialized {
					server.writeError(pluginHostMessageTypeInitReply, message.ID, fmt.Errorf("plugin host is already initialized"))
					continue
				}
				if err := server.initialize(message); err != nil {
					server.writeError(pluginHostMessageTypeInitReply, message.ID, err)
					continue
				}
				initialized = true
				payload, err := marshalPluginHostPayload(pluginHostInitResponse{Sandbox: server.sandbox})
				if err != nil {
					return err
				}
				if err := server.write(pluginHostMessage{Type: pluginHostMessageTypeInitReply, ReplyTo: message.ID, OK: true, Payload: payload}); err != nil {
					return err
				}
			case pluginHostMessageTypeEvent:
				if !initialized {
					server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("plugin host is not initialized"))
					continue
				}
				if err := server.executeEvent(message); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unexpected plugin host command %q", message.Type)
			}
		}
	}
}

func (server *pluginHostProcessServer) readLoop() error {
	for {
		message, err := server.reader.Read()
		if err != nil {
			server.stopProcess()
			return err
		}
		switch message.Type {
		case pluginHostMessageTypeHostReply:
			server.pendingMu.Lock()
			waiter := server.pending[message.ReplyTo]
			server.pendingMu.Unlock()
			if waiter == nil {
				server.stopProcess()
				return fmt.Errorf("plugin host received response for unknown call %d", message.ReplyTo)
			}
			select {
			case waiter <- message:
			case <-server.stop:
				return nil
			}
		case pluginHostMessageTypeNested:
			select {
			case server.nested <- message:
			case <-server.stop:
				return nil
			}
		case pluginHostMessageTypeInterrupt:
			server.runtimeMu.Lock()
			runtime := server.runtime
			server.runtimeMu.Unlock()
			if runtime != nil {
				runtime.Interrupt(boundedPluginHostError(message.Error))
			}
		case pluginHostMessageTypeShutdown:
			server.stopProcess()
			return nil
		case pluginHostMessageTypeInit, pluginHostMessageTypeEvent:
			select {
			case server.commands <- message:
			case <-server.stop:
				return nil
			}
		default:
			server.stopProcess()
			return fmt.Errorf("plugin host received unsupported message type %q", message.Type)
		}
	}
}

func (server *pluginHostProcessServer) stopProcess() {
	server.stopOnce.Do(func() {
		close(server.stop)
		server.runtimeMu.Lock()
		if server.runtime != nil {
			server.runtime.Interrupt("plugin host stopped")
		}
		server.runtimeMu.Unlock()
	})
}

func (server *pluginHostProcessServer) initialize(message pluginHostMessage) error {
	var request pluginHostInitRequest
	if err := decodePluginHostPayload(message.Payload, &request); err != nil {
		return fmt.Errorf("decode plugin host init: %w", err)
	}
	if request.ProtocolVersion != pluginHostProtocolVersion {
		return fmt.Errorf("unsupported plugin host protocol version %d", request.ProtocolVersion)
	}
	if err := validatePluginHostSandboxAdmission(server.sandbox, request.MinimumSandboxLevel); err != nil {
		return err
	}
	if request.Source == "" || len(request.Source) > pluginControlMaxSize {
		return fmt.Errorf("plugin control source must contain 1 to %d bytes", pluginControlMaxSize)
	}
	request.Filename = strings.TrimSpace(request.Filename)
	if request.Filename == "" || len(request.Filename) > 1024 {
		return fmt.Errorf("plugin control filename is invalid")
	}
	if request.MaxCallStack <= 0 || request.MaxCallStack > pluginControlMaxCallStackDepth {
		return fmt.Errorf("plugin control max call stack is invalid")
	}
	if strings.TrimSpace(request.MainModuleID) == "" {
		request.MainModuleID = filepath.ToSlash(request.Filename)
	}
	mainModuleID, normalizeErr := normalizePluginControlModuleID(request.MainModuleID)
	if normalizeErr != nil {
		return fmt.Errorf("plugin control main module id: %w", normalizeErr)
	}
	request.MainModuleID = mainModuleID
	timeout := pluginHostRequestTimeout(request.TimeoutMS)
	runtime := goja.New()
	runtime.SetMaxCallStackSize(request.MaxCallStack)
	server.runtimeMu.Lock()
	server.runtime = runtime
	server.deadline = time.Now().Add(timeout)
	server.requestID = message.ID
	server.runtimeMu.Unlock()
	if err := server.installProxy(runtime); err != nil {
		return err
	}
	exports := runtime.NewObject()
	module := runtime.NewObject()
	if err := module.Set("exports", exports); err != nil {
		return err
	}
	if err := runtime.Set("exports", exports); err != nil {
		return err
	}
	if err := runtime.Set("module", module); err != nil {
		return err
	}
	server.module = module
	if err := installPluginControlModuleLoader(runtime, request.MainModuleID, module, func(referrer, requested string) (pluginControlModuleSource, error) {
		value := server.callHost(runtime, pluginHostInternalModuleLoadMethod, []goja.Value{runtime.ToValue(referrer), runtime.ToValue(requested)})
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return pluginControlModuleSource{}, fmt.Errorf("plugin module broker returned no source")
		}
		object := value.ToObject(runtime)
		return pluginControlModuleSource{ID: object.Get("id").String(), Source: object.Get("source").String()}, nil
	}); err != nil {
		return err
	}
	err := withPluginControlDeadline(runtime, time.Now().Add(timeout), func() error {
		_, runErr := runtime.RunScript(request.Filename, request.Source)
		return runErr
	})
	server.runtimeMu.Lock()
	server.deadline = time.Time{}
	server.requestID = 0
	server.runtimeMu.Unlock()
	if err != nil {
		return fmt.Errorf("run control script %s: %w", request.Filename, err)
	}
	return nil
}

func (server *pluginHostProcessServer) installProxy(runtime *goja.Runtime) error {
	objects := make(map[string]*goja.Object)
	for _, method := range pluginHostControlMethods {
		parts := strings.Split(method, ".")
		if len(parts) < 2 {
			return fmt.Errorf("invalid plugin host method %q", method)
		}
		var object *goja.Object
		path := ""
		for i := 0; i < len(parts)-1; i++ {
			if path == "" {
				path = parts[i]
			} else {
				path += "." + parts[i]
			}
			object = objects[path]
			if object != nil {
				continue
			}
			object = runtime.NewObject()
			objects[path] = object
			if i == 0 {
				if err := runtime.Set(parts[i], object); err != nil {
					return err
				}
				continue
			}
			parentPath := strings.Join(parts[:i], ".")
			if err := objects[parentPath].Set(parts[i], object); err != nil {
				return err
			}
		}
		methodName := method
		if err := object.Set(parts[len(parts)-1], func(call goja.FunctionCall) goja.Value {
			return server.callHost(runtime, methodName, call.Arguments)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (server *pluginHostProcessServer) callHost(runtime *goja.Runtime, method string, values []goja.Value) goja.Value {
	arguments := make([]any, len(values))
	for i, value := range values {
		if value == nil || goja.IsUndefined(value) {
			arguments[i] = nil
			continue
		}
		arguments[i] = value.Export()
	}
	if err := validatePluginHostJSONValue(arguments, 0); err != nil {
		panic(runtime.NewGoError(err))
	}
	payload, err := marshalPluginHostPayload(pluginHostCallRequest{Arguments: arguments})
	if err != nil {
		panic(runtime.NewGoError(fmt.Errorf("encode %s call: %w", method, err)))
	}
	id := server.nextID.Add(1)
	waiter := make(chan pluginHostMessage, 1)
	server.pendingMu.Lock()
	server.pending[id] = waiter
	server.pendingMu.Unlock()
	defer func() {
		server.pendingMu.Lock()
		delete(server.pending, id)
		server.pendingMu.Unlock()
	}()
	if err := server.write(pluginHostMessage{Type: pluginHostMessageTypeHostCall, ID: id, ReplyTo: server.currentRequestID(), Method: method, Payload: payload}); err != nil {
		panic(runtime.NewGoError(err))
	}

	for {
		deadline := server.currentDeadline()
		if deadline.IsZero() {
			deadline = time.Now().Add(pluginControlTimeout)
		}
		timer := time.NewTimer(max(time.Until(deadline), time.Millisecond))
		select {
		case response := <-waiter:
			timer.Stop()
			if !response.OK {
				panic(runtime.NewGoError(errors.New(boundedPluginHostError(response.Error))))
			}
			if response.Undefined {
				return goja.Undefined()
			}
			var result pluginHostCallResponse
			if err := decodePluginHostPayload(response.Payload, &result); err != nil {
				panic(runtime.NewGoError(fmt.Errorf("decode %s response: %w", method, err)))
			}
			if len(result.Value) == 0 {
				return goja.Null()
			}
			exported, err := decodePluginHostJSONValue(result.Value)
			if err != nil {
				panic(runtime.NewGoError(fmt.Errorf("decode %s result: %w", method, err)))
			}
			return runtime.ToValue(exported)
		case nested := <-server.nested:
			timer.Stop()
			if err := server.executeEvent(nested); err != nil {
				panic(runtime.NewGoError(err))
			}
		case <-timer.C:
			panic(runtime.NewGoError(fmt.Errorf("plugin host call %s timed out", method)))
		case <-server.stop:
			timer.Stop()
			panic(runtime.NewGoError(io.ErrClosedPipe))
		}
	}
}

func (server *pluginHostProcessServer) executeEvent(message pluginHostMessage) error {
	var request pluginHostEventRequest
	if err := decodePluginHostPayload(message.Payload, &request); err != nil {
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("decode plugin event: %w", err))
	}
	if err := validatePluginHostJSONValue(request.Context, 0); err != nil {
		return server.writeError(pluginHostMessageTypeResult, message.ID, err)
	}
	request.Handler = strings.TrimSpace(request.Handler)
	if !validPluginControlHandlerName(request.Handler) {
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("invalid plugin handler name"))
	}
	timeout := pluginHostRequestTimeout(request.TimeoutMS)
	runtime := server.runtime
	module := server.module
	if runtime == nil || module == nil {
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("plugin host runtime is unavailable"))
	}
	exportsValue := module.Get("exports")
	if exportsValue == nil || goja.IsUndefined(exportsValue) || goja.IsNull(exportsValue) {
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("control script module.exports is not an object"))
	}
	exportsObject := exportsValue.ToObject(runtime)
	if !pluginHostObjectOwns(exportsObject, request.Handler) {
		if request.Optional {
			payload, _ := marshalPluginHostPayload(pluginHostEventResponse{Handled: false})
			return server.write(pluginHostMessage{Type: pluginHostMessageTypeResult, ReplyTo: message.ID, OK: true, Payload: payload})
		}
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("control script does not export %s", request.Handler))
	}
	handlerValue := exportsObject.Get(request.Handler)
	if handlerValue == nil || goja.IsUndefined(handlerValue) || goja.IsNull(handlerValue) {
		if request.Optional {
			payload, _ := marshalPluginHostPayload(pluginHostEventResponse{Handled: false})
			return server.write(pluginHostMessage{Type: pluginHostMessageTypeResult, ReplyTo: message.ID, OK: true, Payload: payload})
		}
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("control script does not export %s", request.Handler))
	}
	handler, ok := goja.AssertFunction(handlerValue)
	if !ok {
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("control export %s is not a function", request.Handler))
	}
	if request.Probe {
		payload, _ := marshalPluginHostPayload(pluginHostEventResponse{Handled: true})
		return server.write(pluginHostMessage{Type: pluginHostMessageTypeResult, ReplyTo: message.ID, OK: true, Payload: payload})
	}

	deadline := time.Now().Add(timeout)
	server.runtimeMu.Lock()
	previousDeadline := server.deadline
	previousRequestID := server.requestID
	if !previousDeadline.IsZero() && previousDeadline.Before(deadline) {
		deadline = previousDeadline
	}
	server.deadline = deadline
	server.requestID = message.ID
	server.runtimeMu.Unlock()
	var value goja.Value
	err := withPluginControlDeadline(runtime, deadline, func() error {
		var callErr error
		value, callErr = handler(goja.Undefined(), runtime.ToValue(request.Context))
		return callErr
	})
	server.runtimeMu.Lock()
	server.deadline = previousDeadline
	server.requestID = previousRequestID
	server.runtimeMu.Unlock()
	if err != nil {
		var interrupted *goja.InterruptedError
		if errors.As(err, &interrupted) {
			return fmt.Errorf("control handler %s was interrupted: %w", request.Handler, err)
		}
		return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("control handler %s failed: %w", request.Handler, err))
	}
	response := pluginHostEventResponse{Handled: true}
	if request.CaptureResult {
		if value == nil || goja.IsUndefined(value) {
			response.Undefined = true
		} else {
			exported := value.Export()
			if err := validatePluginHostJSONValue(exported, 0); err != nil {
				return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("control handler %s result is invalid: %w", request.Handler, err))
			}
			raw, err := json.Marshal(exported)
			if err != nil {
				return server.writeError(pluginHostMessageTypeResult, message.ID, fmt.Errorf("control handler %s result is not JSON serializable: %w", request.Handler, err))
			}
			response.Value = json.RawMessage(raw)
		}
	}
	payload, err := marshalPluginHostPayload(response)
	if err != nil {
		return server.writeError(pluginHostMessageTypeResult, message.ID, err)
	}
	return server.write(pluginHostMessage{Type: pluginHostMessageTypeResult, ReplyTo: message.ID, OK: true, Payload: payload})
}

func pluginHostObjectOwns(object *goja.Object, name string) bool {
	if object == nil {
		return false
	}
	for _, candidate := range object.GetOwnPropertyNames() {
		if candidate == name {
			return true
		}
	}
	return false
}

func (server *pluginHostProcessServer) currentDeadline() time.Time {
	server.runtimeMu.Lock()
	defer server.runtimeMu.Unlock()
	return server.deadline
}

func (server *pluginHostProcessServer) currentRequestID() uint64 {
	server.runtimeMu.Lock()
	defer server.runtimeMu.Unlock()
	return server.requestID
}

func (server *pluginHostProcessServer) write(message pluginHostMessage) error {
	server.writeMu.Lock()
	defer server.writeMu.Unlock()
	return writePluginHostFrame(server.writer, message, pluginHostMaxChildFrameBytes)
}

func (server *pluginHostProcessServer) writeError(messageType string, replyTo uint64, err error) error {
	message := "plugin host request failed"
	if err != nil {
		message = err.Error()
	}
	return server.write(pluginHostMessage{
		Type: messageType, ReplyTo: replyTo, OK: false, Error: boundedPluginHostError(message),
	})
}

func pluginHostRequestTimeout(milliseconds int64) time.Duration {
	if milliseconds <= 0 {
		return pluginControlTimeout
	}
	timeout := time.Duration(milliseconds) * time.Millisecond
	if timeout > pluginControlTimeout {
		return pluginControlTimeout
	}
	return timeout
}

func boundedPluginHostError(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "plugin host request failed"
	}
	if len(message) <= pluginHostMaxErrorBytes {
		return message
	}
	return message[:pluginHostMaxErrorBytes] + "...<truncated>"
}
