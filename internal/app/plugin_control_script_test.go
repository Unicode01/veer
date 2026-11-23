package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// The host's tests drive the plugin host API with small JavaScript plugins.
// This engine runs them in-process: every host API function is a proxy to
// callPluginHostMethod, the dispatch native plugins use, so the tests cover
// the same method table, permission checks and validation.
func init() {
	pluginControlScriptEngine = newGojaTestControlScript
}

type gojaTestControlScript struct {
	host    *pluginControlHost
	runtime *goja.Runtime
	module  *goja.Object
	json    goja.Callable

	mu    sync.Mutex
	depth int
}

// newGojaTestHostScript makes a runtime whose host API globals call host.
func newGojaTestHostScript(host *pluginControlHost) (*gojaTestControlScript, error) {
	runtime := goja.New()
	runtime.SetMaxCallStackSize(pluginControlMaxCallStackDepth)
	script := &gojaTestControlScript{host: host, runtime: runtime}
	parse, ok := goja.AssertFunction(runtime.Get("JSON").ToObject(runtime).Get("parse"))
	if !ok {
		return nil, fmt.Errorf("JSON.parse is unavailable")
	}
	script.json = parse
	if err := script.installProxy(); err != nil {
		return nil, err
	}
	return script, nil
}

var gojaTestHostScripts sync.Map

func (h *pluginControlHost) testJSScript() (*gojaTestControlScript, error) {
	cached, ok := gojaTestHostScripts.Load(h)
	if !ok {
		script, err := newGojaTestHostScript(h)
		if err != nil {
			return nil, err
		}
		cached, _ = gojaTestHostScripts.LoadOrStore(h, script)
	}
	return cached.(*gojaTestControlScript), nil
}

// setTestJSGlobal defines a global for runTestJS.
func (h *pluginControlHost) setTestJSGlobal(name string, value any) error {
	script, err := h.testJSScript()
	if err != nil {
		return err
	}
	return script.runtime.Set(name, value)
}

// runTestJS evaluates JavaScript against a host's bindings through the
// proxies a test plugin uses; globals persist per host.
func (h *pluginControlHost) runTestJS(source string) (goja.Value, error) {
	script, err := h.testJSScript()
	if err != nil {
		return nil, err
	}
	var value goja.Value
	err = script.withDeadline(time.Now().Add(pluginControlTimeout), func() error {
		var runErr error
		value, runErr = script.runtime.RunString(source)
		return runErr
	})
	return value, err
}

func newGojaTestControlScript(host *pluginControlHost, plugin LoadedPlugin, source string, deadline time.Time) (pluginControlScript, error) {
	script, err := newGojaTestHostScript(host)
	if err != nil {
		return nil, err
	}
	runtime := script.runtime
	exports := runtime.NewObject()
	module := runtime.NewObject()
	if err := module.Set("exports", exports); err != nil {
		return nil, err
	}
	if err := runtime.Set("exports", exports); err != nil {
		return nil, err
	}
	if err := runtime.Set("module", module); err != nil {
		return nil, err
	}
	script.module = module
	mainModuleID, err := pluginControlMainModuleID(plugin)
	if err != nil {
		return nil, err
	}
	if err := installPluginControlModuleLoader(runtime, mainModuleID, module, func(referrer, request string) (pluginControlModuleSource, error) {
		return resolvePluginControlModule(plugin, referrer, request)
	}); err != nil {
		return nil, err
	}
	err = script.withDeadline(deadline, func() error {
		_, runErr := runtime.RunScript(plugin.Control.Main, source)
		return runErr
	})
	if err != nil {
		return nil, err
	}
	return script, nil
}

func (s *gojaTestControlScript) installProxy() error {
	objects := make(map[string]*goja.Object)
	for _, method := range pluginHostControlMethods {
		parts := strings.Split(method, ".")
		var object *goja.Object
		for i := 0; i < len(parts)-1; i++ {
			path := strings.Join(parts[:i+1], ".")
			if existing := objects[path]; existing != nil {
				object = existing
				continue
			}
			object = s.runtime.NewObject()
			objects[path] = object
			var err error
			if i == 0 {
				err = s.runtime.Set(parts[0], object)
			} else {
				err = objects[strings.Join(parts[:i], ".")].Set(parts[i], object)
			}
			if err != nil {
				return err
			}
		}
		name := method
		if err := object.Set(parts[len(parts)-1], func(call goja.FunctionCall) goja.Value {
			return s.callHost(name, call.Arguments)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *gojaTestControlScript) callHost(method string, values []goja.Value) goja.Value {
	arguments := make([]any, len(values))
	for i, value := range values {
		if value == nil || goja.IsUndefined(value) {
			continue
		}
		arguments[i] = value.Export()
	}
	if err := validatePluginHostJSONValue(arguments, 0); err != nil {
		panic(s.runtime.NewTypeError("%s", err.Error()))
	}
	result, undefined, err := s.host.callPluginHostMethod(method, arguments)
	if err != nil {
		panic(s.runtime.NewTypeError("%s", err.Error()))
	}
	if undefined {
		return goja.Undefined()
	}
	return s.toValue(result)
}

// toValue gives the script plain JavaScript values, the way a worker
// decodes the host's JSON replies.
func (s *gojaTestControlScript) toValue(value any) goja.Value {
	if value == nil {
		return goja.Null()
	}
	data, err := json.Marshal(value)
	if err != nil {
		return s.runtime.ToValue(value)
	}
	parsed, err := s.json(goja.Undefined(), s.runtime.ToValue(string(data)))
	if err != nil {
		return s.runtime.ToValue(value)
	}
	return parsed
}

func (s *gojaTestControlScript) run(request pluginHostEventRequest, deadline time.Time) (pluginHostEventResponse, error) {
	var exportsObject *goja.Object
	if exportsValue := s.module.Get("exports"); exportsValue != nil && !goja.IsUndefined(exportsValue) && !goja.IsNull(exportsValue) {
		exportsObject = exportsValue.ToObject(s.runtime)
	}
	if exportsObject == nil || !gojaObjectOwns(exportsObject, request.Handler) {
		if request.Optional {
			return pluginHostEventResponse{}, nil
		}
		return pluginHostEventResponse{}, fmt.Errorf("%w: control script %s does not export %s", errPluginRuntimeTargetNotLoaded, s.host.plugin.Control.Main, request.Handler)
	}
	handler, ok := goja.AssertFunction(exportsObject.Get(request.Handler))
	if !ok {
		return pluginHostEventResponse{}, fmt.Errorf("control export %s is not a function", request.Handler)
	}
	if request.Probe {
		return pluginHostEventResponse{Handled: true}, nil
	}
	var value goja.Value
	err := s.withDeadline(deadline, func() error {
		var callErr error
		value, callErr = handler(goja.Undefined(), s.toValue(request.Context))
		return callErr
	})
	if err != nil {
		return pluginHostEventResponse{Handled: true}, fmt.Errorf("control handler %s failed: %w", request.Handler, err)
	}
	response := pluginHostEventResponse{Handled: true}
	if !request.CaptureResult {
		return response, nil
	}
	if value == nil || goja.IsUndefined(value) {
		response.Undefined = true
		return response, nil
	}
	exported := value.Export()
	if err := validatePluginHostJSONValue(exported, 0); err != nil {
		return response, fmt.Errorf("control handler %s result is invalid: %w", request.Handler, err)
	}
	raw, err := json.Marshal(exported)
	if err != nil {
		return response, fmt.Errorf("control handler %s result is not JSON serializable: %w", request.Handler, err)
	}
	response.Value = raw
	return response, nil
}

// withDeadline bounds the outermost call; nested handlers run inside it.
func (s *gojaTestControlScript) withDeadline(deadline time.Time, fn func() error) error {
	s.mu.Lock()
	s.depth++
	outer := s.depth == 1
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.depth--
		s.mu.Unlock()
	}()
	if !outer {
		return fn()
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return fmt.Errorf("plugin control script timed out")
	}
	fired := make(chan struct{})
	timer := time.AfterFunc(remaining, func() {
		s.runtime.Interrupt("plugin control script timed out")
		close(fired)
	})
	err := fn()
	if !timer.Stop() {
		<-fired
	}
	s.runtime.ClearInterrupt()
	return err
}

func (s *gojaTestControlScript) interrupt(reason string) {
	s.runtime.Interrupt(reason)
}

func (s *gojaTestControlScript) close() {}

func gojaObjectOwns(object *goja.Object, name string) bool {
	for _, candidate := range object.GetOwnPropertyNames() {
		if candidate == name {
			return true
		}
	}
	return false
}
