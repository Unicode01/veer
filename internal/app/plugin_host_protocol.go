package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	hv "github.com/Unicode01/veer/internal/hostvalue"
)

// Limits of the host side of a plugin handler: frame sizes between the
// host and a plugin worker, host calls per handler and JSON nesting.
const (
	pluginHostProtocolVersion     = 1
	pluginHostMaxParentFrameBytes = 72 << 20
	pluginHostMaxChildFrameBytes  = 20 << 20
	pluginHostMaxErrorBytes       = 16 << 10
	pluginHostMaxCallsPerEvent    = 4096
	pluginHostMaxJSONDepth        = pluginJSONMaxDepth
)

// pluginHostEventRequest is one handler invocation: the handler name and
// the context it receives.
type pluginHostEventRequest struct {
	Handler       string         `json:"handler"`
	Optional      bool           `json:"optional,omitempty"`
	Probe         bool           `json:"probe,omitempty"`
	CaptureResult bool           `json:"capture_result,omitempty"`
	TimeoutMS     int64          `json:"timeout_ms"`
	Context       map[string]any `json:"context"`
}

type pluginHostEventResponse struct {
	Handled   bool            `json:"handled"`
	Undefined bool            `json:"undefined,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
}

var pluginHostDeclaredControlMethods = pluginHostCapabilityMethods(pluginHostControlCapabilities)

var (
	pluginHostControlMethods   []string
	pluginHostControlMethodSet map[string]struct{}
)

func init() {
	pluginHostControlMethods = mustDiscoverPluginHostControlMethods()
	pluginHostControlMethodSet = make(map[string]struct{}, len(pluginHostControlMethods))
	for _, method := range pluginHostControlMethods {
		pluginHostControlMethodSet[method] = struct{}{}
	}
}

func pluginHostMethodAllowed(method string) bool {
	_, allowed := pluginHostControlMethodSet[method]
	return allowed
}

// mustDiscoverPluginHostControlMethods lists the functions the bindings
// install and checks them against the declared capability table.
func mustDiscoverPluginHostControlMethods() []string {
	vm := hv.New()
	host := &pluginControlHost{vm: vm}
	if err := host.install(); err != nil {
		panic(fmt.Sprintf("discover plugin host control methods: %v", err))
	}
	methods := make([]string, 0, len(pluginHostDeclaredControlMethods))
	seenObjects := make(map[*hv.Object]struct{})
	for _, root := range []string{
		"plugin", "pipeline", "kv", "resources", "plugins", "ebpf", "hooks", "ui", "net",
		"timer", "worker", "events", "operations", "metrics", "crypto", "secret", "blob", "log", "process",
	} {
		value := vm.Get(root)
		if value == nil || hv.IsUndefined(value) || hv.IsNull(value) {
			panic(fmt.Sprintf("plugin host API root %s is unavailable", root))
		}
		discoverPluginHostObjectMethods(vm, value.ToObject(vm), root, seenObjects, &methods)
	}
	sort.Strings(methods)
	declared := append([]string(nil), pluginHostDeclaredControlMethods...)
	sort.Strings(declared)
	if len(methods) != len(declared) {
		panic(fmt.Sprintf("plugin host method registry drift: discovered=%d declared=%d", len(methods), len(declared)))
	}
	for i := range methods {
		if methods[i] != declared[i] {
			panic(fmt.Sprintf("plugin host method registry drift: discovered=%s declared=%s", methods[i], declared[i]))
		}
	}
	return methods
}

func discoverPluginHostObjectMethods(vm *hv.Runtime, object *hv.Object, prefix string, seen map[*hv.Object]struct{}, methods *[]string) {
	if object == nil {
		return
	}
	if _, exists := seen[object]; exists {
		return
	}
	seen[object] = struct{}{}
	for _, key := range object.Keys() {
		value := object.Get(key)
		path := prefix + "." + key
		if _, ok := hv.AssertFunction(value); ok {
			*methods = append(*methods, path)
			continue
		}
		if value == nil || hv.IsUndefined(value) || hv.IsNull(value) {
			continue
		}
		discoverPluginHostObjectMethods(vm, value.ToObject(vm), path, seen, methods)
	}
}

func decodePluginHostJSONValue(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("JSON value has trailing content")
		}
		return nil, err
	}
	if err := validatePluginHostJSONValue(value, 0); err != nil {
		return nil, err
	}
	return value, nil
}

func validatePluginHostJSONValue(value any, depth int) error {
	if depth > pluginHostMaxJSONDepth {
		return fmt.Errorf("plugin host JSON nesting exceeds %d", pluginHostMaxJSONDepth)
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if len(key) > 1024 {
				return fmt.Errorf("plugin host JSON object key exceeds 1024 bytes")
			}
			if err := validatePluginHostJSONValue(item, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := validatePluginHostJSONValue(item, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
