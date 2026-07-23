package app

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dop251/goja"
)

const (
	pluginHostProtocolVersion      = 1
	pluginHostMaxParentFrameBytes  = 72 << 20
	pluginHostMaxChildFrameBytes   = 20 << 20
	pluginHostMaxErrorBytes        = 16 << 10
	pluginHostMaxCallsPerEvent     = 4096
	pluginHostMaxJSONDepth         = pluginJSONMaxDepth
	pluginHostMessageTypeInit      = "init"
	pluginHostMessageTypeInitReply = "init_result"
	pluginHostMessageTypeEvent     = "event"
	pluginHostMessageTypeNested    = "nested_event"
	pluginHostMessageTypeResult    = "event_result"
	pluginHostMessageTypeHostCall  = "host_call"
	pluginHostMessageTypeHostReply = "host_result"
	pluginHostMessageTypeInterrupt = "interrupt"
	pluginHostMessageTypeShutdown  = "shutdown"
)

type pluginHostMessage struct {
	Type      string          `json:"type"`
	ID        uint64          `json:"id,omitempty"`
	ReplyTo   uint64          `json:"reply_to,omitempty"`
	Method    string          `json:"method,omitempty"`
	OK        bool            `json:"ok,omitempty"`
	Undefined bool            `json:"undefined,omitempty"`
	Error     string          `json:"error,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type pluginHostInitRequest struct {
	ProtocolVersion     int    `json:"protocol_version"`
	Source              string `json:"source"`
	Filename            string `json:"filename"`
	MainModuleID        string `json:"main_module_id"`
	MaxCallStack        int    `json:"max_call_stack"`
	TimeoutMS           int64  `json:"timeout_ms"`
	MinimumSandboxLevel string `json:"minimum_sandbox_level"`
}

type pluginHostInitResponse struct {
	Sandbox PluginHostSandboxState `json:"sandbox"`
}

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

type pluginHostCallRequest struct {
	Arguments []any `json:"arguments,omitempty"`
}

type pluginHostCallResponse struct {
	Value json.RawMessage `json:"value,omitempty"`
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

func mustDiscoverPluginHostControlMethods() []string {
	vm := goja.New()
	host := &pluginControlHost{vm: vm}
	if err := host.install(); err != nil {
		panic(fmt.Sprintf("discover plugin host control methods: %v", err))
	}
	methods := make([]string, 0, len(pluginHostDeclaredControlMethods))
	seenObjects := make(map[*goja.Object]struct{})
	for _, root := range []string{
		"plugin", "pipeline", "kv", "resources", "plugins", "ebpf", "hooks", "ui", "net",
		"timer", "worker", "events", "operations", "metrics", "crypto", "secret", "blob", "log",
	} {
		value := vm.Get(root)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
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

func discoverPluginHostObjectMethods(vm *goja.Runtime, object *goja.Object, prefix string, seen map[*goja.Object]struct{}, methods *[]string) {
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
		if _, ok := goja.AssertFunction(value); ok {
			*methods = append(*methods, path)
			continue
		}
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			continue
		}
		discoverPluginHostObjectMethods(vm, value.ToObject(vm), path, seen, methods)
	}
}

type pluginHostFrameReader struct {
	reader *bufio.Reader
	max    int
}

func newPluginHostFrameReader(reader io.Reader, maxBytes int) *pluginHostFrameReader {
	return &pluginHostFrameReader{reader: bufio.NewReaderSize(reader, 64<<10), max: maxBytes}
}

func (reader *pluginHostFrameReader) Read() (pluginHostMessage, error) {
	if reader == nil || reader.reader == nil {
		return pluginHostMessage{}, io.ErrClosedPipe
	}
	var header [4]byte
	if _, err := io.ReadFull(reader.reader, header[:]); err != nil {
		return pluginHostMessage{}, err
	}
	size := int(binary.BigEndian.Uint32(header[:]))
	if size <= 0 || size > reader.max {
		return pluginHostMessage{}, fmt.Errorf("plugin host frame size %d exceeds limit %d", size, reader.max)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader.reader, data); err != nil {
		return pluginHostMessage{}, err
	}
	if err := rejectPluginDuplicateJSONKeys(data); err != nil {
		return pluginHostMessage{}, fmt.Errorf("decode plugin host frame: %w", err)
	}
	var message pluginHostMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return pluginHostMessage{}, fmt.Errorf("decode plugin host frame: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return pluginHostMessage{}, fmt.Errorf("plugin host frame has trailing JSON values")
		}
		return pluginHostMessage{}, fmt.Errorf("decode trailing plugin host frame content: %w", err)
	}
	message.Type = strings.TrimSpace(message.Type)
	message.Method = strings.TrimSpace(message.Method)
	if message.Type == "" {
		return pluginHostMessage{}, fmt.Errorf("plugin host frame type is required")
	}
	if len(message.Error) > pluginHostMaxErrorBytes {
		return pluginHostMessage{}, fmt.Errorf("plugin host error exceeds %d bytes", pluginHostMaxErrorBytes)
	}
	return message, nil
}

func writePluginHostFrame(writer io.Writer, message pluginHostMessage, maxBytes int) error {
	if writer == nil {
		return io.ErrClosedPipe
	}
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode plugin host frame: %w", err)
	}
	if len(data) == 0 || len(data) > maxBytes {
		return fmt.Errorf("plugin host frame size %d exceeds limit %d", len(data), maxBytes)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err := writePluginHostBytes(writer, header[:]); err != nil {
		return err
	}
	return writePluginHostBytes(writer, data)
}

func writePluginHostBytes(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func marshalPluginHostPayload(value any) (json.RawMessage, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func decodePluginHostPayload(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("payload has trailing JSON values")
		}
		return err
	}
	return nil
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
