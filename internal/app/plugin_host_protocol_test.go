package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func TestPluginHostFrameRoundTrip(t *testing.T) {
	var stream bytes.Buffer
	want := pluginHostMessage{Type: pluginHostMessageTypeEvent, ID: 7, Method: "kv.get", Payload: json.RawMessage(`{"key":"value"}`)}
	if err := writePluginHostFrame(&stream, want, 4096); err != nil {
		t.Fatal(err)
	}
	got, err := newPluginHostFrameReader(&stream, 4096).Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.ID != want.ID || got.Method != want.Method || string(got.Payload) != string(want.Payload) {
		t.Fatalf("frame = %+v, want %+v", got, want)
	}
}

func TestPluginHostMessageQueueBackpressuresUnconsumedFrames(t *testing.T) {
	if pluginHostMessageQueueSize != 0 {
		t.Fatalf("plugin host message queue size = %d, want synchronous delivery", pluginHostMessageQueueSize)
	}
	reader, writer := io.Pipe()
	done := make(chan struct{})
	client := &pluginHostClient{
		messages: make(chan pluginHostMessage, pluginHostMessageQueueSize),
		errors:   make(chan error, 1),
		done:     done,
	}
	readDone := make(chan struct{})
	go func() {
		client.readLoop(reader)
		close(readDone)
	}()
	t.Cleanup(func() {
		close(done)
		_ = writer.Close()
		_ = reader.Close()
		select {
		case <-readDone:
		case <-time.After(time.Second):
			t.Error("plugin host read loop did not stop")
		}
	})

	writeFrame := func(id uint64) <-chan error {
		result := make(chan error, 1)
		go func() {
			result <- writePluginHostFrame(writer, pluginHostMessage{Type: pluginHostMessageTypeResult, ID: id}, 4096)
		}()
		return result
	}
	firstWrite := writeFrame(1)
	select {
	case err := <-firstWrite:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first plugin host frame was not read")
	}

	secondWrite := writeFrame(2)
	select {
	case err := <-secondWrite:
		t.Fatalf("second frame was read before the first was consumed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if message := <-client.messages; message.ID != 1 {
		t.Fatalf("first message id = %d, want 1", message.ID)
	}
	select {
	case err := <-secondWrite:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second plugin host frame remained blocked after consuming the first")
	}
	if message := <-client.messages; message.ID != 2 {
		t.Fatalf("second message id = %d, want 2", message.ID)
	}
}

func TestPluginHostFrameRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		max  int
		want string
	}{
		{name: "empty", data: []byte{0, 0, 0, 0}, max: 64, want: "frame size 0"},
		{name: "oversized", data: []byte{0, 0, 0, 65}, max: 64, want: "exceeds limit"},
		{name: "truncated", data: append([]byte{0, 0, 0, 4}, []byte(`{}`)...), max: 64, want: "unexpected EOF"},
		{name: "unknown field", data: framedPluginHostJSON(`{"type":"event","extra":true}`), max: 128, want: "unknown field"},
		{name: "duplicate field", data: framedPluginHostJSON(`{"type":"event","type":"shutdown"}`), max: 128, want: "duplicate key"},
		{name: "trailing value", data: framedPluginHostJSON(`{"type":"event"}{}`), max: 128, want: "trailing"},
		{name: "missing type", data: framedPluginHostJSON(`{"id":1}`), max: 128, want: "type is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newPluginHostFrameReader(bytes.NewReader(tt.data), tt.max).Read()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Read() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPluginHostPayloadRejectsUnknownAndTrailingJSON(t *testing.T) {
	var request pluginHostCallRequest
	if err := decodePluginHostPayload(json.RawMessage(`{"arguments":[],"extra":true}`), &request); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	if err := decodePluginHostPayload(json.RawMessage(`{"arguments":[]}[]`), &request); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing payload error = %v", err)
	}
	if _, err := decodePluginHostJSONValue(json.RawMessage(`{"ok":true}[]`)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing value error = %v", err)
	}
}

func TestPluginHostJSONNumbersPreserveJavaScriptSemantics(t *testing.T) {
	var request pluginHostEventRequest
	if err := decodePluginHostPayload(json.RawMessage(`{
		"handler":"onAction",
		"timeout_ms":1000,
		"context":{"count":7,"ratio":1.5,"nested":{"value":2}}
	}`), &request); err != nil {
		t.Fatalf("decodePluginHostPayload() error = %v", err)
	}
	value, err := decodePluginHostJSONValue(json.RawMessage(`{"count":7,"ratio":1.5,"nested":{"value":2}}`))
	if err != nil {
		t.Fatalf("decodePluginHostJSONValue() error = %v", err)
	}

	runtime := goja.New()
	if err := runtime.Set("eventContext", request.Context); err != nil {
		t.Fatalf("set event context: %v", err)
	}
	if err := runtime.Set("hostResult", value); err != nil {
		t.Fatalf("set host result: %v", err)
	}
	if _, err := runtime.RunString(`
for (var item of [eventContext, hostResult]) {
  if (typeof item.count !== 'number' || item.count !== 7) throw new Error('count is not a JavaScript number');
  if (typeof item.ratio !== 'number' || item.ratio !== 1.5) throw new Error('ratio is not a JavaScript number');
  if (typeof item.nested.value !== 'number' || item.nested.value !== 2) throw new Error('nested value is not a JavaScript number');
}
`); err != nil {
		t.Fatalf("evaluate decoded numeric values: %v", err)
	}
}

func TestPluginHostJSONDepthLimit(t *testing.T) {
	var value any = map[string]any{"leaf": true}
	for i := 0; i <= pluginHostMaxJSONDepth; i++ {
		value = map[string]any{"next": value}
	}
	if err := validatePluginHostJSONValue(value, 0); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("depth error = %v", err)
	}
}

func TestPluginHostSandboxAdmissionIsFailClosed(t *testing.T) {
	partial := PluginHostSandboxState{
		Platform: "linux",
		Level:    pluginSandboxLevelPartial,
		Degraded: []string{"Landlock unavailable"},
	}
	if err := validatePluginHostSandboxAdmission(partial, pluginSandboxLevelPartial); err != nil {
		t.Fatalf("partial admission error = %v", err)
	}
	if err := validatePluginHostSandboxAdmission(partial, pluginSandboxLevelFull); err == nil || !strings.Contains(err.Error(), "Landlock unavailable") {
		t.Fatalf("full admission error = %v", err)
	}
	if err := validatePluginHostSandboxAdmission(PluginHostSandboxState{Platform: "linux", Level: "unknown"}, pluginSandboxLevelMinimal); err == nil {
		t.Fatal("unknown sandbox level was admitted")
	}
}

func TestPluginHostInitializationChecksSandboxBeforeJavaScript(t *testing.T) {
	server := &pluginHostProcessServer{
		sandbox: PluginHostSandboxState{
			Platform: "linux",
			Level:    pluginSandboxLevelPartial,
			Degraded: []string{"Landlock unavailable"},
		},
	}
	payload, err := marshalPluginHostPayload(pluginHostInitRequest{
		ProtocolVersion:     pluginHostProtocolVersion,
		Source:              `throw new Error("javascript executed");`,
		Filename:            "control.js",
		MaxCallStack:        pluginControlMaxCallStackDepth,
		TimeoutMS:           pluginControlTimeout.Milliseconds(),
		MinimumSandboxLevel: pluginSandboxLevelFull,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = server.initialize(pluginHostMessage{ID: 1, Payload: payload})
	if err == nil || !strings.Contains(err.Error(), "Landlock unavailable") || strings.Contains(err.Error(), "javascript executed") {
		t.Fatalf("initialization error = %v", err)
	}
	if server.runtime != nil {
		t.Fatal("Goja runtime was created before sandbox admission")
	}
}

func TestPluginHostRejectsInheritedHandler(t *testing.T) {
	cfg := isolatedPluginsTestConfig(&Config{})
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "handler_guard", Control: &PluginControl{Main: "control.js"}}}
	client, err := startPluginHostClient(cfg, plugin, "control", "", `exports.onAction = function () {};`, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.runEvent(pluginHostEventRequest{Handler: "constructor", Context: map[string]any{}}, nil, time.Now().Add(time.Second), false)
	if err == nil || !strings.Contains(err.Error(), "does not export constructor") {
		t.Fatalf("constructor handler error = %v", err)
	}
}

func TestPluginControlInProcessRejectsInheritedHandler(t *testing.T) {
	vm := goja.New()
	module := vm.NewObject()
	if err := module.Set("exports", vm.NewObject()); err != nil {
		t.Fatal(err)
	}
	host := &pluginControlHost{
		vm:     vm,
		module: module,
		plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "handler_guard", Control: &PluginControl{Main: "control.js"}}},
	}
	_, _, _, err := host.runEvent(pluginControlEvent{Kind: "worker", Worker: &pluginControlWorkerEvent{Name: "worker", Handler: "constructor"}}, false)
	if err == nil || !strings.Contains(err.Error(), "does not export constructor") {
		t.Fatalf("constructor handler error = %v", err)
	}
}

func TestPluginHostCallLimitTerminatesProcess(t *testing.T) {
	cfg := isolatedPluginsTestConfig(&Config{})
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "call_limit", Control: &PluginControl{Main: "control.js"}}}
	source := `exports.onAction = function () { for (var i = 0; i < 5000; i++) kv.get('key'); };`
	client, err := startPluginHostClient(cfg, plugin, "control", "", source, pluginHostBrokerFunc(func(string, []any) (any, bool, error) {
		return nil, false, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.runEvent(pluginHostEventRequest{Handler: "onAction", Context: map[string]any{}}, pluginHostBrokerFunc(func(string, []any) (any, bool, error) {
		return nil, false, nil
	}), time.Now().Add(15*time.Second), false)
	if !errors.Is(err, errPluginHostProcessExited) || !strings.Contains(err.Error(), "call limit") {
		t.Fatalf("call limit error = %v", err)
	}
}

type pluginHostBrokerFunc func(method string, arguments []any) (any, bool, error)

func (fn pluginHostBrokerFunc) callPluginHostMethod(method string, arguments []any) (any, bool, error) {
	return fn(method, arguments)
}

func framedPluginHostJSON(value string) []byte {
	payload := []byte(value)
	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(payload)))
	copy(data[4:], payload)
	return data
}

func TestPluginHostFrameReaderReturnsEOFForMissingHeader(t *testing.T) {
	_, err := newPluginHostFrameReader(bytes.NewReader(nil), 64).Read()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v, want EOF", err)
	}
}
