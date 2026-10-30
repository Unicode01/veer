package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

const (
	pluginExecDefaultTimeout = 5 * time.Second
	pluginExecMaxTimeout     = 15 * time.Second
	pluginExecMaxInputBytes  = 64 << 10
	pluginExecMaxOutputBytes = 64 << 10
)

type pluginExecRequest struct {
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Stdin     string   `json:"stdin"`
	TimeoutMS int64    `json:"timeout_ms"`
}

type pluginExecResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	TimedOut  bool
	Cancelled bool
	Truncated bool
}

func (h *pluginControlHost) processExec(call goja.FunctionCall) goja.Value {
	const api = "process.exec"
	h.requirePermission("exec")
	if !h.cfg.PluginExecEnabled() {
		h.throwf("%s is disabled while remote plugin installation is enabled", api)
	}
	obj := h.requiredObjectArg(call, 0, "request")
	data, err := json.Marshal(obj.Export())
	if err != nil || len(data) > pluginExecMaxInputBytes {
		h.throwf("%s request must be JSON and at most %d bytes", api, pluginExecMaxInputBytes)
	}
	var request pluginExecRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		h.throwf("%s: invalid request: %v", api, err)
	}
	timeout, err := validatePluginExecRequest(request)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	timeout = h.boundedTransportTimeout(timeout, api)
	result, err := runPluginExec(request, timeout, h.executionStop)
	outcome := "success"
	if err != nil || result.ExitCode != 0 || result.TimedOut || result.Cancelled || result.Truncated {
		outcome = "error"
	}
	// Arguments, stdin and output may contain credentials. Audit only metadata.
	recordPluginAudit(h.db, h.plugin.ID, api, "control", outcome, map[string]any{
		"command": request.Command, "exit_code": result.ExitCode,
		"timed_out": result.TimedOut, "cancelled": result.Cancelled, "truncated": result.Truncated,
	})
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{
		"stdout": result.Stdout, "stderr": result.Stderr, "exit_code": result.ExitCode,
		"timed_out": result.TimedOut, "cancelled": result.Cancelled, "truncated": result.Truncated,
	})
}

func validatePluginExecRequest(request pluginExecRequest) (time.Duration, error) {
	if !filepath.IsAbs(request.Command) || strings.IndexByte(request.Command, 0) >= 0 {
		return 0, fmt.Errorf("command must be an absolute executable path without NUL bytes")
	}
	if len(request.Args) > 128 {
		return 0, fmt.Errorf("args exceeds 128 arguments")
	}
	size := len(request.Command) + len(request.Stdin)
	for _, arg := range request.Args {
		if strings.IndexByte(arg, 0) >= 0 {
			return 0, fmt.Errorf("args must not contain NUL bytes")
		}
		size += len(arg)
	}
	if size > pluginExecMaxInputBytes {
		return 0, fmt.Errorf("input exceeds %d bytes", pluginExecMaxInputBytes)
	}
	if request.TimeoutMS == 0 {
		return pluginExecDefaultTimeout, nil
	}
	if request.TimeoutMS < 1 || request.TimeoutMS > pluginExecMaxTimeout.Milliseconds() {
		return 0, fmt.Errorf("timeout_ms must be between 1 and %d", pluginExecMaxTimeout.Milliseconds())
	}
	return time.Duration(request.TimeoutMS) * time.Millisecond, nil
}

// Commands intentionally run in the trusted host, not the unprivileged JS
// sandbox. argv is passed directly; no shell, inherited stdin or service env.
func runPluginExec(request pluginExecRequest, timeout time.Duration, stop <-chan struct{}) (pluginExecResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-stop:
			cancel()
		case <-done:
		}
	}()
	select {
	case <-stop:
		return pluginExecResult{}, fmt.Errorf("plugin execution stopped")
	default:
	}
	command := exec.CommandContext(ctx, request.Command, request.Args...) // #nosec G204 -- explicitly authorized local exec capability.
	command.Env = pluginExecEnvironment()
	command.Dir = filepath.VolumeName(request.Command) + string(filepath.Separator)
	command.Stdin = strings.NewReader(request.Stdin)
	command.WaitDelay = 100 * time.Millisecond
	cleanup := configurePluginExecCommand(command)
	defer cleanup()
	output := &pluginExecOutput{remaining: pluginExecMaxOutputBytes, cancel: cancel}
	stdout := &pluginExecWriter{output: output}
	stderr := &pluginExecWriter{output: output}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	result := pluginExecResult{
		Stdout: stdout.buffer.String(), Stderr: stderr.buffer.String(), ExitCode: -1,
		TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded), Truncated: output.truncated,
		Cancelled: errors.Is(ctx.Err(), context.Canceled) && !output.truncated,
	}
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
	}
	var exitError *exec.ExitError
	// Cancellation can race with a successful exit after the output writer has
	// cancelled the context. os/exec then returns ctx.Err rather than ExitError.
	cancelledAfterStart := command.ProcessState != nil && ctx.Err() != nil && errors.Is(err, ctx.Err())
	if err != nil && !errors.As(err, &exitError) && !errors.Is(err, exec.ErrWaitDelay) && !cancelledAfterStart {
		return result, fmt.Errorf("execute command: %w", err)
	}
	return result, nil
}

type pluginExecOutput struct {
	mu        sync.Mutex
	remaining int
	truncated bool
	cancel    context.CancelFunc
}

type pluginExecWriter struct {
	output *pluginExecOutput
	buffer bytes.Buffer
}

func (writer *pluginExecWriter) Write(data []byte) (int, error) {
	writer.output.mu.Lock()
	defer writer.output.mu.Unlock()
	n := min(len(data), writer.output.remaining)
	_, _ = writer.buffer.Write(data[:n])
	writer.output.remaining -= n
	if n < len(data) {
		writer.output.truncated = true
		writer.output.cancel()
	}
	return len(data), nil
}
