package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

func TestPluginExecHelper(t *testing.T) {
	if len(os.Args) < 5 || os.Args[3] != "--veer-exec-test" {
		return
	}
	switch os.Args[4] {
	case "echo":
		input, _ := io.ReadAll(os.Stdin)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"args": os.Args[5:], "stdin": string(input), "secret": os.Getenv("VEER_EXEC_TEST_SECRET"),
		})
		_, _ = fmt.Fprint(os.Stderr, "test stderr")
		os.Exit(7)
	case "sleep":
		time.Sleep(time.Minute)
	case "output":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", pluginExecMaxOutputBytes*2))
	}
	os.Exit(0)
}

func pluginExecTestRequest(t *testing.T, mode string) pluginExecRequest {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return pluginExecRequest{Command: executable, Args: []string{"-test.run=^TestPluginExecHelper$", "--", "--veer-exec-test", mode}}
}

func TestPluginExecPassesLiteralArgumentsAndStdin(t *testing.T) {
	t.Setenv("VEER_EXEC_TEST_SECRET", "must-not-be-inherited")
	request := pluginExecTestRequest(t, "echo")
	request.Args = append(request.Args, "$(echo unsafe); spaces & quotes'")
	request.Stdin = "private key\n"
	result, err := runPluginExec(request, 5*time.Second, nil)
	if err != nil || result.ExitCode != 7 || result.Stderr != "test stderr" || result.TimedOut || result.Truncated {
		t.Fatalf("exec = %+v, %v", result, err)
	}
	var output struct {
		Args   []string `json:"args"`
		Stdin  string   `json:"stdin"`
		Secret string   `json:"secret"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Args) != 1 || output.Args[0] != request.Args[4] || output.Stdin != request.Stdin || output.Secret != "" {
		t.Fatalf("output = %+v", output)
	}
}

func TestPluginExecTimeoutStopAndOutputLimit(t *testing.T) {
	for _, mode := range []string{"timeout", "stop", "output"} {
		t.Run(mode, func(t *testing.T) {
			request := pluginExecTestRequest(t, "sleep")
			stop := make(chan struct{})
			timeout := 5 * time.Second
			if mode == "timeout" {
				timeout = 100 * time.Millisecond
			}
			if mode == "stop" {
				time.AfterFunc(100*time.Millisecond, func() { close(stop) })
			}
			if mode == "output" {
				request = pluginExecTestRequest(t, "output")
			}
			start := time.Now()
			result, err := runPluginExec(request, timeout, stop)
			if err != nil || time.Since(start) > 4*time.Second {
				t.Fatalf("exec = %+v, %v, took %s", result, err, time.Since(start))
			}
			if mode == "timeout" && !result.TimedOut || mode == "stop" && !result.Cancelled || mode == "output" && (!result.Truncated || len(result.Stdout)+len(result.Stderr) > pluginExecMaxOutputBytes) {
				t.Fatalf("wrong termination state: %+v", result)
			}
		})
	}
}

func TestPluginExecBrokerAuthorization(t *testing.T) {
	request := pluginExecTestRequest(t, "echo")
	argument := map[string]any{"command": request.Command, "args": request.Args}
	for _, mode := range []string{"local", "remote", "permission", "registration", "upgrade", "migration", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			host := &pluginControlHost{vm: goja.New(), cfg: &Config{}}
			host.plugin.Control = &PluginControl{Permissions: []string{"exec"}}
			switch mode {
			case "remote":
				host.cfg.PluginsRemoteInstallEnabled = true
			case "permission":
				host.plugin.Control.Permissions = nil
			case "registration":
				host.registrationPhase = true
			case "upgrade":
				host.upgradePhase = true
			case "migration":
				host.migrationPhase = true
			case "deadline":
				host.executionDeadline = time.Now().Add(-time.Second)
			}
			if err := host.install(); err != nil {
				t.Fatal(err)
			}
			value, _, err := host.callPluginHostMethod("process.exec", []any{argument})
			if mode == "local" {
				result, ok := value.(map[string]any)
				if err != nil || !ok || result["exit_code"] != 7 {
					t.Fatalf("local broker result = %#v, %v", value, err)
				}
			} else if err == nil {
				t.Fatalf("%s broker unexpectedly executed: %#v", mode, value)
			}
		})
	}
}

func TestPluginExecValidatesRequest(t *testing.T) {
	valid := pluginExecTestRequest(t, "echo")
	for _, mutate := range []func(*pluginExecRequest){
		func(r *pluginExecRequest) { r.Command = "relative" },
		func(r *pluginExecRequest) { r.Command += "\x00" },
		func(r *pluginExecRequest) { r.Args = []string{"\x00"} },
		func(r *pluginExecRequest) { r.TimeoutMS = -1 },
		func(r *pluginExecRequest) { r.TimeoutMS = 1 << 62 },
		func(r *pluginExecRequest) { r.Args = make([]string, 129) },
		func(r *pluginExecRequest) { r.Stdin = strings.Repeat("x", pluginExecMaxInputBytes+1) },
	} {
		request := valid
		mutate(&request)
		if _, err := validatePluginExecRequest(request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
}

func TestPluginExecThroughIsolatedAndInProcessRuntime(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		t.Run(fmt.Sprint(isolated), func(t *testing.T) {
			dir := t.TempDir()
			writeTestPlugin(t, dir, "exec_runtime", `{
  "api_version":"v1", "id":"exec_runtime", "name":"Exec Runtime", "version":"1.0.0",
  "kind":"control", "stability":"lab",
  "actions":[{"id":"run","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["exec","kv"]}
}`)
			request := pluginExecTestRequest(t, "echo")
			requestJSON, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			writePluginControlScript(t, dir, "exec_runtime", `exports.onAction = function () { kv.set("result", process.exec(`+string(requestJSON)+`)); };`)
			cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
			if isolated {
				cfg = isolatedPluginsTestConfig(cfg)
			}
			plugin := loadTestPluginByID(t, cfg, "exec_runtime")
			db := openTestDB(t)
			runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
			t.Cleanup(func() { _ = runtime.Close() })
			if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "result")
			if err != nil || !strings.Contains(record.DataJSON, `"exit_code":7`) || !strings.Contains(record.DataJSON, `"stderr":"test stderr"`) {
				t.Fatalf("exec runtime result = %+v, %v", record, err)
			}
		})
	}
}
