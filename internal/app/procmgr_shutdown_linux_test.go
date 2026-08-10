//go:build linux

package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const userspaceHandoffHelperEnv = "VEER_TEST_USERSPACE_HANDOFF_HELPER"

type userspaceHandoffHelperProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func TestUserspaceHandoffHelperProcess(t *testing.T) {
	if os.Getenv(userspaceHandoffHelperEnv) != "1" {
		return
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := os.WriteFile(os.Getenv("VEER_TEST_USERSPACE_HANDOFF_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	<-signals
}

func startUserspaceHandoffHelperProcess(t *testing.T, name string) userspaceHandoffHelperProcess {
	t.Helper()
	readyPath := filepath.Join(t.TempDir(), name+".ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestUserspaceHandoffHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		userspaceHandoffHelperEnv+"=1",
		"VEER_TEST_USERSPACE_HANDOFF_READY="+readyPath,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s helper: %v", name, err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		_ = cmd.Process.Kill()
		<-done
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		select {
		case <-done:
			t.Fatalf("%s helper exited before becoming ready", name)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s helper did not become ready", name)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return userspaceHandoffHelperProcess{cmd: cmd, done: done}
}

func TestStopAllPreservesActiveUserspaceWorkersDuringHotRestart(t *testing.T) {
	markerPath := filepath.Join(t.TempDir(), "hot-restart.marker")
	if err := os.WriteFile(markerPath, []byte("1"), 0o600); err != nil {
		t.Fatalf("write hot restart marker: %v", err)
	}
	t.Setenv(forwardHotRestartMarkerEnv, markerPath)

	ruleProcess := startUserspaceHandoffHelperProcess(t, "rule")
	proxyProcess := startUserspaceHandoffHelperProcess(t, "proxy")
	drainingProcess := startUserspaceHandoffHelperProcess(t, "draining")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	activeRuleServer, activeRuleClient := net.Pipe()
	t.Cleanup(func() { _ = activeRuleClient.Close() })
	activeProxyServer, activeProxyClient := net.Pipe()
	t.Cleanup(func() { _ = activeProxyClient.Close() })
	drainingServer, drainingClient := net.Pipe()
	t.Cleanup(func() { _ = drainingClient.Close() })

	type readResult struct {
		line string
		err  error
	}
	readLine := func(conn net.Conn, onLine func()) <-chan readResult {
		ch := make(chan readResult, 1)
		go func() {
			line, err := bufio.NewReader(conn).ReadString('\n')
			if line != "" && onLine != nil {
				onLine()
			}
			ch <- readResult{line: strings.TrimSpace(line), err: err}
		}()
		return ch
	}

	activeRuleRead := readLine(activeRuleClient, nil)
	activeProxyRead := readLine(activeProxyClient, nil)
	drainingRead := readLine(drainingClient, func() {
		_ = drainingProcess.cmd.Process.Signal(syscall.SIGTERM)
	})

	runtimeDir := t.TempDir()
	pm := &ProcessManager{
		sockPath:   filepath.Join(runtimeDir, "control.sock"),
		listener:   listener,
		shutdownCh: make(chan struct{}),
		monitorDone: func() chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		}(),
		redistributeDone: func() chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		}(),
		ruleWorkers: map[int]*WorkerInfo{
			1: {
				workerIndex: 1,
				kind:        workerKindRule,
				process:     ruleProcess.cmd.Process,
				waitCh:      ruleProcess.done,
				conn:        activeRuleServer,
				binaryHash:  "rule-hash",
			},
		},
		drainingWorkers: []*WorkerInfo{
			{
				workerIndex: 2,
				kind:        workerKindRule,
				process:     drainingProcess.cmd.Process,
				waitCh:      drainingProcess.done,
				conn:        drainingServer,
				draining:    true,
			},
		},
		sharedProxy: &WorkerInfo{
			kind:       workerKindShared,
			process:    proxyProcess.cmd.Process,
			waitCh:     proxyProcess.done,
			conn:       activeProxyServer,
			binaryHash: "proxy-hash",
		},
	}

	pm.stopAll()

	for name, resultCh := range map[string]<-chan readResult{
		"rule":  activeRuleRead,
		"proxy": activeProxyRead,
	} {
		result := <-resultCh
		if result.line != "" || !errors.Is(result.err, io.EOF) {
			t.Fatalf("active %s read = (%q, %v), want empty EOF after detach", name, result.line, result.err)
		}
	}
	drainingResult := <-drainingRead
	if !strings.Contains(drainingResult.line, `"type":"stop"`) {
		t.Fatalf("draining line = %q, want stop message", drainingResult.line)
	}
	select {
	case <-drainingProcess.done:
	case <-time.After(2 * time.Second):
		t.Fatal("draining worker process remained alive after stop")
	}

	handoffPath := userspaceWorkerHandoffPath(pm.sockPath)
	data, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatalf("read handoff file: %v", err)
	}
	var state userspaceWorkerHandoffState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode handoff file: %v", err)
	}
	if state.FormatVersion != userspaceWorkerHandoffFormatVersion || state.OwnerPID != os.Getpid() {
		t.Fatalf("handoff metadata = %+v, want format %d owner %d", state, userspaceWorkerHandoffFormatVersion, os.Getpid())
	}
	if len(state.Workers) != 2 {
		t.Fatalf("handoff workers = %+v, want active rule and proxy only", state.Workers)
	}
	wantPIDs := map[userspaceWorkerHandoffKey]int{
		{Kind: workerKindRule, Index: 1}: ruleProcess.cmd.Process.Pid,
		{Kind: workerKindShared}:         proxyProcess.cmd.Process.Pid,
	}
	for _, record := range state.Workers {
		key, err := userspaceWorkerKey(record.Kind, record.Index)
		if err != nil {
			t.Fatalf("invalid handoff record %+v: %v", record, err)
		}
		wantPID, ok := wantPIDs[key]
		if !ok || record.PID != wantPID || record.StartTicks == 0 {
			t.Fatalf("handoff record = %+v, want pid %d with start time", record, wantPID)
		}
		if !userspaceWorkerProcessIdentityAlive(record.PID, record.StartTicks) {
			t.Fatalf("preserved process identity is not alive: %+v", record)
		}
		delete(wantPIDs, key)
	}
	if len(wantPIDs) != 0 {
		t.Fatalf("handoff file omitted workers: %+v", wantPIDs)
	}

	for _, helper := range []userspaceHandoffHelperProcess{ruleProcess, proxyProcess} {
		select {
		case <-helper.done:
			t.Fatalf("preserved process %d exited during shutdown", helper.cmd.Process.Pid)
		default:
		}
		_ = helper.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-helper.done:
		case <-time.After(2 * time.Second):
			t.Fatalf("preserved process %d did not stop during test cleanup", helper.cmd.Process.Pid)
		}
	}
}
