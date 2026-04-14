package app

import (
	"bufio"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestStopAllSendsStopToWorkerConnections(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	server, client := net.Pipe()
	defer client.Close()

	stopLineCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(client).ReadString('\n')
		stopLineCh <- strings.TrimSpace(line)
	}()

	pm := &ProcessManager{
		listener:    listener,
		shutdownCh:  make(chan struct{}),
		monitorDone: make(chan struct{}),
		redistributeDone: func() chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		}(),
		ruleWorkers: map[int]*WorkerInfo{
			1: {conn: server},
		},
	}
	close(pm.monitorDone)

	pm.stopAll()

	line := <-stopLineCh
	if !strings.Contains(line, `"type":"stop"`) {
		t.Fatalf("stop line = %q, want stop message", line)
	}
}

func TestRequestRedistributeWorkersIgnoredDuringShutdown(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		shutdownCh:       make(chan struct{}),
		redistributeWake: make(chan struct{}, 1),
	}

	pm.beginShutdown()
	pm.requestRedistributeWorkers(0)

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.redistributePending {
		t.Fatal("redistributePending = true, want false after shutdown")
	}
}

func TestStopAllPreservesActiveUserspaceWorkersDuringHotRestart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("hot restart preservation is only supported on linux")
	}

	markerPath := t.TempDir() + "/hot-restart.marker"
	if err := os.WriteFile(markerPath, []byte("1"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("FORWARD_HOT_RESTART_MARKER", markerPath)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	activeRuleServer, activeRuleClient := net.Pipe()
	defer activeRuleClient.Close()

	activeProxyServer, activeProxyClient := net.Pipe()
	defer activeProxyClient.Close()

	drainingServer, drainingClient := net.Pipe()
	defer drainingClient.Close()

	type readResult struct {
		line string
		err  error
	}
	readLine := func(conn net.Conn) <-chan readResult {
		ch := make(chan readResult, 1)
		go func() {
			line, err := bufio.NewReader(conn).ReadString('\n')
			ch <- readResult{line: strings.TrimSpace(line), err: err}
		}()
		return ch
	}

	activeRuleRead := readLine(activeRuleClient)
	activeProxyRead := readLine(activeProxyClient)
	drainingRead := readLine(drainingClient)

	pm := &ProcessManager{
		listener:    listener,
		shutdownCh:  make(chan struct{}),
		monitorDone: make(chan struct{}),
		redistributeDone: func() chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		}(),
		ruleWorkers: map[int]*WorkerInfo{
			1: {conn: activeRuleServer},
		},
		drainingWorkers: []*WorkerInfo{
			{conn: drainingServer, draining: true},
		},
		sharedProxy: &WorkerInfo{conn: activeProxyServer},
	}
	close(pm.monitorDone)

	pm.stopAll()

	activeRuleResult := <-activeRuleRead
	if activeRuleResult.line != "" || !errorsIsEOF(activeRuleResult.err) {
		t.Fatalf("active rule read = (%q, %v), want empty EOF after detach", activeRuleResult.line, activeRuleResult.err)
	}

	activeProxyResult := <-activeProxyRead
	if activeProxyResult.line != "" || !errorsIsEOF(activeProxyResult.err) {
		t.Fatalf("active proxy read = (%q, %v), want empty EOF after detach", activeProxyResult.line, activeProxyResult.err)
	}

	drainingResult := <-drainingRead
	if !strings.Contains(drainingResult.line, `"type":"stop"`) {
		t.Fatalf("draining line = %q, want stop message", drainingResult.line)
	}
}

func errorsIsEOF(err error) bool {
	return err == io.EOF
}
