package app

import (
	"bufio"
	"net"
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
