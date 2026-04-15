//go:build linux

package app

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareSecureIPCListenerSetsRestrictedPermissions(t *testing.T) {
	ln, sockPath, err := prepareSecureIPCListener(filepath.Join(t.TempDir(), "forward"))
	if err != nil {
		t.Fatalf("prepareSecureIPCListener() error = %v", err)
	}
	defer ln.Close()
	defer cleanupSecureIPCListener(sockPath)

	socketDir := filepath.Dir(sockPath)

	dirInfo, err := os.Stat(socketDir)
	if err != nil {
		t.Fatalf("Stat(socketDir) error = %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("socket dir perms = %#o, want 0700", got)
	}

	socketInfo, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("Stat(sockPath) error = %v", err)
	}
	if got := socketInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket perms = %#o, want 0600", got)
	}
}

func TestHandleWorkerConnRejectsUnexpectedPeerPID(t *testing.T) {
	ln, sockPath, err := prepareSecureIPCListener(filepath.Join(t.TempDir(), "forward"))
	if err != nil {
		t.Fatalf("prepareSecureIPCListener() error = %v", err)
	}
	defer ln.Close()
	defer cleanupSecureIPCListener(sockPath)

	expectedProc := exec.Command("sleep", "30")
	if err := expectedProc.Start(); err != nil {
		t.Fatalf("start expected process: %v", err)
	}
	defer func() {
		_ = expectedProc.Process.Kill()
		_ = expectedProc.Wait()
	}()

	pm := &ProcessManager{
		listener:    ln,
		sockPath:    sockPath,
		binaryHash:  "manager-hash",
		ruleWorkers: map[int]*WorkerInfo{7: {workerIndex: 7, process: expectedProc.Process}},
	}

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			pm.handleWorkerConn(conn)
		}
		close(done)
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	data, err := json.Marshal(IPCMessage{Type: "register", WorkerIndex: 7, BinaryHash: "worker-hash"})
	if err != nil {
		t.Fatalf("marshal register: %v", err)
	}
	data = append(data, '\n')
	if _, err := client.Write(data); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("client.Read() error = nil, want connection close")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleWorkerConn() did not exit")
	}

	if pm.ruleWorkers[7].conn != nil {
		t.Fatal("rule worker conn registered for unexpected peer")
	}
}

func TestHandleWorkerConnAcceptsExpectedPeerPID(t *testing.T) {
	ln, sockPath, err := prepareSecureIPCListener(filepath.Join(t.TempDir(), "forward"))
	if err != nil {
		t.Fatalf("prepareSecureIPCListener() error = %v", err)
	}
	defer ln.Close()
	defer cleanupSecureIPCListener(sockPath)

	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess() error = %v", err)
	}

	pm := &ProcessManager{
		listener:    ln,
		sockPath:    sockPath,
		binaryHash:  "manager-hash",
		ruleWorkers: map[int]*WorkerInfo{3: {workerIndex: 3, process: self, rules: []Rule{{ID: 12, InIP: "127.0.0.1", InPort: 80, OutIP: "127.0.0.1", OutPort: 8080, Protocol: "tcp"}}}},
	}

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			pm.handleWorkerConn(conn)
		}
		close(done)
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	data, err := json.Marshal(IPCMessage{Type: "register", WorkerIndex: 3, BinaryHash: "worker-hash"})
	if err != nil {
		t.Fatalf("marshal register: %v", err)
	}
	data = append(data, '\n')
	if _, err := client.Write(data); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	scanner := bufio.NewScanner(client)
	if !scanner.Scan() {
		t.Fatal("scanner.Scan() = false, want config message")
	}
	var msg IPCMessage
	if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if msg.Type != "config" || len(msg.Rules) != 1 || msg.Rules[0].ID != 12 {
		t.Fatalf("config message = %#v, want config for rule 12", msg)
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleWorkerConn() did not exit")
	}
}
