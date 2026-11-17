package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// A keeper is a small veer process that owns one execution of a managed
// process. When the daemon hands it off during a hot restart it keeps the
// process running for the successor; when the daemon disappears without a
// handoff it kills the process, as the parent-death signal used to.
const (
	pluginKeeperProtocolVersion = 1
	pluginKeeperMessageLimit    = 4 << 20
	pluginKeeperStartTimeout    = 10 * time.Second
	pluginKeeperStopGrace       = 2 * time.Second
	pluginKeeperWriteTimeout    = 2 * time.Second
	pluginKeeperAdoptWait       = 90 * time.Second
)

type pluginKeeperMessage struct {
	Version   int      `json:"version,omitempty"`
	Op        string   `json:"op,omitempty"`
	Event     string   `json:"event,omitempty"`
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	Env       []string `json:"env,omitempty"`
	Dir       string   `json:"dir,omitempty"`
	Stdin     string   `json:"stdin,omitempty"`
	TimeoutMS int      `json:"timeout_ms,omitempty"`
	Name      string   `json:"name,omitempty"`
	Token     string   `json:"token,omitempty"`
	PID       int      `json:"pid,omitempty"`
	StartedAt int64    `json:"started_at,omitempty"`
	Running   bool     `json:"running,omitempty"`
	Code      int      `json:"code"`
	Stream    string   `json:"stream,omitempty"`
	Data      []byte   `json:"data,omitempty"`
	Stdout    []byte   `json:"stdout,omitempty"`
	Stderr    []byte   `json:"stderr,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func newPluginKeeperScanner(conn net.Conn) *bufio.Scanner {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64<<10), pluginKeeperMessageLimit)
	return scanner
}

// pluginKeeperRun is the daemon's handle on one keeper.
type pluginKeeperRun struct {
	keeperPID int
	// keeperTicks identifies an adopted keeper, which is not our child and
	// whose PID could be reused after it exits.
	keeperTicks uint64

	mu        sync.Mutex
	conn      net.Conn
	enc       *json.Encoder
	corePID   int
	startedAt int64
	exitCode  int
	released  bool

	exited   chan struct{}
	exitOnce sync.Once
	started  chan pluginKeeperMessage
	detached chan struct{}
	// reaped closes once a keeper this daemon started has been waited for.
	// An exited but unreaped keeper still keeps its cgroup from being removed.
	reaped chan struct{}
}

func newPluginKeeperRun(conn net.Conn, keeperPID int) *pluginKeeperRun {
	return &pluginKeeperRun{
		keeperPID: keeperPID, conn: conn, enc: json.NewEncoder(conn), exitCode: -1,
		exited: make(chan struct{}), started: make(chan pluginKeeperMessage, 1), detached: make(chan struct{}, 1),
	}
}

func (run *pluginKeeperRun) send(msg pluginKeeperMessage) error {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.conn == nil || run.released {
		return fmt.Errorf("process keeper connection is closed")
	}
	msg.Version = pluginKeeperProtocolVersion
	_ = run.conn.SetWriteDeadline(time.Now().Add(pluginKeeperWriteTimeout))
	return run.enc.Encode(msg)
}

// read applies keeper events until the keeper reports the exit or the
// connection closes. A lost connection counts as an exit with code -1.
func (run *pluginKeeperRun) read(scanner *bufio.Scanner, stdout, stderr *pluginProcessLog) {
	defer run.finish(-1, false)
	for scanner.Scan() {
		var msg pluginKeeperMessage
		if json.Unmarshal(scanner.Bytes(), &msg) != nil {
			return
		}
		switch msg.Event {
		case "output":
			if msg.Stream == "stderr" {
				_, _ = stderr.Write(msg.Data)
			} else {
				_, _ = stdout.Write(msg.Data)
			}
		case "started", "error":
			select {
			case run.started <- msg:
			default:
			}
		case "detached":
			select {
			case run.detached <- struct{}{}:
			default:
			}
		case "exited":
			run.finish(msg.Code, true)
			return
		}
	}
}

func (run *pluginKeeperRun) finish(code int, reported bool) {
	run.exitOnce.Do(func() {
		run.mu.Lock()
		if reported {
			run.exitCode = code
		}
		run.mu.Unlock()
		close(run.exited)
	})
}

func (run *pluginKeeperRun) code() int {
	run.mu.Lock()
	defer run.mu.Unlock()
	return run.exitCode
}

func (run *pluginKeeperRun) core() (int, int64) {
	run.mu.Lock()
	defer run.mu.Unlock()
	return run.corePID, run.startedAt
}

// awaitStart waits for the keeper to report whether the process started. A
// process that starts and exits at once still counts as started.
func (run *pluginKeeperRun) awaitStart() error {
	timer := time.NewTimer(pluginKeeperStartTimeout)
	defer timer.Stop()
	var msg pluginKeeperMessage
	select {
	case msg = <-run.started:
	case <-run.exited:
		select {
		case msg = <-run.started:
		default:
			return fmt.Errorf("process keeper exited before starting the executable")
		}
	case <-timer.C:
		return fmt.Errorf("process keeper did not respond")
	}
	if msg.Event == "error" {
		return fmt.Errorf("%s", msg.Error)
	}
	run.mu.Lock()
	run.corePID, run.startedAt = msg.PID, msg.StartedAt
	run.mu.Unlock()
	return nil
}

// stop asks the keeper to terminate its process and waits for the exit. A
// keeper that does not answer in time is killed together with its process.
func (run *pluginKeeperRun) stop(timeout time.Duration) {
	if run.send(pluginKeeperMessage{Op: "stop", TimeoutMS: int(timeout / time.Millisecond)}) == nil {
		timer := time.NewTimer(timeout + pluginKeeperStopGrace)
		select {
		case <-run.exited:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	run.kill()
	timer := time.NewTimer(pluginKeeperStopGrace)
	defer timer.Stop()
	select {
	case <-run.exited:
	case <-timer.C:
	}
}

// detach arms the keeper to wait for a successor. Until the connection is
// released the daemon can still stop it, so a failed handoff is reversible.
func (run *pluginKeeperRun) detach(name, token string, wait time.Duration) error {
	if err := run.send(pluginKeeperMessage{Op: "detach", Name: name, Token: token, TimeoutMS: int(wait / time.Millisecond)}); err != nil {
		return err
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-run.detached:
		return nil
	case <-run.exited:
		return fmt.Errorf("process exited")
	case <-timer.C:
		return fmt.Errorf("process keeper did not acknowledge the handoff")
	}
}

// release closes the connection without stopping a handed-off keeper.
func (run *pluginKeeperRun) release() {
	run.mu.Lock()
	defer run.mu.Unlock()
	run.released = true
	if run.conn != nil {
		_ = run.conn.Close()
	}
}
