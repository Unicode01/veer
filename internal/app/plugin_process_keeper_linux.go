package app

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const pluginProcessKeeperTestEnv = "VEER_PLUGIN_PROCESS_KEEPER_TEST"

// pluginProcessKeeperTestMode makes the test binary re-enter itself as the
// keeper, the same way isolated plugin-host tests do.
var pluginProcessKeeperTestMode bool

func pluginProcessKeeperInvocation() (string, []string, []string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", nil, nil, fmt.Errorf("resolve process keeper executable: %w", err)
	}
	if pluginProcessKeeperTestMode {
		return executable, []string{"-test.run=^TestPluginProcessKeeperEntrypoint$"},
			append(pluginExecEnvironment(), pluginProcessKeeperTestEnv+"=1"), nil
	}
	return executable, []string{"--plugin-process-keeper"}, pluginExecEnvironment(), nil
}

// launch starts a keeper, places it in the process's resource cgroup, and only
// then lets it start the executable so that every descendant inherits the limits.
func (p *pluginManagedProcess) launch(req pluginProcessRequest, dir string) (*pluginKeeperRun, func(), error) {
	args := append([]string(nil), req.Args...)
	for i := range args {
		args[i] = strings.ReplaceAll(args[i], "{config}", filepath.Join(dir, "config"))
	}
	executable, keeperArgs, keeperEnv, err := pluginProcessKeeperInvocation()
	if err != nil {
		return nil, nil, err
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create process keeper channel: %w", err)
	}
	local, remote := os.NewFile(uintptr(pair[0]), "process-keeper"), os.NewFile(uintptr(pair[1]), "process-keeper")
	defer remote.Close()
	conn, err := net.FileConn(local)
	_ = local.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("open process keeper channel: %w", err)
	}
	keeper := exec.Command(executable, keeperArgs...) // #nosec G204 -- re-executes this binary.
	keeper.Env, keeper.Dir, keeper.ExtraFiles = keeperEnv, "/", []*os.File{remote}
	keeper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := keeper.Start(); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("start process keeper: %w", err)
	}
	_ = remote.Close()
	run := newPluginKeeperRun(conn, keeper.Process.Pid)
	run.reaped = make(chan struct{})
	go func() {
		_ = keeper.Wait()
		close(run.reaped)
	}()
	go run.read(newPluginKeeperScanner(conn), &p.stdout, &p.stderr)
	limitCleanup, err := limitPluginManagedProcess(keeper.Process.Pid, p.limitOwner, p.limitConfig)
	if err != nil {
		run.kill()
		_ = conn.Close()
		return nil, nil, err
	}
	cleanup := func() {
		run.kill()
		run.awaitGone(pluginKeeperStopGrace)
		limitCleanup()
	}
	if err := run.send(pluginKeeperMessage{Op: "start", Command: req.Command, Args: args, Env: pluginExecEnvironment(), Dir: dir, Stdin: req.Stdin}); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("start executable: %w", err)
	}
	if err := run.awaitStart(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("start executable: %w", err)
	}
	corePID, startedAt := run.core()
	p.mu.Lock()
	p.run = run
	p.status.State, p.status.PID, p.status.ExitCode = "running", corePID, -1
	p.status.Starts++
	p.status.StartedAt = startedAt
	p.mu.Unlock()
	return run, cleanup, nil
}

// kill stops the keeper and the process group of its executable. An adopted
// keeper is only signalled while its PID still names the same process.
func (run *pluginKeeperRun) kill() {
	if run.keeperPID > 0 {
		if run.keeperTicks == 0 {
			_ = syscall.Kill(-run.keeperPID, syscall.SIGKILL)
		} else if ticks, err := kernelProcessStartTicks(run.keeperPID); err == nil && ticks == run.keeperTicks {
			_ = syscall.Kill(-run.keeperPID, syscall.SIGKILL)
		}
	}
	if corePID, _ := run.core(); corePID > 0 {
		_ = syscall.Kill(-corePID, syscall.SIGKILL)
	}
}

// awaitGone waits until the keeper no longer exists, so its cgroup can go.
// An adopted keeper is reaped by init rather than by this daemon.
func (run *pluginKeeperRun) awaitGone(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	if run.reaped != nil {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-run.reaped:
		case <-timer.C:
		}
		return
	}
	for time.Now().Before(deadline) {
		if ticks, err := kernelProcessStartTicks(run.keeperPID); err != nil || ticks != run.keeperTicks {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// dialPluginKeeper attaches to a keeper handed off by the previous daemon.
func dialPluginKeeper(name, token string, keeperPID int, keeperTicks uint64) (*pluginKeeperRun, pluginKeeperMessage, *bufio.Scanner, error) {
	conn, err := net.DialTimeout("unix", "@"+name, 2*time.Second)
	if err != nil {
		return nil, pluginKeeperMessage{}, nil, err
	}
	run := newPluginKeeperRun(conn, keeperPID)
	run.keeperTicks = keeperTicks
	if err := run.send(pluginKeeperMessage{Op: "attach", Token: token}); err != nil {
		_ = conn.Close()
		return nil, pluginKeeperMessage{}, nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	scanner := newPluginKeeperScanner(conn)
	var msg pluginKeeperMessage
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &msg) != nil || msg.Event != "attached" || msg.Version != pluginKeeperProtocolVersion {
		_ = conn.Close()
		return nil, pluginKeeperMessage{}, nil, fmt.Errorf("process keeper did not accept the attachment")
	}
	_ = conn.SetReadDeadline(time.Time{})
	run.mu.Lock()
	run.corePID, run.startedAt = msg.PID, msg.StartedAt
	run.mu.Unlock()
	return run, msg, scanner, nil
}

type pluginKeeper struct {
	mu        sync.Mutex
	link      *pluginKeeperLink
	stdout    pluginProcessLog
	stderr    pluginProcessLog
	pid       int
	startedAt int64
	exitCode  int
	token     string
	adoptWait time.Duration
}

type pluginKeeperOutput struct {
	keeper *pluginKeeper
	stream string
	log    *pluginProcessLog
}

// pluginKeeperOutputQueue bounds output waiting for a slow daemon. Beyond it
// output chunks are dropped from the stream, never held: a stalled daemon must
// not stall the process. The keeper's own buffer still has them.
const pluginKeeperOutputQueue = 1024

// pluginKeeperLink is one daemon connection with a single ordered writer.
type pluginKeeperLink struct {
	conn    net.Conn
	out     chan pluginKeeperMessage
	flushed chan struct{}
}

func newPluginKeeperLink(conn net.Conn) *pluginKeeperLink {
	link := &pluginKeeperLink{conn: conn, out: make(chan pluginKeeperMessage, pluginKeeperOutputQueue), flushed: make(chan struct{})}
	go func() {
		defer close(link.flushed)
		enc := json.NewEncoder(conn)
		for msg := range link.out {
			if enc.Encode(msg) != nil {
				// The reader sees the closed connection and handles it as a loss.
				_ = conn.Close()
				for range link.out {
				}
				return
			}
		}
	}()
	return link
}

// Write records output in the keeper's own buffer and queues it for an
// attached daemon under one lock, so an attachment snapshot never duplicates
// or misses a chunk. Output is kept, not blocked, while nobody is attached.
func (w pluginKeeperOutput) Write(data []byte) (int, error) {
	w.keeper.mu.Lock()
	defer w.keeper.mu.Unlock()
	_, _ = w.log.Write(data)
	w.keeper.sendLocked(pluginKeeperMessage{Event: "output", Stream: w.stream, Data: append([]byte(nil), data...)}, false)
	return len(data), nil
}

func (k *pluginKeeper) send(msg pluginKeeperMessage) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sendLocked(msg, true)
}

// sendLocked queues a message for the attached daemon. Control messages wait
// for queue space; the writer never takes the keeper lock, so this cannot
// deadlock, and a failed writer drains its queue.
func (k *pluginKeeper) sendLocked(msg pluginKeeperMessage, required bool) {
	if k.link == nil {
		return
	}
	msg.Version = pluginKeeperProtocolVersion
	if required {
		k.link.out <- msg
		return
	}
	select {
	case k.link.out <- msg:
	default:
	}
}

func (k *pluginKeeper) dropLinkLocked() {
	if k.link != nil {
		close(k.link.out)
		_ = k.link.conn.Close()
		k.link = nil
	}
}

// flush delivers what is queued before the keeper exits.
func (k *pluginKeeper) flush() {
	k.mu.Lock()
	link := k.link
	k.link = nil
	if link != nil {
		close(link.out)
	}
	k.mu.Unlock()
	if link == nil {
		return
	}
	timer := time.NewTimer(pluginKeeperWriteTimeout)
	defer timer.Stop()
	select {
	case <-link.flushed:
	case <-timer.C:
	}
	_ = link.conn.Close()
}

func (k *pluginKeeper) connected(conn net.Conn) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.link != nil && k.link.conn == conn
}

// runPluginProcessKeeper is the keeper's entry point: --plugin-process-keeper.
func runPluginProcessKeeper() error {
	// The executable's parent-death signal follows the thread that forked it.
	runtime.LockOSThread()
	control := os.NewFile(3, "process-keeper")
	if control == nil {
		return fmt.Errorf("process keeper channel is missing")
	}
	conn, err := net.FileConn(control)
	_ = control.Close()
	if err != nil {
		return fmt.Errorf("open process keeper channel: %w", err)
	}
	k := &pluginKeeper{link: newPluginKeeperLink(conn), exitCode: -1}
	defer k.flush()
	scanner := newPluginKeeperScanner(conn)
	_ = conn.SetReadDeadline(time.Now().Add(pluginKeeperStartTimeout))
	var start pluginKeeperMessage
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &start) != nil || start.Op != "start" || start.Version != pluginKeeperProtocolVersion {
		return fmt.Errorf("invalid start request")
	}
	_ = conn.SetReadDeadline(time.Time{})
	cmd := exec.Command(start.Command, start.Args...) // #nosec G204 -- the daemon validated the request.
	cmd.Env, cmd.Dir, cmd.Stdin = start.Env, start.Dir, strings.NewReader(start.Stdin)
	cmd.Stdout = pluginKeeperOutput{keeper: k, stream: "stdout", log: &k.stdout}
	cmd.Stderr = pluginKeeperOutput{keeper: k, stream: "stderr", log: &k.stderr}
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		k.send(pluginKeeperMessage{Event: "error", Error: err.Error()})
		return nil
	}
	k.pid, k.startedAt = cmd.Process.Pid, time.Now().UnixMilli()
	k.send(pluginKeeperMessage{Event: "started", PID: k.pid, StartedAt: k.startedAt})
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		k.mu.Lock()
		k.exitCode = cmd.ProcessState.ExitCode()
		k.mu.Unlock()
		// Reap descendants even if the leader exited on its own.
		_ = syscall.Kill(-k.pid, syscall.SIGKILL)
		close(done)
	}()
	k.serve(conn, scanner, done)
	return nil
}

func (k *pluginKeeper) serve(conn net.Conn, scanner *bufio.Scanner, done <-chan struct{}) {
	ops := make(chan pluginKeeperMessage)
	lost := make(chan net.Conn, 2)
	go readPluginKeeperOps(conn, scanner, ops, lost)
	exited := done
	var listener net.Listener
	var accepted chan net.Conn
	var adoptDeadline <-chan time.Time
	defer func() {
		if listener != nil {
			_ = listener.Close()
		}
	}()
	coreExited := false
	for {
		select {
		case <-exited:
			exited, coreExited = nil, true
			if k.reportExit() || listener == nil {
				return
			}
			// Keep the exit for a successor that is still coming.
		case msg := <-ops:
			switch msg.Op {
			case "stop":
				if !coreExited {
					k.terminate(time.Duration(msg.TimeoutMS)*time.Millisecond, done)
				}
				k.reportExit()
				return
			case "detach":
				if listener != nil {
					_ = listener.Close()
				}
				var err error
				listener, err = net.Listen("unix", "@"+msg.Name)
				if err != nil {
					listener = nil
					continue
				}
				k.mu.Lock()
				k.token, k.adoptWait = msg.Token, time.Duration(msg.TimeoutMS)*time.Millisecond
				k.mu.Unlock()
				k.send(pluginKeeperMessage{Event: "detached"})
			}
		case gone := <-lost:
			if !k.connected(gone) {
				continue
			}
			k.mu.Lock()
			k.dropLinkLocked()
			wait := k.adoptWait
			k.mu.Unlock()
			if listener == nil {
				// The daemon vanished without a handoff: behave as a dead parent.
				_ = syscall.Kill(-k.pid, syscall.SIGKILL)
				<-done
				return
			}
			accepted = make(chan net.Conn, 1)
			go k.accept(listener, accepted)
			adoptDeadline = time.After(wait)
		case next := <-accepted:
			_ = listener.Close()
			listener, accepted, adoptDeadline = nil, nil, nil
			k.attach(next, coreExited)
			if coreExited {
				return
			}
			go readPluginKeeperOps(next, newPluginKeeperScanner(next), ops, lost)
		case <-adoptDeadline:
			_ = syscall.Kill(-k.pid, syscall.SIGKILL)
			<-done
			return
		}
	}
}

func readPluginKeeperOps(conn net.Conn, scanner *bufio.Scanner, ops chan<- pluginKeeperMessage, lost chan<- net.Conn) {
	defer func() { lost <- conn }()
	for scanner.Scan() {
		var msg pluginKeeperMessage
		if json.Unmarshal(scanner.Bytes(), &msg) != nil || msg.Version != pluginKeeperProtocolVersion {
			return
		}
		ops <- msg
		if msg.Op == "stop" {
			return
		}
	}
}

func (k *pluginKeeper) terminate(timeout time.Duration, done <-chan struct{}) {
	_ = syscall.Kill(-k.pid, syscall.SIGTERM)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		_ = syscall.Kill(-k.pid, syscall.SIGKILL)
		<-done
	}
}

// reportExit tells an attached daemon about the exit and reports whether one
// was attached to hear it.
func (k *pluginKeeper) reportExit() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.link == nil {
		return false
	}
	k.sendLocked(pluginKeeperMessage{Event: "exited", Code: k.exitCode}, true)
	return true
}

// accept admits only a successor that runs as the same user and presents the
// token from the handoff file; anything else in the network namespace could
// otherwise reach the abstract socket.
func (k *pluginKeeper) accept(listener net.Listener, accepted chan<- net.Conn) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if k.verifyAttach(conn) {
			accepted <- conn
			return
		}
		_ = conn.Close()
	}
}

func (k *pluginKeeper) verifyAttach(conn net.Conn) bool {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil || int(cred.Uid) != os.Geteuid() {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	line, err := bufio.NewReaderSize(conn, 4096).ReadSlice('\n')
	if err != nil {
		return false
	}
	var msg pluginKeeperMessage
	if json.Unmarshal(line, &msg) != nil || msg.Op != "attach" || msg.Version != pluginKeeperProtocolVersion {
		return false
	}
	k.mu.Lock()
	token := k.token
	k.mu.Unlock()
	return token != "" && subtle.ConstantTimeCompare([]byte(msg.Token), []byte(token)) == 1
}

// attach switches output to the successor and sends everything it missed.
func (k *pluginKeeper) attach(conn net.Conn, exited bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	stdout, outTruncated := k.stdout.snapshot()
	stderr, errTruncated := k.stderr.snapshot()
	k.link, k.token = newPluginKeeperLink(conn), ""
	k.sendLocked(pluginKeeperMessage{Event: "attached", PID: k.pid, StartedAt: k.startedAt, Running: !exited, Code: k.exitCode,
		Stdout: []byte(stdout), Stderr: []byte(stderr), Truncated: outTruncated || errTruncated}, true)
}
