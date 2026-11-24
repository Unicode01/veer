package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// pluginProcessKeeperArgv0 makes the plugin worker binary run as the keeper
// (sdk/native/worker/src/keeper.rs). It is also the keeper's command line.
const pluginProcessKeeperArgv0 = "veer-process-keeper"

// pluginProcessKeeperExecutable finds the keeper: the plugin worker binary,
// embedded or next to veer.
func pluginProcessKeeperExecutable() (string, error) {
	executable, err := pluginNativeWorkerExecutable()
	if err != nil {
		return "", fmt.Errorf("process keeper: %w", err)
	}
	return executable, nil
}

// launch starts a keeper, places it in the process's resource cgroup, and only
// then lets it start the executable so that every descendant inherits the limits.
func (p *pluginManagedProcess) launch(req pluginProcessRequest, dir string) (*pluginKeeperRun, func(), error) {
	args := append([]string(nil), req.Args...)
	for i := range args {
		args[i] = strings.ReplaceAll(args[i], "{config}", filepath.Join(dir, "config"))
	}
	executable, err := pluginProcessKeeperExecutable()
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
	keeper := exec.Command(executable) // #nosec G204 -- the embedded worker.
	keeper.Args[0] = pluginProcessKeeperArgv0
	keeper.Env, keeper.Dir, keeper.ExtraFiles = pluginExecEnvironment(), "/", []*os.File{remote}
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
	cleanup := func() { run.teardown(limitCleanup) }
	if err := run.send(pluginKeeperMessage{Op: "start", Command: req.Command, Args: args, Env: pluginExecEnvironment(), Dir: dir, Stdin: req.Stdin}); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("start executable: %w", err)
	}
	if err := run.awaitStart(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("start executable: %w", err)
	}
	run.noteCoreStart()
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
	if group := run.coreGroup(); group > 0 {
		_ = syscall.Kill(-group, syscall.SIGKILL)
	}
}

// noteCoreStart records the start time of the executable the keeper reported.
// If it already exited and was reaped there is nothing to record, and its
// group is signalled as before.
func (run *pluginKeeperRun) noteCoreStart() {
	corePID, _ := run.core()
	if corePID <= 0 {
		return
	}
	ticks, err := kernelProcessStartTicks(corePID)
	if err != nil {
		return
	}
	run.mu.Lock()
	run.coreTicks = ticks
	run.mu.Unlock()
}

// coreGroup returns the executable's process group, or 0 once its PID names a
// different process. The kernel does not hand out a PID while a group still
// uses it as its ID, so the executable's group is gone by then and the number
// may lead somebody else's. A PID that names no process is still returned:
// the group may live on in the executable's children.
func (run *pluginKeeperRun) coreGroup() int {
	run.mu.Lock()
	corePID, coreTicks := run.corePID, run.coreTicks
	run.mu.Unlock()
	if corePID <= 0 {
		return 0
	}
	if coreTicks != 0 {
		if ticks, err := kernelProcessStartTicks(corePID); err == nil && ticks != coreTicks {
			return 0
		}
	}
	return corePID
}

// teardown kills the keeper and the executable's process group, waits until
// they have exited, and only then releases their resource limits.
func (run *pluginKeeperRun) teardown(releaseLimits func()) {
	run.kill()
	run.awaitGone(pluginKeeperStopGrace)
	run.awaitGroupGone(pluginKeeperStopGrace)
	releaseLimits()
}

// awaitGroupGone waits until no process in the executable's group is still
// running. A killed process acts on SIGKILL only when it leaves the kernel, so
// one in an uninterruptible sleep keeps its sockets and files a while longer.
func (run *pluginKeeperRun) awaitGroupGone(timeout time.Duration) {
	group := run.coreGroup()
	if group <= 0 {
		return
	}
	deadline := time.Now().Add(timeout)
	for pluginProcessGroupRunning(group) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

// pluginProcessGroupRunning reports whether a member of the process group has
// not exited yet. Zombies have exited: their parent, or init, reaps them.
func pluginProcessGroupRunning(pgid int) bool {
	if syscall.Kill(-pgid, 0) == syscall.ESRCH {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	group := strconv.Itoa(pgid)
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		// After the command name: state, ppid, pgrp.
		stat := string(data)
		fields := strings.Fields(stat[strings.LastIndexByte(stat, ')')+1:])
		if len(fields) >= 3 && fields[2] == group && fields[0] != "Z" && fields[0] != "X" {
			return true
		}
	}
	return false
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
	run.noteCoreStart()
	return run, msg, scanner, nil
}

// runPluginProcessKeeper serves --plugin-process-keeper, the keeper command of
// daemons from before the keeper moved into the plugin worker. Such a daemon
// starts keepers from its executable path, which names this binary once an
// upgrade has replaced the file, so until it hands over it still runs this
// command. It becomes the worker's keeper, keeping the control socket (fd 3).
func runPluginProcessKeeper() error {
	executable, err := pluginProcessKeeperExecutable()
	if err != nil {
		return err
	}
	return syscall.Exec(executable, []string{pluginProcessKeeperArgv0}, pluginExecEnvironment()) // #nosec G204 -- the embedded worker.
}
