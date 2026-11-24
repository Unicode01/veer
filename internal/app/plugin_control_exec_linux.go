package app

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func pluginExecEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
}

func configurePluginExecCommand(command *exec.Cmd) func() {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.Cancel = kill
	// Run has reaped the command by the time this cleanup runs, so its PID
	// may have been handed out again, but only once its group was gone. A
	// process with that PID therefore means there is nothing of ours to kill.
	return func() {
		if command.Process != nil && !pluginPIDInUse(command.Process.Pid) {
			_ = kill()
		}
	}
}

// pluginPIDInUse reports whether a process with this PID exists.
func pluginPIDInUse(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
