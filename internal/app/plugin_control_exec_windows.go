package app

import (
	"os"
	"os/exec"
	"syscall"
)

func pluginExecEnvironment() []string {
	environment := []string{"LANG=C", "LC_ALL=C"}
	if root := os.Getenv("SystemRoot"); root != "" {
		environment = append(environment, "SystemRoot="+root, "PATH="+root+`\System32`)
	}
	return environment
}

func configurePluginExecCommand(command *exec.Cmd) func() {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	}
}
