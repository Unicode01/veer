//go:build windows

package app

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pluginHostProcessRSSMax = 224 << 20

func configurePluginHostCommand(command *exec.Cmd) error {
	if command == nil {
		return fmt.Errorf("plugin host command is nil")
	}
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return nil
}

func preparePluginHostFilesystemRoot() (string, func(), error) {
	return "", func() {}, nil
}

func preparePluginHostResourceLimitRoot() error {
	return nil
}

func applyPluginHostChildSandbox() (PluginHostSandboxState, error) {
	return PluginHostSandboxState{
		Platform: "windows", Mode: "job_object", Level: "partial",
		Degraded: []string{"Windows plugin host uses a Job Object but not a restricted access token"},
	}, nil
}

func attachPluginHostResourceLimits(pid int, _ string, resourceLimits pluginHostResourceLimits) (func(), string, error) {
	if pid <= 0 {
		return func() {}, "", fmt.Errorf("invalid plugin host pid")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return func() {}, "", fmt.Errorf("create plugin host job object: %w", err)
	}
	closeJob := func() { _ = windows.CloseHandle(job) }
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
		windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	limits.BasicLimitInformation.ActiveProcessLimit = 1
	limits.ProcessMemoryLimit = uintptr(resourceLimits.ProcessRSSBytes)
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		closeJob()
		return func() {}, "", fmt.Errorf("configure plugin host job object: %w", err)
	}
	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		closeJob()
		return func() {}, "", fmt.Errorf("open plugin host process: %w", err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		closeJob()
		return func() {}, "", fmt.Errorf("assign plugin host job object: %w", err)
	}
	return closeJob, "", nil
}

func pluginHostProcessRSS(_ int) (uint64, error) {
	return 0, fmt.Errorf("plugin host RSS monitoring is unavailable on windows")
}

func pluginHostResourceLimitMode() string {
	return "job_object"
}
