package ipcmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Check struct {
	Available bool
	Reason    string
}

type ProbeResult struct {
	Path      string
	Command   Check
	RuleShow  Check
	RouteShow Check
}

var (
	commandCandidates = []string{"ip", "/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"}
	commandOutput     = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
)

func Run(args ...string) error {
	_, _, err := runAny(commandCandidates, args...)
	return err
}

func Output(args ...string) ([]byte, error) {
	_, out, err := runAny(commandCandidates, args...)
	return out, err
}

func Probe() ProbeResult {
	result := ProbeResult{}
	path, err := resolveAny(commandCandidates)
	if err != nil {
		result.Command = Check{Reason: err.Error()}
		result.RuleShow = Check{Reason: "ip command unavailable"}
		result.RouteShow = Check{Reason: "ip command unavailable"}
		return result
	}
	result.Path = path
	result.Command = Check{Available: true}

	if _, err := Output("rule", "show"); err != nil {
		result.RuleShow = Check{Reason: err.Error()}
	} else {
		result.RuleShow = Check{Available: true}
	}
	if _, err := Output("route", "show"); err != nil {
		result.RouteShow = Check{Reason: err.Error()}
	} else {
		result.RouteShow = Check{Available: true}
	}
	return result
}

func SetCandidatesForTest(candidates []string) func() {
	old := append([]string(nil), commandCandidates...)
	commandCandidates = append([]string(nil), candidates...)
	return func() {
		commandCandidates = old
	}
}

func SetCommandOutputForTest(fn func(name string, args ...string) ([]byte, error)) func() {
	old := commandOutput
	commandOutput = fn
	return func() {
		commandOutput = old
	}
}

func runAny(candidates []string, args ...string) (string, []byte, error) {
	var errs []error
	for _, candidate := range candidates {
		name, err := resolveCommand(candidate)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out, err := commandOutput(name, args...)
		if err == nil {
			return name, out, nil
		}
		errs = append(errs, formatCmdError(name, args, out, err))
	}
	if len(errs) == 0 {
		return "", nil, fmt.Errorf("no ip command candidates configured")
	}
	return "", nil, fmt.Errorf("no compatible ip command succeeded: %w", errors.Join(errs...))
}

func resolveAny(candidates []string) (string, error) {
	var errs []error
	for _, candidate := range candidates {
		name, err := resolveCommand(candidate)
		if err == nil {
			return name, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return "", fmt.Errorf("no ip command candidates configured")
	}
	return "", fmt.Errorf("no ip command candidate found: %w", errors.Join(errs...))
}

func resolveCommand(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("empty command candidate")
	}
	if strings.ContainsAny(name, `/\`) {
		if info, err := os.Stat(name); err == nil && !info.IsDir() {
			return name, nil
		}
		return "", fmt.Errorf("%s not found", name)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH", name)
	}
	return path, nil
}

func formatCmdError(name string, args []string, out []byte, err error) error {
	output := strings.TrimSpace(string(out))
	if output == "" {
		return fmt.Errorf("%s %s: %w", commandBaseName(name), strings.Join(args, " "), err)
	}
	return fmt.Errorf("%s %s: %s (%w)", commandBaseName(name), strings.Join(args, " "), output, err)
}

func commandBaseName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	name = strings.ReplaceAll(name, "\\", "/")
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		return name[idx+1:]
	}
	return name
}
