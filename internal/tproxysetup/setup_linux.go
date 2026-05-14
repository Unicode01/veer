//go:build linux

package tproxysetup

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"forward/internal/ipcmd"
)

const (
	tproxyTable = "198"
	tproxyMark  = "0x1/0x1"
)

var (
	transparentSetupDone  bool
	transparentSetupDirty bool
	transparentLastError  error
	transparentSetupMu    sync.Mutex
	transparentRuleOwned  bool
	transparentRouteOwned bool
	transparentTCPOwned   bool
	transparentUDPOwned   bool
)

var (
	iptablesCommandCandidates = []string{"iptables", "iptables-nft", "iptables-legacy", "/sbin/iptables", "/usr/sbin/iptables", "/bin/iptables", "/usr/bin/iptables"}
	commandOutput             = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
)

func EnsureRouting() error {
	transparentSetupMu.Lock()
	defer transparentSetupMu.Unlock()
	if transparentSetupDone {
		return nil
	}

	var setupErrs []error
	if !ipRuleExists() {
		if err := runIPCmd("rule", "add", "fwmark", tproxyMark, "lookup", tproxyTable); err != nil {
			setupErrs = append(setupErrs, err)
			log.Printf("transparent: ip rule add: %v", err)
		} else {
			transparentRuleOwned = true
			updateTransparentSetupDirtyLocked()
			log.Printf("transparent: added ip rule fwmark -> table %s", tproxyTable)
		}
	}

	if !ipRouteExists() {
		if err := runIPCmd("route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyTable); err != nil {
			setupErrs = append(setupErrs, err)
			log.Printf("transparent: ip route replace: %v", err)
		} else {
			transparentRouteOwned = true
			updateTransparentSetupDirtyLocked()
			log.Printf("transparent: local route in table %s ready", tproxyTable)
		}
	}

	if added, err := ensureIptablesRule("tcp"); err != nil {
		setupErrs = append(setupErrs, err)
		log.Printf("transparent: iptables tcp rule: %v", err)
	} else if added {
		transparentTCPOwned = true
		updateTransparentSetupDirtyLocked()
	}
	if added, err := ensureIptablesRule("udp"); err != nil {
		setupErrs = append(setupErrs, err)
		log.Printf("transparent: iptables udp rule: %v", err)
	} else if added {
		transparentUDPOwned = true
		updateTransparentSetupDirtyLocked()
	}

	if len(setupErrs) > 0 {
		transparentLastError = errors.Join(setupErrs...)
		log.Printf("transparent: routing setup incomplete: %v", transparentLastError)
		cleanupRoutingLocked(false)
		return transparentLastError
	}

	transparentSetupDone = true
	transparentLastError = nil
	log.Println("transparent: routing setup complete")
	return nil
}

func CleanupRouting() error {
	transparentSetupMu.Lock()
	defer transparentSetupMu.Unlock()
	if !transparentSetupDone && !transparentSetupDirty {
		return nil
	}

	cleanupRoutingLocked(true)
	log.Println("transparent: routing cleanup complete")
	return nil
}

func LastError() error {
	transparentSetupMu.Lock()
	defer transparentSetupMu.Unlock()
	return transparentLastError
}

func ipRuleExists() bool {
	out, err := ipcmd.Output("rule", "show")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "fwmark") && strings.Contains(line, tproxyMark) && strings.Contains(line, "lookup "+tproxyTable) {
			return true
		}
	}
	return false
}

func ipRouteExists() bool {
	out, err := ipcmd.Output("route", "show", "table", tproxyTable)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "local") || !strings.Contains(line, "dev lo") {
			continue
		}
		if strings.Contains(line, "default") || strings.Contains(line, "0.0.0.0/0") {
			return true
		}
	}
	return false
}

func ensureIptablesRule(proto string) (bool, error) {
	_, err := runCmdOutput(iptablesCommandCandidates, "-t", "mangle", "-C", "PREROUTING",
		"-p", proto, "-m", "socket", "--transparent",
		"-j", "MARK", "--set-mark", tproxyMark)
	if err == nil {
		return false, nil
	}
	name, err := runCmd(iptablesCommandCandidates, "-t", "mangle", "-A", "PREROUTING",
		"-p", proto, "-m", "socket", "--transparent",
		"-j", "MARK", "--set-mark", tproxyMark)
	if err != nil {
		return false, err
	}
	log.Printf("transparent: added %s mangle PREROUTING %s rule", commandBaseName(name), proto)
	return true, nil
}

func removeIptablesRule(proto string) {
	_, _ = runCmdOutput(iptablesCommandCandidates, "-t", "mangle", "-D", "PREROUTING",
		"-p", proto, "-m", "socket", "--transparent",
		"-j", "MARK", "--set-mark", tproxyMark)
}

func cleanupRoutingLocked(clearLastError bool) {
	if transparentTCPOwned {
		removeIptablesRule("tcp")
	}
	if transparentUDPOwned {
		removeIptablesRule("udp")
	}
	if transparentRouteOwned {
		_ = runIPCmd("route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyTable)
	}
	if transparentRuleOwned {
		_ = runIPCmd("rule", "del", "fwmark", tproxyMark, "lookup", tproxyTable)
	}

	transparentSetupDone = false
	transparentRuleOwned = false
	transparentRouteOwned = false
	transparentTCPOwned = false
	transparentUDPOwned = false
	updateTransparentSetupDirtyLocked()
	if clearLastError {
		transparentLastError = nil
	}
}

func updateTransparentSetupDirtyLocked() {
	transparentSetupDirty = transparentRuleOwned || transparentRouteOwned || transparentTCPOwned || transparentUDPOwned
}

func runIPCmd(args ...string) error {
	return ipcmd.Run(args...)
}

func runCmd(candidates []string, args ...string) (string, error) {
	name, out, err := runCmdAny(candidates, args...)
	if err != nil {
		return "", formatCmdError(name, args, out, err)
	}
	return name, nil
}

func runCmdOutput(candidates []string, args ...string) ([]byte, error) {
	name, out, err := runCmdAny(candidates, args...)
	if err != nil {
		return nil, formatCmdError(name, args, out, err)
	}
	return out, nil
}

func runCmdAny(candidates []string, args ...string) (string, []byte, error) {
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
		return "", nil, fmt.Errorf("no command candidates configured")
	}
	return "", nil, fmt.Errorf("no compatible command succeeded: %w", errors.Join(errs...))
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
	if strings.TrimSpace(name) == "" {
		return err
	}
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
