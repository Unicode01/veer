//go:build linux

package tproxysetup

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"forward/internal/ipcmd"
)

func TestEnsureRoutingFallsBackAcrossCommandCandidates(t *testing.T) {
	dir := t.TempDir()
	ip := fakeCommandPath(t, dir, "ip")
	iptablesBad := fakeCommandPath(t, dir, "iptables-bad")
	iptablesGood := fakeCommandPath(t, dir, "iptables-good")
	resetTransparentTestState(t, []string{ip}, []string{iptablesBad, iptablesGood})

	goodAdds := 0
	badAttempts := 0
	commandOutput = func(name string, args ...string) ([]byte, error) {
		switch filepath.Base(name) {
		case "ip":
			return nil, nil
		case "iptables-bad":
			badAttempts++
			return []byte("socket match unavailable"), errors.New("exit status 1")
		case "iptables-good":
			if slices.Contains(args, "-C") {
				return []byte("rule does not exist"), errors.New("exit status 1")
			}
			if slices.Contains(args, "-A") {
				goodAdds++
				return nil, nil
			}
		}
		return nil, errors.New("unexpected command")
	}

	if err := EnsureRouting(); err != nil {
		t.Fatalf("EnsureRouting() error = %v", err)
	}
	if !transparentSetupDone {
		t.Fatal("transparentSetupDone = false, want true")
	}
	if badAttempts == 0 {
		t.Fatal("bad iptables candidate was not attempted")
	}
	if goodAdds != 2 {
		t.Fatalf("good iptables add count = %d, want 2", goodAdds)
	}
}

func TestEnsureRoutingFailureDoesNotMarkSetupDone(t *testing.T) {
	dir := t.TempDir()
	ip := fakeCommandPath(t, dir, "ip")
	iptables := fakeCommandPath(t, dir, "iptables")
	resetTransparentTestState(t, []string{ip}, []string{iptables})

	allowIptablesAdd := false
	addAttempts := 0
	commandOutput = func(name string, args ...string) ([]byte, error) {
		switch filepath.Base(name) {
		case "ip":
			return nil, nil
		case "iptables":
			if slices.Contains(args, "-C") {
				return []byte("rule does not exist"), errors.New("exit status 1")
			}
			if slices.Contains(args, "-A") {
				addAttempts++
				if !allowIptablesAdd {
					return []byte("socket match unavailable"), errors.New("exit status 1")
				}
				return nil, nil
			}
		}
		return nil, errors.New("unexpected command")
	}

	if err := EnsureRouting(); err == nil {
		t.Fatal("EnsureRouting() error = nil, want setup failure")
	}
	if transparentSetupDone {
		t.Fatal("transparentSetupDone = true after failure")
	}
	if LastError() == nil {
		t.Fatal("LastError() = nil after failure")
	}

	allowIptablesAdd = true
	if err := EnsureRouting(); err != nil {
		t.Fatalf("EnsureRouting() retry error = %v", err)
	}
	if !transparentSetupDone {
		t.Fatal("transparentSetupDone = false after retry")
	}
	if LastError() != nil {
		t.Fatalf("LastError() after retry = %v, want nil", LastError())
	}
	if addAttempts < 4 {
		t.Fatalf("iptables add attempts = %d, want retry attempts", addAttempts)
	}
}

func TestEnsureRoutingFailureRollsBackOwnedIPState(t *testing.T) {
	dir := t.TempDir()
	ip := fakeCommandPath(t, dir, "ip")
	resetTransparentTestState(t, []string{ip}, []string{})

	var commands []string
	commandOutput = func(name string, args ...string) ([]byte, error) {
		commands = append(commands, filepath.Base(name)+" "+strings.Join(args, " "))
		switch filepath.Base(name) {
		case "ip":
			if slices.Equal(args, []string{"rule", "show"}) || slices.Equal(args, []string{"route", "show", "table", tproxyTable}) {
				return nil, nil
			}
			return nil, nil
		}
		return nil, errors.New("unexpected command")
	}

	if err := EnsureRouting(); err == nil {
		t.Fatal("EnsureRouting() error = nil, want iptables setup failure")
	}
	if transparentSetupDone {
		t.Fatal("transparentSetupDone = true after failure")
	}
	if transparentSetupDirty {
		t.Fatal("transparentSetupDirty = true after rollback")
	}
	if LastError() == nil {
		t.Fatal("LastError() = nil after failure")
	}

	joined := strings.Join(commands, "\n")
	for _, want := range []string{
		"ip rule add fwmark " + tproxyMark + " lookup " + tproxyTable,
		"ip route replace local 0.0.0.0/0 dev lo table " + tproxyTable,
		"ip route del local 0.0.0.0/0 dev lo table " + tproxyTable,
		"ip rule del fwmark " + tproxyMark + " lookup " + tproxyTable,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands = %q, missing %q", joined, want)
		}
	}
}

func fakeCommandPath(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func resetTransparentTestState(t *testing.T, ipCandidates []string, iptablesCandidates []string) {
	t.Helper()
	oldDone := transparentSetupDone
	oldDirty := transparentSetupDirty
	oldErr := transparentLastError
	oldRuleOwned := transparentRuleOwned
	oldRouteOwned := transparentRouteOwned
	oldTCPOwned := transparentTCPOwned
	oldUDPOwned := transparentUDPOwned
	oldIPTablesCandidates := append([]string(nil), iptablesCommandCandidates...)
	oldCommandOutput := commandOutput
	restoreIPCandidates := ipcmd.SetCandidatesForTest(ipCandidates)
	restoreIPOutput := ipcmd.SetCommandOutputForTest(func(name string, args ...string) ([]byte, error) {
		return commandOutput(name, args...)
	})

	transparentSetupDone = false
	transparentSetupDirty = false
	transparentLastError = nil
	transparentRuleOwned = false
	transparentRouteOwned = false
	transparentTCPOwned = false
	transparentUDPOwned = false
	iptablesCommandCandidates = append([]string(nil), iptablesCandidates...)
	commandOutput = func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("unexpected command: " + strings.Join(append([]string{name}, args...), " "))
	}

	t.Cleanup(func() {
		transparentSetupDone = oldDone
		transparentSetupDirty = oldDirty
		transparentLastError = oldErr
		transparentRuleOwned = oldRuleOwned
		transparentRouteOwned = oldRouteOwned
		transparentTCPOwned = oldTCPOwned
		transparentUDPOwned = oldUDPOwned
		iptablesCommandCandidates = oldIPTablesCandidates
		commandOutput = oldCommandOutput
		restoreIPOutput()
		restoreIPCandidates()
	})
}
