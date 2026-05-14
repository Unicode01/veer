package ipcmd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestOutputFallsBackAcrossCandidates(t *testing.T) {
	dir := t.TempDir()
	bad := fakeCommandPath(t, dir, "ip-bad")
	good := fakeCommandPath(t, dir, "ip-good")
	defer SetCandidatesForTest([]string{bad, good})()

	badAttempts := 0
	defer SetCommandOutputForTest(func(name string, args ...string) ([]byte, error) {
		switch filepath.Base(name) {
		case "ip-bad":
			badAttempts++
			return []byte("unsupported"), errors.New("exit status 1")
		case "ip-good":
			if !slices.Equal(args, []string{"rule", "show"}) {
				t.Fatalf("args = %#v, want rule show", args)
			}
			return []byte("0: from all lookup local\n"), nil
		default:
			t.Fatalf("unexpected command %q", name)
			return nil, errors.New("unexpected command")
		}
	})()

	out, err := Output("rule", "show")
	if err != nil {
		t.Fatalf("Output() error = %v", err)
	}
	if string(out) != "0: from all lookup local\n" {
		t.Fatalf("Output() = %q", string(out))
	}
	if badAttempts != 1 {
		t.Fatalf("bad attempts = %d, want 1", badAttempts)
	}
}

func TestProbeReportsRouteCommandSupport(t *testing.T) {
	dir := t.TempDir()
	ip := fakeCommandPath(t, dir, "ip")
	defer SetCandidatesForTest([]string{ip})()
	defer SetCommandOutputForTest(func(name string, args ...string) ([]byte, error) {
		switch {
		case slices.Equal(args, []string{"rule", "show"}):
			return []byte("rules"), nil
		case slices.Equal(args, []string{"route", "show"}):
			return []byte("routes"), nil
		default:
			t.Fatalf("unexpected args %#v", args)
			return nil, errors.New("unexpected command")
		}
	})()

	probe := Probe()
	if !probe.Command.Available || !probe.RuleShow.Available || !probe.RouteShow.Available {
		t.Fatalf("Probe() = %+v, want available checks", probe)
	}
	if filepath.Base(probe.Path) != "ip" {
		t.Fatalf("Probe().Path = %q, want fake ip path", probe.Path)
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
