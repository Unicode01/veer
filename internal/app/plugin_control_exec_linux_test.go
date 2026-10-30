package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPluginExecCleansChildProcessGroup(t *testing.T) {
	for _, wait := range []bool{false, true} {
		t.Run(map[bool]string{false: "command exited", true: "timeout"}[wait], func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "leaked-child")
			script := `(sleep 0.6; echo leaked > "$1") &`
			if wait {
				script += " wait"
			}
			request := pluginExecRequest{Command: "/bin/sh", Args: []string{"-c", script, "exec-test", marker}}
			result, err := runPluginExec(request, 150*time.Millisecond, nil)
			if err != nil {
				t.Fatal(err)
			}
			if wait && !result.TimedOut {
				t.Fatalf("expected timeout: %+v", result)
			}
			if !wait && !result.Truncated && !result.TimedOut {
				t.Fatal("closing inherited output pipes must report incomplete output")
			}
			time.Sleep(700 * time.Millisecond)
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("child survived command cleanup: %v", err)
			}
		})
	}
}
