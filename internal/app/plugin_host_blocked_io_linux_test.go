//go:build linux

package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPluginHostStoppedProcessCannotBlockDeadline(t *testing.T) {
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "stopped_host", Control: &PluginControl{Main: "control.js"}}}
	client, err := startPluginHostClient(isolatedPluginsTestConfig(&Config{}), plugin, "control", "", `exports.onAction = function () {};`, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err := unix.Kill(client.command.Process.Pid, unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	// Larger than a pipe's capacity, so the parent's request cannot finish writing.
	finished := make(chan error, 1)
	go func() {
		_, err := client.runEvent(pluginHostEventRequest{Handler: "onAction", Context: map[string]any{"data": strings.Repeat("x", 2<<20)}}, nil, time.Now().Add(150*time.Millisecond), false)
		finished <- err
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, errPluginHostProcessExited) {
			t.Fatalf("runEvent = %v", err)
		}
	case <-time.After(3 * time.Second):
		_ = client.command.Process.Kill()
		t.Fatal("SIGSTOP child blocked parent deadline")
	}
	select {
	case <-client.done:
	case <-time.After(3 * time.Second):
		t.Fatal("stopped child was not reaped")
	}
}
