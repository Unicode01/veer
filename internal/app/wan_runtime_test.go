package app

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestWANRuntimeHelperProcess(t *testing.T) {
	if os.Getenv("FORWARD_WAN_RUNTIME_HELPER") != "1" {
		return
	}
	if len(os.Args) == 0 {
		os.Exit(2)
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) > 0 {
		args = args[1:]
	}
	if len(args) >= 3 && args[0] == "uci" && args[1] == "-q" && args[2] == "delete" {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestRunWANCommandsIgnoresOptionalUCIDeleteFailure(t *testing.T) {
	oldExec := execCommandContextForWANRuntime
	execCommandContextForWANRuntime = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmdArgs := append([]string{"-test.run=TestWANRuntimeHelperProcess", "--", name}, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], cmdArgs...)
		cmd.Env = append(os.Environ(), "FORWARD_WAN_RUNTIME_HELPER=1")
		return cmd
	}
	t.Cleanup(func() {
		execCommandContextForWANRuntime = oldExec
	})

	result, err := runWANCommands([][]string{
		optionalUCIDeleteCommand("wan", "gateway"),
		{"uci", "set", "network.wan.proto=dhcp"},
	})
	if err != nil {
		t.Fatalf("runWANCommands() error = %v result=%+v", err, result)
	}
}

func TestApplyWANProfileOpenWrtCleansStaleModeOptions(t *testing.T) {
	oldLookPath := execLookPathForWANRuntime
	oldExec := execCommandContextForWANRuntime
	var commands [][]string
	execLookPathForWANRuntime = func(name string) (string, error) {
		return "/bin/" + name, nil
	}
	execCommandContextForWANRuntime = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		commands = append(commands, append([]string{name}, args...))
		cmdArgs := append([]string{"-test.run=TestWANRuntimeHelperProcess", "--", name}, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], cmdArgs...)
		cmd.Env = append(os.Environ(), "FORWARD_WAN_RUNTIME_HELPER=1")
		return cmd
	}
	t.Cleanup(func() {
		execLookPathForWANRuntime = oldLookPath
		execCommandContextForWANRuntime = oldExec
	})

	result, err := applyWANProfileOpenWrt(WANProfile{
		Name:            "wan",
		Type:            wanProfileTypeDHCP,
		ParentInterface: "eth1",
		DefaultRoute:    true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("applyWANProfileOpenWrt() error = %v result=%+v", err, result)
	}

	want := []string{
		"uci -q delete network.wan.ipaddr",
		"uci -q delete network.wan.netmask",
		"uci -q delete network.wan.gateway",
		"uci -q delete network.wan.dns",
		"uci set network.wan.proto=dhcp",
		"ifup wan",
	}
	for _, expected := range want {
		if !commandLogContains(commands, expected) {
			t.Fatalf("commands missing %q in:\n%s", expected, commandLogString(commands))
		}
	}
}

func commandLogContains(commands [][]string, expected string) bool {
	target := strings.Fields(expected)
	for _, command := range commands {
		if reflect.DeepEqual(command, target) {
			return true
		}
	}
	return false
}

func commandLogString(commands [][]string) string {
	lines := make([]string, 0, len(commands))
	for _, command := range commands {
		lines = append(lines, strings.Join(command, " "))
	}
	return strings.Join(lines, "\n")
}
