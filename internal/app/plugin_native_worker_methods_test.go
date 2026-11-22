package app

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// The worker's method table and pluginNativeWorkerMethods describe the same
// set: the contract advertises it and tests check those calls stay local.
func TestPluginNativeWorkerMethodsMatchWorkerTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "sdk", "native", "worker", "src", "local", "mod.rs"))
	if err != nil {
		t.Fatal(err)
	}
	var table []string
	for _, match := range regexp.MustCompile(`(?m)^\s*"([a-zA-Z0-9.]+)" =>`).FindAllStringSubmatch(string(data), -1) {
		table = append(table, match[1])
	}
	slices.Sort(table)
	want := slices.Clone(pluginNativeWorkerMethods)
	slices.Sort(want)
	if !slices.Equal(table, want) {
		t.Fatalf("worker table %v, pluginNativeWorkerMethods %v", table, want)
	}
	for _, method := range want {
		if !slices.Contains(pluginHostControlMethods, method) {
			t.Errorf("%s is served by the worker but is not a host control method", method)
		}
	}
}
