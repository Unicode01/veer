//go:build linux

package app

import (
	"errors"
	"strings"
	"testing"
)

func TestPluginNetOffloadFeatureStatusRequiresEthtool(t *testing.T) {
	original := pluginHostLookPath
	t.Cleanup(func() { pluginHostLookPath = original })
	pluginHostLookPath = func(string) (string, error) { return "", errors.New("missing") }

	status := pluginNetOffloadFeatureStatus()
	if status.Available || !strings.Contains(status.Reason, "ethtool not found") {
		t.Fatalf("missing ethtool status = %+v", status)
	}

	pluginHostLookPath = func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	if status := pluginNetOffloadFeatureStatus(); !status.Available || status.Reason != "" {
		t.Fatalf("available ethtool status = %+v", status)
	}
}
