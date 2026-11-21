//go:build linux

package app

import (
	"errors"
	"testing"
)

// Offloads go through ethtool ioctls, so a host without the ethtool tool
// still offers them.
func TestPluginNetOffloadFeatureStatusDoesNotNeedEthtool(t *testing.T) {
	original := pluginHostLookPath
	t.Cleanup(func() { pluginHostLookPath = original })
	pluginHostLookPath = func(string) (string, error) { return "", errors.New("missing") }

	if status := pluginNetOffloadFeatureStatus(); !status.Available || status.Reason != "" {
		t.Fatalf("offload status without ethtool = %+v", status)
	}
}
