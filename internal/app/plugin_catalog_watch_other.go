//go:build !linux

package app

import "errors"

// pluginCatalogWatcher is Linux-only; elsewhere the update monitor scans the
// plugin directory on its timer.
type pluginCatalogWatcher struct{ root string }

func openPluginCatalogWatcher(string) (*pluginCatalogWatcher, error) {
	return nil, errors.New("plugin directory watch is not supported on this platform")
}

func (w *pluginCatalogWatcher) takeChange() bool { return false }

func (w *pluginCatalogWatcher) healthy() bool { return false }

func (w *pluginCatalogWatcher) Close() {}
