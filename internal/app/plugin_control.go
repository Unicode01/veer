package app

import (
	"fmt"
	"os"
	"path/filepath"
)

func resolvePluginControl(plugin *LoadedPlugin) error {
	if plugin == nil || plugin.Control == nil || plugin.Control.Main == "" {
		return nil
	}
	mainPath := filepath.Join(plugin.rootDir, filepath.FromSlash(plugin.Control.Main))
	cleanRoot, err := filepath.Abs(plugin.rootDir)
	if err != nil {
		return fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return fmt.Errorf("resolve plugin root: %w", err)
	}
	cleanMain, err := filepath.Abs(mainPath)
	if err != nil {
		return fmt.Errorf("resolve control.main: %w", err)
	}
	if !pathWithinRoot(cleanRoot, cleanMain) {
		return fmt.Errorf("control.main escapes plugin root")
	}
	realMain, err := filepath.EvalSymlinks(cleanMain)
	if err != nil {
		return fmt.Errorf("control.main: %w", err)
	}
	if !pathWithinRoot(realRoot, realMain) {
		return fmt.Errorf("control.main escapes plugin root")
	}
	info, err := os.Stat(realMain)
	if err != nil {
		return fmt.Errorf("control.main: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("control.main is a directory")
	}
	if info.Size() > pluginControlMaxSize {
		return fmt.Errorf("control.main exceeds %d bytes", pluginControlMaxSize)
	}
	plugin.controlMainPath = realMain
	return nil
}

func pluginControlHasPermission(plugin LoadedPlugin, permission string) bool {
	if plugin.Control == nil {
		return false
	}
	for _, value := range plugin.Control.Permissions {
		if value == permission {
			return true
		}
	}
	return false
}
