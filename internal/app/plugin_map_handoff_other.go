//go:build !linux

package app

func handOffPluginStateMapsForHotRestart(...any) error { return nil }

func releasePluginMapHandoff() {}
