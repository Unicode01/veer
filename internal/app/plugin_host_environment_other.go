//go:build !linux

package app

func currentPluginKernelRelease() string {
	return ""
}
