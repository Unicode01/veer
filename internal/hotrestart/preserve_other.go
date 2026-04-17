//go:build !linux

package hotrestart

func ShouldPreserveOnClose(markerPath string) bool {
	_ = markerPath
	return false
}
