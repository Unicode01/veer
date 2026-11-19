//go:build !linux

package app

func lookupUserspaceSecondaryUplink(string, string) bool {
	return false
}
