//go:build !linux

package app

func lookupUserspaceSecondaryUplink(*userspaceUplinkRoutes, string, string) bool {
	return false
}
