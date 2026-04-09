//go:build !linux

package app

func newIPv6AssignmentRuntime() ipv6AssignmentRuntime {
	return nil
}
