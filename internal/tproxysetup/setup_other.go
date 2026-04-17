//go:build !linux

package tproxysetup

func EnsureRouting() {}

func CleanupRouting() {}
