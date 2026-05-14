//go:build !linux

package tproxysetup

func EnsureRouting() error { return nil }

func CleanupRouting() error { return nil }

func LastError() error { return nil }
