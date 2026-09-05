//go:build !linux

package app

func userspaceListenerLimit() int64 { return 1024 }
