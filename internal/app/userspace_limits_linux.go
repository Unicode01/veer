//go:build linux

package app

import "golang.org/x/sys/unix"

func userspaceListenerLimit() int64 {
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) == nil && limit.Cur/8 < 1024 {
		if limit.Cur < 8 {
			return 1
		}
		return int64(limit.Cur / 8)
	}
	return 1024
}
