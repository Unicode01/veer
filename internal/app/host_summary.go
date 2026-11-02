package app

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Host metadata is best effort: unavailable platform fields are omitted.
func currentHostSummary() HostSummary {
	name, _ := os.Hostname()
	host := HostSummary{Name: name, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			host.KernelRelease = strings.TrimSpace(string(data))
		}
		if data, err := os.ReadFile("/proc/uptime"); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) > 0 {
				if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil && seconds >= 0 {
					host.UptimeSeconds = &seconds
				}
			}
		}
	}
	return host
}
