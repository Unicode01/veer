//go:build linux

package app

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPluginHostSeccompFilterRejectsForeignABIAndBlockedSyscalls(t *testing.T) {
	filters, err := pluginHostSeccompFilters(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	auditArch, ok := pluginHostAuditArchitecture(runtime.GOARCH)
	if !ok {
		t.Fatalf("missing audit architecture for %s", runtime.GOARCH)
	}
	wantDenied := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	if got := evaluatePluginHostSeccompFilter(t, filters, uint32(unix.SYS_SOCKET), auditArch); got != wantDenied {
		t.Fatalf("socket result = %#x, want %#x", got, wantDenied)
	}
	if got := evaluatePluginHostSeccompFilter(t, filters, uint32(unix.SYS_READ), auditArch); got != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("read result = %#x, want allow", got)
	}
	if got := evaluatePluginHostSeccompFilter(t, filters, uint32(unix.SYS_READ), auditArch^1); got != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatalf("foreign architecture result = %#x, want kill", got)
	}
	if runtime.GOARCH == "amd64" {
		if got := evaluatePluginHostSeccompFilter(t, filters, uint32(unix.SYS_SOCKET)|0x40000000, auditArch); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("x32 syscall result = %#x, want kill", got)
		}
	}
}

func evaluatePluginHostSeccompFilter(t *testing.T, filters []unix.SockFilter, syscallNumber, auditArch uint32) uint32 {
	t.Helper()
	var accumulator uint32
	for pc := 0; pc >= 0 && pc < len(filters); {
		instruction := filters[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch instruction.K {
			case 0:
				accumulator = syscallNumber
			case 4:
				accumulator = auditArch
			default:
				t.Fatalf("unsupported seccomp load offset %d", instruction.K)
			}
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == instruction.K {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			if accumulator >= instruction.K {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatalf("unsupported seccomp instruction %#x", instruction.Code)
		}
	}
	t.Fatal("seccomp filter terminated without a return")
	return 0
}
