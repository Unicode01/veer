//go:build linux

package app

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func TestPluginControlNetRetryLinkLookupRetriesInterruptedDump(t *testing.T) {
	want := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "retry0"}}
	attempts := 0
	got, err := pluginControlNetRetryLinkLookup(func() (netlink.Link, error) {
		attempts++
		if attempts < 3 {
			return nil, nl.ErrDumpInterrupted
		}
		return want, nil
	})
	if err != nil || got != want || attempts != 3 {
		t.Fatalf("retry lookup link=%v attempts=%d err=%v, want link after 3 attempts", got, attempts, err)
	}
}

func TestPluginControlNetRetryLinkLookupRejectsPermanentError(t *testing.T) {
	wantErr := errors.New("permanent")
	attempts := 0
	got, err := pluginControlNetRetryLinkLookup(func() (netlink.Link, error) {
		attempts++
		return nil, wantErr
	})
	if got != nil || !errors.Is(err, wantErr) || attempts != 1 {
		t.Fatalf("permanent lookup link=%v attempts=%d err=%v", got, attempts, err)
	}
}

func TestPluginControlNetRetryLinkLookupIsBounded(t *testing.T) {
	attempts := 0
	got, err := pluginControlNetRetryLinkLookup(func() (netlink.Link, error) {
		attempts++
		return nil, nl.ErrDumpInterrupted
	})
	if got != nil || !errors.Is(err, nl.ErrDumpInterrupted) || attempts != pluginControlNetLinkLookupAttempts {
		t.Fatalf("exhausted lookup link=%v attempts=%d err=%v", got, attempts, err)
	}
}
