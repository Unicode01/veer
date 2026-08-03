//go:build linux

package managednet

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedNetworkIPv4AddressDeleteAbsentErrors(t *testing.T) {
	t.Parallel()

	absentErrors := []error{unix.ESRCH, unix.ENOENT, unix.ENODEV, unix.EADDRNOTAVAIL}
	for _, err := range absentErrors {
		if !managedNetworkIPv4AddressDeleteErrorIsAbsent(fmt.Errorf("wrapped: %w", err)) {
			t.Fatalf("managedNetworkIPv4AddressDeleteErrorIsAbsent(%v) = false", err)
		}
	}
	if managedNetworkIPv4AddressDeleteErrorIsAbsent(errors.New("permission denied")) {
		t.Fatal("arbitrary address delete error was treated as absent")
	}
}
