//go:build linux

package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxIPv6AssignmentNetOpsIgnoreEquivalentRuntimeUpdates(t *testing.T) {
	t.Parallel()

	ops := newLinuxIPv6AssignmentNetOps()
	raConfig := ipv6AssignmentRAConfig{
		TargetInterface: "br-lan",
		Prefixes:        []string{"2001:db8:100::/64"},
	}
	advertiser := newIPv6RouterAdvertiser(raConfig)
	ops.advertisers[raConfig.TargetInterface] = advertiser

	if err := ops.EnsureIPv6RA(cloneIPv6AssignmentRAConfig(raConfig)); err != nil {
		t.Fatalf("EnsureIPv6RA(equivalent) error = %v", err)
	}
	select {
	case <-advertiser.wakeCh:
		t.Fatal("EnsureIPv6RA(equivalent) triggered an immediate advertisement")
	default:
	}
	changedRA := cloneIPv6AssignmentRAConfig(raConfig)
	changedRA.DNSServers = []string{"2001:4860:4860::8888"}
	if err := ops.EnsureIPv6RA(changedRA); err != nil {
		t.Fatalf("EnsureIPv6RA(changed) error = %v", err)
	}
	select {
	case <-advertiser.wakeCh:
	default:
		t.Fatal("EnsureIPv6RA(changed) did not trigger an immediate advertisement")
	}

	dhcpConfig := ipv6AssignmentDHCPv6Config{
		TargetInterface: "br-lan",
		Addresses:       []string{"2001:db8:100::10"},
	}
	server := newIPv6DHCPv6Server(dhcpConfig)
	ops.dhcpv6[dhcpConfig.TargetInterface] = server
	if err := ops.EnsureIPv6DHCPv6(cloneIPv6AssignmentDHCPv6Config(dhcpConfig)); err != nil {
		t.Fatalf("EnsureIPv6DHCPv6(equivalent) error = %v", err)
	}
	changedDHCP := cloneIPv6AssignmentDHCPv6Config(dhcpConfig)
	changedDHCP.DNSServers = []string{"2001:4860:4860::8888"}
	if err := ops.EnsureIPv6DHCPv6(changedDHCP); err != nil {
		t.Fatalf("EnsureIPv6DHCPv6(changed) error = %v", err)
	}
	if got := server.snapshot().DNSServers; len(got) != 1 || got[0] != "2001:4860:4860::8888" {
		t.Fatalf("DHCPv6 runtime config DNS = %v", got)
	}
}

func TestLinuxIPv6AssignmentNetOpsPreserveIPv6AssignmentStateOnClose(t *testing.T) {
	ops := newLinuxIPv6AssignmentNetOps()

	t.Run("env unset", func(t *testing.T) {
		t.Setenv(forwardHotRestartMarkerEnv, "")
		if ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatal("PreserveIPv6AssignmentStateOnClose() = true, want false when marker env is unset")
		}
	})

	t.Run("marker missing", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
		t.Setenv(forwardHotRestartMarkerEnv, marker)
		if ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatalf("PreserveIPv6AssignmentStateOnClose() = true, want false when marker %q is missing", marker)
		}
	})

	t.Run("marker present", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
		if err := os.WriteFile(marker, []byte("1"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", marker, err)
		}
		t.Setenv(forwardHotRestartMarkerEnv, marker)
		if !ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatalf("PreserveIPv6AssignmentStateOnClose() = false, want true when marker %q exists", marker)
		}
	})
}
