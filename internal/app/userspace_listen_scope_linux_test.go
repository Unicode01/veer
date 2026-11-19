//go:build linux

package app

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
)

// Two uplinks with default routes ordered by metric, as wan_core sets them
// up, and a LAN without one: only the second uplink is a secondary uplink,
// and only until a source rule sends its answers out by it.
func TestLookupUserspaceSecondaryUplink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	ns := "fwul" + strconv.Itoa(os.Getpid()%100000)
	runDataplanePerfCmd("ip", "netns", "del", ns)
	mustRunDataplanePerfCmd(t, "ip", "netns", "add", ns)
	t.Cleanup(func() { runDataplanePerfCmd("ip", "netns", "del", ns) })
	in := func(args ...string) {
		t.Helper()
		mustRunDataplanePerfCmd(t, "ip", append([]string{"netns", "exec", ns, "ip"}, args...)...)
	}
	for i, name := range []string{"wan1", "wan2", "lan"} {
		in("link", "add", name, "type", "dummy")
		in("addr", "add", "10.72."+strconv.Itoa(i+1)+".2/24", "dev", name)
		in("link", "set", name, "up")
	}
	in("route", "add", "default", "via", "10.72.1.1", "dev", "wan1", "metric", "100")
	in("route", "add", "default", "via", "10.72.2.1", "dev", "wan2", "metric", "200")

	check := func(iface string, ip string, want bool) {
		t.Helper()
		var got bool
		if err := runInNetNSForTest(ns, func() error {
			got = lookupUserspaceSecondaryUplink(iface, ip)
			return nil
		}); err != nil {
			t.Fatalf("run in %s: %v", ns, err)
		}
		if got != want {
			t.Fatalf("lookupUserspaceSecondaryUplink(%s, %s) = %v, want %v", iface, ip, got, want)
		}
	}
	check("wan1", "10.72.1.2", false)
	check("wan2", "10.72.2.2", true)
	check("lan", "10.72.3.2", false)
	check("missing", "10.72.3.2", false)

	in("route", "add", "default", "via", "10.72.2.1", "dev", "wan2", "table", "100")
	in("rule", "add", "from", "10.72.2.2", "lookup", "100", "priority", "100")
	check("wan2", "10.72.2.2", false)
}
