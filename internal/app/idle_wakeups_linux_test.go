//go:build linux

package app

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestKernelRuntimePressureSamplesSlowerWithHeadroom(t *testing.T) {
	at := time.Unix(1000, 0)
	state := func(flows, nat int, sampledAt time.Time) kernelRuntimePressureState {
		return kernelRuntimePressureState{sampledAt: sampledAt, flowsEntries: flows, flowsCapacity: 131072, natEntries: nat, natCapacity: 131072}
	}
	cases := []struct {
		name           string
		previous, next kernelRuntimePressureState
		want           time.Duration
	}{
		{"first sample, mostly empty", kernelRuntimePressureState{}, state(1000, 50, at), kernelRuntimePressureIdleSampleTTL},
		{"steady and empty", state(1000, 50, at), state(1000, 50, at.Add(20*time.Second)), kernelRuntimePressureIdleSampleTTL},
		{"a quarter full", state(1000, 50, at), state(32768, 50, at.Add(20*time.Second)), kernelRuntimePressureSampleTTL},
		{"slow growth", state(1000, 50, at), state(2000, 50, at.Add(20*time.Second)), kernelRuntimePressureIdleSampleTTL},
		// 1500 entries a second reach the hold watermark in about 80 s.
		{"fast growth", state(1000, 50, at), state(31000, 50, at.Add(20*time.Second)), kernelRuntimePressureSampleTTL},
		{"NAT filling", state(1000, 1000, at), state(1000, 31000, at.Add(20*time.Second)), kernelRuntimePressureSampleTTL},
	}
	for _, c := range cases {
		if got := kernelRuntimePressureSampleEvery(c.previous, c.next); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	held := state(1000, 50, at)
	held.level = kernelRuntimePressureLevelHold
	if got := kernelRuntimePressureSampleEvery(kernelRuntimePressureState{}, held); got != kernelRuntimePressureSampleTTL {
		t.Errorf("under pressure: %v", got)
	}
	if got := (kernelRuntimePressureState{}).trustedFor(); got != kernelRuntimePressureSampleTTL {
		t.Errorf("a state without its own interval: %v", got)
	}
}

func netlinkTestAttr(kind uint16, value []byte) []byte {
	out := make([]byte, unix.SizeofRtAttr, unix.SizeofRtAttr+len(value)+3)
	binary.NativeEndian.PutUint16(out[0:2], uint16(unix.SizeofRtAttr+len(value)))
	binary.NativeEndian.PutUint16(out[2:4], kind)
	out = append(out, value...)
	for len(out)%unix.RTA_ALIGNTO != 0 {
		out = append(out, 0)
	}
	return out
}

func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func TestPluginRuleAndOffloadEventPayloads(t *testing.T) {
	header := []byte{unix.AF_INET, 0, 0, 0, unix.RT_TABLE_COMPAT, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
	data := append([]byte(nil), header...)
	data = append(data, netlinkTestAttr(unix.FRA_PRIORITY, u32(10100))...)
	data = append(data, netlinkTestAttr(unix.FRA_TABLE, u32(12001))...)
	data = append(data, netlinkTestAttr(unix.FRA_IIFNAME, []byte("veerwan0\x00"))...)
	payload, ok := pluginRuleEventPayload(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_DELRULE}, Data: data})
	if !ok || payload["operation"] != "delete" || payload["priority"] != 10100 || payload["table"] != 12001 || payload["iif"] != "veerwan0" || payload["family"] != unix.AF_INET {
		t.Fatalf("rule payload = %v, %v", payload, ok)
	}
	if _, ok := pluginRuleEventPayload(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWRULE}, Data: header[:4]}); ok {
		t.Fatal("a truncated rule message was accepted")
	}

	nested := append(netlinkTestAttr(unix.ETHTOOL_A_HEADER_DEV_INDEX, u32(7)), netlinkTestAttr(unix.ETHTOOL_A_HEADER_DEV_NAME, []byte("veerpipe0\x00"))...)
	genl := []byte{unix.ETHTOOL_MSG_FEATURES_NTF, 1, 0, 0}
	features := append(append([]byte(nil), genl...), netlinkTestAttr(unix.ETHTOOL_A_FEATURES_HEADER|unix.NLA_F_NESTED, nested)...)
	payload, ok = pluginOffloadEventPayload(syscall.NetlinkMessage{Data: features})
	if !ok || payload["interface"] != "veerpipe0" || payload["ifindex"] != 7 {
		t.Fatalf("offload payload = %v, %v", payload, ok)
	}
	other := append([]byte{unix.ETHTOOL_MSG_LINKSTATE_GET_REPLY, 1, 0, 0}, features[4:]...)
	if _, ok := pluginOffloadEventPayload(syscall.NetlinkMessage{Data: other}); ok {
		t.Fatal("a message other than a features notification was accepted")
	}
}

func TestPluginCatalogWatcherSeesChangesBelowTheRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "first", "ui"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := openPluginCatalogWatcher(root)
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	defer w.Close()
	if !w.takeChange() {
		t.Fatal("a new watch must ask for one scan")
	}
	wait := func(what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !w.takeChange() {
			if time.Now().After(deadline) {
				t.Fatalf("%s was not seen", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	quiet := func(what string) {
		t.Helper()
		time.Sleep(100 * time.Millisecond)
		if w.takeChange() {
			t.Fatalf("%s reported a change", what)
		}
	}
	quiet("an idle tree")
	if err := os.WriteFile(filepath.Join(root, "first", "ui", "app.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	wait("a file written two levels down")
	if err := os.MkdirAll(filepath.Join(root, "second", "ui"), 0o755); err != nil {
		t.Fatal(err)
	}
	wait("a new plugin directory")
	quiet("the tree after the new directory")
	if err := os.WriteFile(filepath.Join(root, "second", "ui", "index.html"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	wait("a file in a directory created after the watch")
	if err := os.Chmod(filepath.Join(root, "second", "ui", "index.html"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait("a mode change")
	if !w.healthy() {
		t.Fatal("the watch is broken")
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for w.healthy() {
		if time.Now().After(deadline) {
			t.Fatal("removing the root left the watch healthy")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The rule and offload sockets receive the kernel's notifications for
// changes made by anyone, including the host's own ioctls.
func TestPluginNetEventSocketsSeeRuleAndOffloadChanges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a network namespace")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origin, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	ns, err := netns.New()
	if err != nil {
		t.Skipf("cannot create a network namespace: %v", err)
	}
	defer func() {
		_ = netns.Set(origin)
		ns.Close()
	}()

	receive := func(file *os.File, family uint16, parse func(syscall.NetlinkMessage) (map[string]any, bool)) map[string]any {
		t.Helper()
		_ = file.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64<<10)
		for {
			n, err := file.Read(buf)
			if err != nil {
				t.Fatalf("no notification: %v", err)
			}
			msgs, err := syscall.ParseNetlinkMessage(buf[:n])
			if err != nil {
				continue
			}
			for _, msg := range msgs {
				if family != 0 && msg.Header.Type != family {
					continue
				}
				if payload, ok := parse(msg); ok {
					return payload
				}
			}
		}
	}

	rules, _, err := openRuleEventSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Close()
	rule := netlink.NewRule()
	rule.Priority, rule.Table, rule.IifName = 10100, 12001, "lo"
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatal(err)
	}
	payload := receive(rules, 0, pluginRuleEventPayload)
	if payload["operation"] != "update" || payload["priority"] != 10100 || payload["table"] != 12001 || payload["iif"] != "lo" {
		t.Fatalf("rule event = %v", payload)
	}

	offloads, family, err := openOffloadEventSocket()
	if err != nil {
		t.Skipf("ethtool netlink unavailable: %v", err)
	}
	defer offloads.Close()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "offev0"}}); err != nil {
		t.Fatal(err)
	}
	dev, err := openPluginOffloadDevice("offev0")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := dev.set(map[string]bool{"gro": false}); err != nil {
		t.Fatal(err)
	}
	payload = receive(offloads, family, pluginOffloadEventPayload)
	if payload["interface"] != "offev0" {
		t.Fatalf("offload event = %v", payload)
	}
}
