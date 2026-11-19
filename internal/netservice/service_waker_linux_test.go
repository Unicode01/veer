//go:build linux

package netservice

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestServiceWakerEndsWaitWithoutTouchingTheSocket(t *testing.T) {
	t.Parallel()

	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	waker := newServiceWaker()
	defer waker.close()

	begin := time.Now()
	readable, woken, err := waker.waitReadable(pipe[0], 50*time.Millisecond)
	if err != nil || readable || woken {
		t.Fatalf("idle wait = readable %t woken %t err %v, want a plain timeout", readable, woken, err)
	}
	if elapsed := time.Since(begin); elapsed < 40*time.Millisecond {
		t.Fatalf("idle wait returned after %v, before its timeout", elapsed)
	}

	if _, err := unix.Write(pipe[1], []byte{1}); err != nil {
		t.Fatal(err)
	}
	readable, woken, err = waker.waitReadable(pipe[0], time.Second)
	if err != nil || !readable || woken {
		t.Fatalf("wait with data = readable %t woken %t err %v, want readable", readable, woken, err)
	}

	done := make(chan time.Duration, 1)
	go func() {
		var buf [1]byte
		_, _ = unix.Read(pipe[0], buf[:]) // drain, so only the waker can end the next wait
		begin := time.Now()
		_, woken, _ := waker.waitReadable(pipe[0], 10*time.Second)
		if !woken {
			done <- -1
			return
		}
		done <- time.Since(begin)
	}()
	time.Sleep(50 * time.Millisecond)
	waker.wake()
	select {
	case elapsed := <-done:
		if elapsed < 0 {
			t.Fatal("wait ended without the waker")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wake did not end the wait")
	}
	// The pipe is still open: the waker never closes what it waits on.
	if _, err := unix.FcntlInt(uintptr(pipe[0]), unix.F_GETFD, 0); err != nil {
		t.Fatalf("waited-on descriptor after wake: %v", err)
	}
	// Later waits end at once too.
	if _, woken, _ := waker.waitReadable(pipe[0], 10*time.Second); !woken {
		t.Fatal("a wait after wake was not woken")
	}
}

// TestNetworkServicesStopWithoutClosingForeignDescriptors stops real DHCPv4,
// DHCPv6 and RA services while descriptors churn the way a burst of SQLite
// connections does. stop() used to close a socket its reader still held, and
// the reader closed the number again up to two seconds later, by which time
// the number belonged to someone else: SQLite then failed with "disk I/O
// error (266)" (EBADF, or ESPIPE once a TCX link took the number). Run it in
// its own network namespace (unshare --net) as root.
func TestNetworkServicesStopWithoutClosingForeignDescriptors(t *testing.T) {
	if os.Getenv("VEER_RUN_NETSERVICE_PRIVILEGED_TESTS") != "1" {
		t.Skip("set VEER_RUN_NETSERVICE_PRIVILEGED_TESTS=1 and run as root in a scratch network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("needs root")
	}
	const (
		target = "veersvc0"
		bridge = "veersvcbr0"
		port   = "veersvcp0"
	)
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	for _, name := range []string{target, port, bridge} {
		_ = exec.Command("ip", "link", "del", name).Run()
	}
	ip("link", "add", target, "type", "dummy")
	ip("link", "add", bridge, "type", "bridge")
	ip("link", "add", port, "type", "dummy")
	ip("link", "set", port, "master", bridge)
	for _, name := range []string{target, port, bridge} {
		ip("link", "set", name, "up")
	}
	t.Cleanup(func() {
		for _, name := range []string{target, port, bridge} {
			_ = exec.Command("ip", "link", "del", name).Run()
		}
	})

	path := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	var probe unix.Stat_t
	if err := unix.Stat(path, &probe); err != nil {
		t.Fatal(err)
	}
	var checked, foreign atomic.Int64
	stopVictims := make(chan struct{})
	var victims sync.WaitGroup
	victims.Add(1)
	go func() {
		defer victims.Done()
		buf := make([]byte, 64)
		for {
			select {
			case <-stopVictims:
				return
			default:
			}
			// A batch takes every free descriptor number, a just-freed one
			// included, as a burst of SQLite connections would.
			fds := make([]int, 0, 64)
			held := make(map[int]bool, 64)
			for i := 0; i < 64; i++ {
				fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					continue
				}
				if held[fd] {
					foreign.Add(1)
					t.Errorf("fd %d was handed out again while this test held it", fd)
					continue
				}
				held[fd] = true
				fds = append(fds, fd)
			}
			time.Sleep(20 * time.Millisecond)
			for _, fd := range fds {
				checked.Add(1)
				var st unix.Stat_t
				if err := unix.Fstat(fd, &st); err != nil {
					foreign.Add(1)
					_, perr := unix.Pread(fd, buf, 0)
					t.Errorf("fd %d was closed under this test (fstat %v, pread %v)", fd, err, perr)
					continue
				}
				if st.Ino != probe.Ino || st.Dev != probe.Dev {
					foreign.Add(1)
					_, perr := unix.Pread(fd, buf, 0)
					t.Errorf("fd %d now names another file (pread %v)", fd, perr)
					continue
				}
				if err := unix.Close(fd); err != nil {
					foreign.Add(1)
					t.Errorf("fd %d: close: %v", fd, err)
				}
			}
		}
	}()

	waitListening := func(what string, listening func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !listening() {
			if time.Now().After(deadline) {
				t.Fatalf("%s never opened its socket", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ipv6 := NewIPv6Manager()
	dhcpv4 := NewDHCPv4Manager()
	for round := 0; round < 6; round++ {
		if err := ipv6.EnsureRA(RAConfig{TargetInterface: target}); err != nil {
			t.Fatal(err)
		}
		if err := ipv6.EnsureDHCPv6(DHCPv6Config{TargetInterface: target}); err != nil {
			t.Fatal(err)
		}
		if err := dhcpv4.Ensure(DHCPv4Config{
			Bridge: bridge, ServerCIDR: "192.0.2.1/24", ServerIP: "192.0.2.1", Gateway: "192.0.2.1",
			PoolStart: "192.0.2.100", PoolEnd: "192.0.2.200",
		}); err != nil {
			t.Fatal(err)
		}
		ipv6.mu.Lock()
		adv, srv6 := ipv6.advertisers[target], ipv6.dhcpv6[target]
		ipv6.mu.Unlock()
		dhcpv4.mu.Lock()
		srv4 := dhcpv4.servers[bridge]
		dhcpv4.mu.Unlock()
		waitListening("router advertisement", func() bool {
			adv.mu.Lock()
			defer adv.mu.Unlock()
			return adv.currentRSFD >= 0
		})
		waitListening("dhcpv6", func() bool {
			srv6.mu.Lock()
			defer srv6.mu.Unlock()
			return srv6.currentFD >= 0
		})
		waitListening("dhcpv4", func() bool {
			srv4.mu.Lock()
			defer srv4.mu.Unlock()
			return len(srv4.currentFDs) > 0
		})
		time.Sleep(50 * time.Millisecond) // let the readers block in their wait

		for _, stop := range []struct {
			name string
			fn   func() error
		}{
			{"router advertisement", func() error { return ipv6.DeleteRA(target) }},
			{"dhcpv6", func() error { return ipv6.DeleteDHCPv6(target) }},
			{"dhcpv4", func() error { return dhcpv4.Delete(bridge) }},
		} {
			begin := time.Now()
			if err := stop.fn(); err != nil {
				t.Fatalf("round %d: stop %s: %v", round, stop.name, err)
			}
			// The reader used to notice only at its 2-second receive timeout.
			if elapsed := time.Since(begin); elapsed > time.Second {
				t.Errorf("round %d: stopping %s took %v", round, stop.name, elapsed)
			}
		}
		time.Sleep(100 * time.Millisecond) // keep churning after the stops
	}
	close(stopVictims)
	victims.Wait()
	if checked.Load() == 0 {
		t.Fatal("no descriptors were checked")
	}
	t.Logf("checked %d descriptors across the stops, %d closed or replaced under this test", checked.Load(), foreign.Load())
}
