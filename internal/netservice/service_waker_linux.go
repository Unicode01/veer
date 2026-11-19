//go:build linux

package netservice

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// serviceWaker lets stop() end a service's wait on its sockets without
// touching the sockets. A socket belongs to the goroutine that reads it, and
// only that goroutine closes it. Closing it from stop() instead frees the
// descriptor number while the reader still holds it: the kernel can give the
// number to the next file the process opens (a SQLite connection, a TCX
// link, an HTTP connection), and the reader's own close then closes that
// file. SQLite read such a reused descriptor and failed with "disk I/O error
// (266)": EBADF, or ESPIPE once a TCX link took the number.
type serviceWaker struct {
	mu sync.Mutex
	fd int // eventfd, or -1: waits then end only by their timeout
}

func newServiceWaker() *serviceWaker {
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		fd = -1
	}
	return &serviceWaker{fd: fd}
}

// wake ends every wait at once, the current one and all later ones: the
// eventfd stays readable since nothing reads it.
func (w *serviceWaker) wake() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fd < 0 {
		return
	}
	var one [8]byte
	one[0] = 1 // any non-zero counter value makes the eventfd readable
	_, _ = unix.Write(w.fd, one[:])
}

// close releases the eventfd. Call it only after every goroutine that waits
// on it has returned.
func (w *serviceWaker) close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fd >= 0 {
		_ = unix.Close(w.fd)
		w.fd = -1
	}
}

// wait blocks until one of fds is readable, wake is called, or timeout
// passes. It returns how many of fds are ready, with their Revents set, and
// whether the waker fired; a woken caller must stop using its sockets. A
// signal interrupting the wait (the Go runtime preempts threads with one)
// resumes it for the time left.
func (w *serviceWaker) wait(fds []unix.PollFd, timeout time.Duration) (int, bool, error) {
	for i := range fds {
		fds[i].Revents = 0
	}
	wakeFD := -1
	if w != nil {
		w.mu.Lock()
		wakeFD = w.fd
		w.mu.Unlock()
	}
	all := fds
	if wakeFD >= 0 {
		all = make([]unix.PollFd, len(fds)+1)
		copy(all, fds)
		all[len(fds)] = unix.PollFd{Fd: int32(wakeFD), Events: unix.POLLIN}
	}
	deadline := time.Now().Add(timeout)
	for {
		_, err := unix.Poll(all, pollTimeoutMillis(time.Until(deadline)))
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EINTR) {
			return 0, false, err
		}
		if !time.Now().Before(deadline) {
			for i := range all {
				all[i].Revents = 0
			}
			break
		}
	}
	if wakeFD >= 0 && all[len(fds)].Revents != 0 {
		return 0, true, nil
	}
	ready := 0
	for i := range fds {
		fds[i].Revents = all[i].Revents
		if fds[i].Revents != 0 {
			ready++
		}
	}
	return ready, false, nil
}

// waitReadable waits on a single socket; see wait.
func (w *serviceWaker) waitReadable(fd int, timeout time.Duration) (bool, bool, error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	ready, woken, err := w.wait(fds, timeout)
	return ready > 0, woken, err
}

func pollTimeoutMillis(timeout time.Duration) int {
	if timeout <= 0 {
		return 0
	}
	return int((timeout + time.Millisecond - 1) / time.Millisecond)
}
