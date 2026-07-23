//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const pluginControlNamedNetNSDir = "/run/netns"

type linuxPluginNetworkProvider struct {
	mu      sync.RWMutex
	handles map[string]*linuxPluginTunTapHandle
}

type linuxPluginTunTapHandle struct {
	owner     string
	fd        int
	wakeRead  int
	wakeWrite int
	info      pluginControlNetTunTapInfo

	lifecycle sync.RWMutex
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closed    bool

	reads       atomic.Uint64
	readBytes   atomic.Uint64
	writes      atomic.Uint64
	writeBytes  atomic.Uint64
	readErrors  atomic.Uint64
	writeErrors atomic.Uint64
}

func newLinuxPluginNetworkProvider() *linuxPluginNetworkProvider {
	return &linuxPluginNetworkProvider{handles: make(map[string]*linuxPluginTunTapHandle)}
}

func (admin *linuxPluginControlNetAdmin) pluginNetworkProvider() (*linuxPluginNetworkProvider, error) {
	if admin == nil || admin.provider == nil {
		return nil, fmt.Errorf("network provider is not initialized")
	}
	return admin.provider, nil
}

func (admin *linuxPluginControlNetAdmin) NamespaceLookup(name string) (pluginControlNetNamespaceInfo, bool, error) {
	if _, err := admin.pluginNetworkProvider(); err != nil {
		return pluginControlNetNamespaceInfo{}, false, err
	}
	return linuxPluginNamespaceLookup(name)
}

func (admin *linuxPluginControlNetAdmin) NamespaceList() ([]pluginControlNetNamespaceInfo, error) {
	if _, err := admin.pluginNetworkProvider(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(pluginControlNamedNetNSDir)
	if errors.Is(err, os.ErrNotExist) {
		return []pluginControlNetNamespaceInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]pluginControlNetNamespaceInfo, 0, len(entries))
	for _, entry := range entries {
		name, validateErr := validatePluginControlNamespaceName(entry.Name(), false)
		if validateErr != nil {
			continue
		}
		info, present, lookupErr := linuxPluginNamespaceLookup(name)
		if lookupErr != nil || !present {
			continue
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (admin *linuxPluginControlNetAdmin) NamespaceEnsure(req pluginControlNetNamespaceRequest) (pluginControlNetNamespaceResult, error) {
	if _, err := admin.pluginNetworkProvider(); err != nil {
		return pluginControlNetNamespaceResult{}, err
	}
	name, err := validatePluginControlNamespaceName(req.Name, false)
	if err != nil {
		return pluginControlNetNamespaceResult{}, err
	}
	if info, present, err := linuxPluginNamespaceLookup(name); err != nil {
		return pluginControlNetNamespaceResult{}, err
	} else if present {
		return pluginControlNetNamespaceResult{Info: info}, nil
	}

	resultCh := make(chan struct {
		info pluginControlNetNamespaceInfo
		err  error
	}, 1)
	go func() {
		runtime.LockOSThread()
		safeToUnlock := true
		defer func() {
			if safeToUnlock {
				runtime.UnlockOSThread()
			}
		}()
		current, currentErr := netns.Get()
		if currentErr != nil {
			resultCh <- struct {
				info pluginControlNetNamespaceInfo
				err  error
			}{err: fmt.Errorf("capture current namespace: %w", currentErr)}
			return
		}
		defer current.Close()
		safeToUnlock = false
		created, createErr := netns.NewNamed(name)
		if createErr != nil {
			restoreErr := netns.Set(current)
			safeToUnlock = restoreErr == nil
			if restoreErr != nil {
				createErr = fmt.Errorf("%v; restore current namespace: %w", createErr, restoreErr)
			}
			resultCh <- struct {
				info pluginControlNetNamespaceInfo
				err  error
			}{err: createErr}
			return
		}
		identity, identityErr := linuxPluginNamespaceIdentity(created)
		if identityErr == nil && req.LoopbackUp {
			loopback, lookupErr := pluginControlNetLinkByName("lo")
			if lookupErr != nil {
				identityErr = fmt.Errorf("resolve loopback: %w", lookupErr)
			} else if upErr := netlink.LinkSetUp(loopback); upErr != nil {
				identityErr = fmt.Errorf("set loopback up: %w", upErr)
			}
		}
		_ = created.Close()
		restoreErr := netns.Set(current)
		safeToUnlock = restoreErr == nil
		if restoreErr != nil {
			if identityErr != nil {
				identityErr = fmt.Errorf("%v; restore current namespace: %w", identityErr, restoreErr)
			} else {
				identityErr = fmt.Errorf("restore current namespace: %w", restoreErr)
			}
		}
		resultCh <- struct {
			info pluginControlNetNamespaceInfo
			err  error
		}{info: pluginControlNetNamespaceInfo{Name: name, Identity: identity}, err: identityErr}
	}()
	result := <-resultCh
	if result.err != nil {
		_ = netns.DeleteNamed(name)
		return pluginControlNetNamespaceResult{}, result.err
	}
	return pluginControlNetNamespaceResult{Info: result.info, Created: true}, nil
}

func (admin *linuxPluginControlNetAdmin) NamespaceDelete(name string, identity pluginControlNetNamespaceIdentity) error {
	provider, err := admin.pluginNetworkProvider()
	if err != nil {
		return err
	}
	name, err = validatePluginControlNamespaceName(name, false)
	if err != nil {
		return err
	}
	provider.mu.RLock()
	for _, handle := range provider.handles {
		if handle.info.Namespace == name {
			provider.mu.RUnlock()
			return fmt.Errorf("namespace %s still has an open managed TUN/TAP device", name)
		}
	}
	provider.mu.RUnlock()
	current, present, err := linuxPluginNamespaceLookup(name)
	if err != nil || !present {
		return err
	}
	if (identity.Device != 0 || identity.Inode != 0) && !pluginControlNamespaceIdentityEqual(current.Identity, identity) {
		return fmt.Errorf("namespace %s changed identity", name)
	}
	if err := netns.DeleteNamed(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func linuxPluginNamespaceLookup(name string) (pluginControlNetNamespaceInfo, bool, error) {
	name, err := validatePluginControlNamespaceName(name, false)
	if err != nil {
		return pluginControlNetNamespaceInfo{}, false, err
	}
	handle, err := netns.GetFromName(name)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return pluginControlNetNamespaceInfo{}, false, nil
	}
	if err != nil {
		return pluginControlNetNamespaceInfo{}, false, err
	}
	defer handle.Close()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(handle), &fs); err != nil {
		return pluginControlNetNamespaceInfo{}, false, err
	}
	if uint64(fs.Type) != uint64(unix.NSFS_MAGIC) {
		return pluginControlNetNamespaceInfo{}, false, fmt.Errorf("%s is not a network namespace", filepath.Join(pluginControlNamedNetNSDir, name))
	}
	identity, err := linuxPluginNamespaceIdentity(handle)
	if err != nil {
		return pluginControlNetNamespaceInfo{}, false, err
	}
	return pluginControlNetNamespaceInfo{Name: name, Identity: identity}, true, nil
}

func linuxPluginNamespaceIdentity(handle netns.NsHandle) (pluginControlNetNamespaceIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(handle), &stat); err != nil {
		return pluginControlNetNamespaceIdentity{}, err
	}
	return pluginControlNetNamespaceIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func (admin *linuxPluginControlNetAdmin) TunTapEnsure(owner string, req pluginControlNetTunTapRequest) (pluginControlNetTunTapResult, error) {
	provider, err := admin.pluginNetworkProvider()
	if err != nil {
		return pluginControlNetTunTapResult{}, err
	}
	owner = strings.TrimSpace(strings.ToLower(owner))
	if owner == "" {
		return pluginControlNetTunTapResult{}, fmt.Errorf("owner is required")
	}
	key := pluginControlTunTapResourceKey(req.Namespace, req.Name)
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if existing := provider.handles[key]; existing != nil {
		if existing.owner != owner {
			return pluginControlNetTunTapResult{}, fmt.Errorf("device %s is already open by another plugin", key)
		}
		if existing.info.Mode != req.Mode {
			return pluginControlNetTunTapResult{}, fmt.Errorf("existing device mode is %s, want %s", existing.info.Mode, req.Mode)
		}
		info := existing.snapshot()
		return pluginControlNetTunTapResult{Info: info}, nil
	}

	fd, info, err := linuxPluginOpenTunTap(req)
	if err != nil {
		return pluginControlNetTunTapResult{}, err
	}
	wake := []int{-1, -1}
	if err := unix.Pipe2(wake, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		_ = unix.Close(fd)
		return pluginControlNetTunTapResult{}, fmt.Errorf("create TUN/TAP wake pipe: %w", err)
	}
	handle := &linuxPluginTunTapHandle{owner: owner, fd: fd, wakeRead: wake[0], wakeWrite: wake[1], info: info}
	provider.handles[key] = handle
	return pluginControlNetTunTapResult{Info: handle.snapshot(), Created: true}, nil
}

func linuxPluginOpenTunTap(req pluginControlNetTunTapRequest) (int, pluginControlNetTunTapInfo, error) {
	resultCh := make(chan struct {
		fd   int
		info pluginControlNetTunTapInfo
		err  error
	}, 1)
	run := func() (int, pluginControlNetTunTapInfo, error) {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, pluginControlNetTunTapInfo{}, fmt.Errorf("open /dev/net/tun: %w", err)
		}
		closeOnError := true
		defer func() {
			if closeOnError {
				_ = unix.Close(fd)
			}
		}()
		ifr, err := unix.NewIfreq(req.Name)
		if err != nil {
			return -1, pluginControlNetTunTapInfo{}, err
		}
		flags := uint16(unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
		if req.Mode == "tap" {
			flags |= unix.IFF_TAP
		} else {
			flags |= unix.IFF_TUN
		}
		ifr.SetUint16(flags)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			return -1, pluginControlNetTunTapInfo{}, fmt.Errorf("create %s device %s: %w", req.Mode, req.Name, err)
		}
		link, err := pluginControlNetLinkByName(req.Name)
		if err != nil {
			return -1, pluginControlNetTunTapInfo{}, fmt.Errorf("resolve created device: %w", err)
		}
		if req.MTU > 0 && link.Attrs().MTU != req.MTU {
			if err := netlink.LinkSetMTU(link, req.MTU); err != nil {
				return -1, pluginControlNetTunTapInfo{}, fmt.Errorf("set mtu: %w", err)
			}
		}
		if req.Up {
			if err := netlink.LinkSetUp(link); err != nil {
				return -1, pluginControlNetTunTapInfo{}, fmt.Errorf("set link up: %w", err)
			}
		}
		link, err = pluginControlNetLinkByName(req.Name)
		if err != nil {
			return -1, pluginControlNetTunTapInfo{}, err
		}
		info := pluginControlNetTunTapInfo{
			Name: req.Name, Namespace: req.Namespace, Mode: req.Mode, IfIndex: link.Attrs().Index,
			MTU: link.Attrs().MTU, Up: link.Attrs().Flags&1 != 0, MAC: link.Attrs().HardwareAddr.String(),
		}
		closeOnError = false
		return fd, info, nil
	}
	if req.Namespace == "host" {
		return run()
	}
	go func() {
		var fd = -1
		var info pluginControlNetTunTapInfo
		err := linuxPluginRunInNamespace(req.Namespace, func() error {
			var runErr error
			fd, info, runErr = run()
			return runErr
		})
		if err != nil && fd >= 0 {
			_ = unix.Close(fd)
			fd = -1
		}
		resultCh <- struct {
			fd   int
			info pluginControlNetTunTapInfo
			err  error
		}{fd: fd, info: info, err: err}
	}()
	result := <-resultCh
	return result.fd, result.info, result.err
}

func linuxPluginRunInNamespace(name string, fn func() error) error {
	runtime.LockOSThread()
	safeToUnlock := true
	defer func() {
		if safeToUnlock {
			runtime.UnlockOSThread()
		}
	}()
	current, err := netns.Get()
	if err != nil {
		return fmt.Errorf("capture current namespace: %w", err)
	}
	defer current.Close()
	target, err := netns.GetFromName(name)
	if err != nil {
		return fmt.Errorf("open namespace %s: %w", name, err)
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		return fmt.Errorf("enter namespace %s: %w", name, err)
	}
	safeToUnlock = false
	operationErr := fn()
	restoreErr := netns.Set(current)
	safeToUnlock = restoreErr == nil
	if operationErr != nil && restoreErr != nil {
		return fmt.Errorf("%v; restore current namespace: %w", operationErr, restoreErr)
	}
	if operationErr != nil {
		return operationErr
	}
	if restoreErr != nil {
		return fmt.Errorf("restore current namespace: %w", restoreErr)
	}
	return nil
}

func (admin *linuxPluginControlNetAdmin) TunTapClose(owner string, req pluginControlNetTunTapCloseRequest) error {
	provider, err := admin.pluginNetworkProvider()
	if err != nil {
		return err
	}
	key := pluginControlTunTapResourceKey(req.Namespace, req.Name)
	provider.mu.Lock()
	handle := provider.handles[key]
	if handle == nil {
		provider.mu.Unlock()
		return nil
	}
	if handle.owner != owner {
		provider.mu.Unlock()
		return fmt.Errorf("device %s is open by another plugin", key)
	}
	if req.IfIndex > 0 && handle.info.IfIndex != req.IfIndex {
		provider.mu.Unlock()
		return fmt.Errorf("device %s changed identity", key)
	}
	delete(provider.handles, key)
	provider.mu.Unlock()
	return handle.close()
}

func (admin *linuxPluginControlNetAdmin) TunTapRead(owner string, req pluginControlNetTunTapReadRequest) (pluginControlNetTunTapPacket, error) {
	provider, err := admin.pluginNetworkProvider()
	if err != nil {
		return pluginControlNetTunTapPacket{}, err
	}
	handle, err := provider.handle(owner, req.Namespace, req.Name)
	if err != nil {
		return pluginControlNetTunTapPacket{}, err
	}
	return handle.read(req.MaxBytes, req.Timeout)
}

func (admin *linuxPluginControlNetAdmin) TunTapWrite(owner string, req pluginControlNetTunTapWriteRequest) (int, error) {
	provider, err := admin.pluginNetworkProvider()
	if err != nil {
		return 0, err
	}
	handle, err := provider.handle(owner, req.Namespace, req.Name)
	if err != nil {
		return 0, err
	}
	return handle.write(req.Packet)
}

func (admin *linuxPluginControlNetAdmin) TunTapList(owner string) []pluginControlNetTunTapInfo {
	provider, err := admin.pluginNetworkProvider()
	if err != nil {
		return []pluginControlNetTunTapInfo{}
	}
	provider.mu.RLock()
	out := make([]pluginControlNetTunTapInfo, 0)
	for _, handle := range provider.handles {
		if handle.owner == owner {
			out = append(out, handle.snapshot())
		}
	}
	provider.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace == out[j].Namespace {
			return out[i].Name < out[j].Name
		}
		return out[i].Namespace < out[j].Namespace
	})
	return out
}

func (admin *linuxPluginControlNetAdmin) TunTapCloseAll(owner string) {
	provider, err := admin.pluginNetworkProvider()
	if err != nil {
		return
	}
	provider.mu.Lock()
	handles := make([]*linuxPluginTunTapHandle, 0)
	for key, handle := range provider.handles {
		if owner == "" || handle.owner == owner {
			handles = append(handles, handle)
			delete(provider.handles, key)
		}
	}
	provider.mu.Unlock()
	for _, handle := range handles {
		_ = handle.close()
	}
}

func (provider *linuxPluginNetworkProvider) handle(owner, namespace, name string) (*linuxPluginTunTapHandle, error) {
	key := pluginControlTunTapResourceKey(namespace, name)
	provider.mu.RLock()
	handle := provider.handles[key]
	provider.mu.RUnlock()
	if handle == nil {
		return nil, fmt.Errorf("device %s is not open", key)
	}
	if handle.owner != owner {
		return nil, fmt.Errorf("device %s is open by another plugin", key)
	}
	return handle, nil
}

func (handle *linuxPluginTunTapHandle) snapshot() pluginControlNetTunTapInfo {
	info := handle.info
	info.Reads = handle.reads.Load()
	info.ReadBytes = handle.readBytes.Load()
	info.Writes = handle.writes.Load()
	info.WriteBytes = handle.writeBytes.Load()
	info.ReadErrors = handle.readErrors.Load()
	info.WriteErrors = handle.writeErrors.Load()
	return info
}

func (handle *linuxPluginTunTapHandle) read(maxBytes int, timeout time.Duration) (pluginControlNetTunTapPacket, error) {
	handle.lifecycle.RLock()
	defer handle.lifecycle.RUnlock()
	if handle.closed {
		return pluginControlNetTunTapPacket{}, fmt.Errorf("device is closed")
	}
	handle.readMu.Lock()
	defer handle.readMu.Unlock()
	timeoutMS := int(timeout.Milliseconds())
	poll := []unix.PollFd{
		{Fd: int32(handle.fd), Events: unix.POLLIN},
		{Fd: int32(handle.wakeRead), Events: unix.POLLIN},
	}
	ready, err := unix.Poll(poll, timeoutMS)
	if err != nil {
		handle.readErrors.Add(1)
		return pluginControlNetTunTapPacket{}, err
	}
	if ready == 0 {
		return pluginControlNetTunTapPacket{TimedOut: true}, nil
	}
	if poll[1].Revents != 0 {
		var wake [8]byte
		_, _ = unix.Read(handle.wakeRead, wake[:])
		return pluginControlNetTunTapPacket{}, fmt.Errorf("device is closing")
	}
	if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
		handle.readErrors.Add(1)
		return pluginControlNetTunTapPacket{}, fmt.Errorf("device poll failed with revents 0x%x", poll[0].Revents)
	}
	packet := make([]byte, maxBytes)
	n, err := unix.Read(handle.fd, packet)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
		return pluginControlNetTunTapPacket{TimedOut: true}, nil
	}
	if err != nil {
		handle.readErrors.Add(1)
		return pluginControlNetTunTapPacket{}, err
	}
	handle.reads.Add(1)
	handle.readBytes.Add(uint64(n))
	return pluginControlNetTunTapPacket{Packet: packet[:n]}, nil
}

func (handle *linuxPluginTunTapHandle) write(packet []byte) (int, error) {
	handle.lifecycle.RLock()
	defer handle.lifecycle.RUnlock()
	if handle.closed {
		return 0, fmt.Errorf("device is closed")
	}
	handle.writeMu.Lock()
	defer handle.writeMu.Unlock()
	n, err := unix.Write(handle.fd, packet)
	if err != nil {
		handle.writeErrors.Add(1)
		return n, err
	}
	if n != len(packet) {
		handle.writeErrors.Add(1)
		return n, fmt.Errorf("short packet write: %d of %d bytes", n, len(packet))
	}
	handle.writes.Add(1)
	handle.writeBytes.Add(uint64(n))
	return n, nil
}

func (handle *linuxPluginTunTapHandle) close() error {
	_, _ = unix.Write(handle.wakeWrite, []byte{1})
	handle.lifecycle.Lock()
	defer handle.lifecycle.Unlock()
	if handle.closed {
		return nil
	}
	handle.closed = true
	errorsList := make([]error, 0, 3)
	for _, fd := range []int{handle.fd, handle.wakeRead, handle.wakeWrite} {
		if err := unix.Close(fd); err != nil && !errors.Is(err, unix.EBADF) {
			errorsList = append(errorsList, err)
		}
	}
	return errors.Join(errorsList...)
}
