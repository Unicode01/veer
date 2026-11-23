//go:build linux

package app

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pluginCatalogWatchMask covers every change a catalog fingerprint can see:
// files written, created, removed, renamed or re-permissioned, and the
// watched directory itself going away.
const pluginCatalogWatchMask = unix.IN_CLOSE_WRITE | unix.IN_MODIFY | unix.IN_ATTRIB |
	unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
	unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR

// pluginCatalogWatcher follows a plugin directory tree with inotify, so the
// update monitor scans it after a change instead of every two seconds.
type pluginCatalogWatcher struct {
	root  string
	file  *os.File
	fd    int
	dirty atomic.Bool
	// broken is set when the watch can no longer be trusted (the root went
	// away, or a directory could not be watched); the monitor then scans on
	// its own timer until the watcher is opened again.
	broken atomic.Bool
	mu     sync.Mutex
	paths  map[int]string
	done   chan struct{}
}

func openPluginCatalogWatcher(root string) (*pluginCatalogWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	w := &pluginCatalogWatcher{
		root:  root,
		fd:    fd,
		file:  os.NewFile(uintptr(fd), "plugin-catalog-inotify"),
		paths: make(map[int]string),
		done:  make(chan struct{}),
	}
	if err := w.addTree(root); err != nil {
		_ = w.file.Close()
		return nil, err
	}
	// Changes made before the watch existed were not seen: scan once.
	w.dirty.Store(true)
	go w.run()
	return w, nil
}

// addTree watches dir and every directory below it.
func (w *pluginCatalogWatcher) addTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == dir {
				return err
			}
			// A directory that vanished while walking is reported by its
			// parent's watch.
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		wd, err := unix.InotifyAddWatch(w.fd, path, pluginCatalogWatchMask)
		if err != nil {
			if path == dir {
				return err
			}
			w.broken.Store(true)
			return nil
		}
		w.mu.Lock()
		w.paths[wd] = path
		w.mu.Unlock()
		return nil
	})
}

func (w *pluginCatalogWatcher) run() {
	defer close(w.done)
	buf := make([]byte, 64<<10)
	for {
		n, err := w.file.Read(buf)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				w.broken.Store(true)
				w.dirty.Store(true)
			}
			return
		}
		w.handle(buf[:n])
	}
}

func (w *pluginCatalogWatcher) handle(buf []byte) {
	for offset := 0; offset+unix.SizeofInotifyEvent <= len(buf); {
		event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameLen := int(event.Len)
		end := offset + unix.SizeofInotifyEvent + nameLen
		if end > len(buf) {
			break
		}
		name := ""
		if nameLen > 0 {
			raw := buf[offset+unix.SizeofInotifyEvent : end]
			for i, b := range raw {
				if b == 0 {
					raw = raw[:i]
					break
				}
			}
			name = string(raw)
		}
		offset = end
		w.dirty.Store(true)
		switch {
		case event.Mask&unix.IN_Q_OVERFLOW != 0:
			// Events were lost, possibly new directories among them.
			w.broken.Store(true)
		case event.Mask&unix.IN_IGNORED != 0:
			w.mu.Lock()
			path := w.paths[int(event.Wd)]
			delete(w.paths, int(event.Wd))
			w.mu.Unlock()
			if path == w.root {
				w.broken.Store(true)
			}
		case event.Mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0:
			w.mu.Lock()
			path := w.paths[int(event.Wd)]
			w.mu.Unlock()
			if path == w.root {
				w.broken.Store(true)
			}
		case event.Mask&unix.IN_ISDIR != 0 && event.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 && name != "":
			w.mu.Lock()
			parent := w.paths[int(event.Wd)]
			w.mu.Unlock()
			if parent != "" {
				_ = w.addTree(filepath.Join(parent, name))
			}
		}
	}
}

// takeChange reports whether anything changed since the last call.
func (w *pluginCatalogWatcher) takeChange() bool {
	return w != nil && w.dirty.Swap(false)
}

// healthy reports whether every change under root is still being seen.
func (w *pluginCatalogWatcher) healthy() bool {
	return w != nil && !w.broken.Load()
}

func (w *pluginCatalogWatcher) Close() {
	if w == nil {
		return
	}
	_ = w.file.Close()
	<-w.done
}
