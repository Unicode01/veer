package app

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// Release builds place veer-plugin-worker builds for the target
// architecture under pluginworker/<triple>/ before compiling veer; the
// placeholder keeps the embed pattern valid in development builds.
//
//go:embed pluginworker
var embeddedPluginNativeWorkers embed.FS

var embeddedPluginNativeWorkerOnce struct {
	sync.Mutex
	path string
}

// extractEmbeddedPluginNativeWorker makes the embedded worker for this host
// executable once and returns the path to run. It prefers an anonymous
// memory file (no file on disk, unaffected by noexec mounts such as /run);
// where the kernel forbids executing those it writes the worker to the first
// directory it can execute from. It returns os.ErrNotExist when this binary
// carries no worker for the host.
func extractEmbeddedPluginNativeWorker() (string, error) {
	triple := pluginNativeHostTriple()
	if triple == "" {
		return "", os.ErrNotExist
	}
	data, err := fs.ReadFile(embeddedPluginNativeWorkers, "pluginworker/"+triple+"/veer-plugin-worker")
	if err != nil {
		return "", os.ErrNotExist
	}
	embeddedPluginNativeWorkerOnce.Lock()
	defer embeddedPluginNativeWorkerOnce.Unlock()
	if embeddedPluginNativeWorkerOnce.path != "" {
		return embeddedPluginNativeWorkerOnce.path, nil
	}
	if path, err := pluginNativeMemfdExecutable(data); err == nil {
		embeddedPluginNativeWorkerOnce.path = path
		return path, nil
	}
	sum := sha256.Sum256(data)
	var lastErr error
	for _, dir := range pluginNativeWorkerFileDirs() {
		path, err := writePluginNativeWorkerFile(dir, data, sum)
		if err == nil {
			embeddedPluginNativeWorkerOnce.path = path
			return path, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("install plugin worker: %w", lastErr)
}

func writePluginNativeWorkerFile(dir string, data []byte, sum [32]byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("veer-plugin-worker-%x", sum[:8]))
	if existing, err := os.ReadFile(path); err != nil || sha256.Sum256(existing) != sum {
		temporary := path + ".tmp"
		if err := os.WriteFile(temporary, data, 0o700); err != nil {
			return "", err
		}
		if err := os.Rename(temporary, path); err != nil {
			_ = os.Remove(temporary)
			return "", err
		}
	}
	if !pluginNativePathExecutable(path) {
		return "", fmt.Errorf("%s is on a filesystem that does not allow executing programs", dir)
	}
	return path, nil
}

// pluginNativeWorkerFileDirs lists where the worker may be written when
// memory files cannot be executed: next to veer, then state and temporary
// directories.
func pluginNativeWorkerFileDirs() []string {
	dirs := make([]string, 0, 4)
	if executable, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(executable), ".veer-plugin-worker"))
	}
	dirs = append(dirs, "/var/lib/veer/plugin-worker", filepath.Join(os.TempDir(), "veer-plugin-worker"))
	return dirs
}
