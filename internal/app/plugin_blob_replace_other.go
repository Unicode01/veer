//go:build !windows

package app

import "os"

func replacePluginBlobFile(source, target string) error {
	return os.Rename(source, target)
}

func syncPluginBlobDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- path is a private plugin blob directory.
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
