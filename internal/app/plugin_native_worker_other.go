//go:build !linux

package app

import (
	"io"
	"net"
	"os"
	"os/exec"
)

func spawnPluginNativeWorker(string, string, *Config) (*exec.Cmd, net.Conn, io.ReadCloser, error) {
	return nil, nil, nil, errPluginNativeUnsupported
}

func pluginNativeSocketPair() (net.Conn, *os.File, error) {
	return nil, nil, errPluginNativeUnsupported
}

func sendPluginNativeFrameWithFile(net.Conn, []byte, *os.File) error {
	return errPluginNativeUnsupported
}

func pluginNativeMemfdExecutable([]byte) (string, error) {
	return "", errPluginNativeUnsupported
}

func pluginNativePathExecutable(string) bool {
	return false
}
