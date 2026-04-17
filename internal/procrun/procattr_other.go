//go:build !linux

package procrun

import "os/exec"

func SetSysProcAttr(_ *exec.Cmd) {}
