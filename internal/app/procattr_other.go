//go:build !linux

package app

import "os/exec"

func setSysProcAttr(_ *exec.Cmd) {}
