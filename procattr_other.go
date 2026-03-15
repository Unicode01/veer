//go:build !linux

package main

import "os/exec"

func setSysProcAttr(_ *exec.Cmd) {}
