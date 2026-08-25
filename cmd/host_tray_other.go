//go:build !windows

package cmd

import "os/exec"

func setHideWindow(cmd *exec.Cmd) {}
