//go:build !windows
// +build !windows

package engine

import (
	"os/exec"
)

func hideWindow(cmd *exec.Cmd) {
	// На не-Windows платформах ничего не делаем
}