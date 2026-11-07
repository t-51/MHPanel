//go:build windows

package dnsembed

import (
	_ "embed"
	"os/exec"
	"syscall"
)

//go:embed vaydns-client.exe
var vaydnsBin []byte

func GetVayDNS() []byte {
	return vaydnsBin
}

func SetHideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
