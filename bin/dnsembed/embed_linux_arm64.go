//go:build linux && arm64

package dnsembed

import (
	_ "embed"
	"os/exec"
)

//go:embed vaydns-client-termux-arm64
var vaydnsBin []byte

func GetVayDNS() []byte {
	return vaydnsBin
}

func SetHideWindow(cmd *exec.Cmd) {
}
