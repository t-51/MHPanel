//go:build linux && amd64

package dnsembed

import (
	_ "embed"
	"os/exec"
)

//go:embed vaydns-client-linux-amd64
var vaydnsBin []byte

func GetVayDNS() []byte {
	return vaydnsBin
}

func SetHideWindow(cmd *exec.Cmd) {
}
