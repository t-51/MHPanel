//go:build !windows && !(linux && amd64) && !(linux && arm64)

package dnsembed

import "os/exec"

func GetVayDNS() []byte {
	return nil
}

func SetHideWindow(cmd *exec.Cmd) {
}
