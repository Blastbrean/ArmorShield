//go:build darwin || freebsd || linux

package main

func getLogPath() string {
	return "/var/log/armorshield.log"
}
