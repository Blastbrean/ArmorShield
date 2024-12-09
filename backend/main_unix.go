//go:build darwin || freebsd || linux

package main

func getLogPath() string {
	return "/home/armorshield/armorshield.log"
}
