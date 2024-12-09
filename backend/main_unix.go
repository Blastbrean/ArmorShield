//go:build darwin || freebsd || linux

package main

func getLogPath() string {
	return "logs/armorshield.log"
}
