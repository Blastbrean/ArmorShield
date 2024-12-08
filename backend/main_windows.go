package main

import "os"

func getLogPath() string {
	return os.TempDir() + "/armorshield/backend.log"
}
