package main

import (
	"log"
	"os"
)

func main() {
	parseArgs()
	if os.Geteuid() != 0 {
		log.Fatal("This program requires root privileges. Please run with sudo.")
	}

	if config.Mode == "enum" || config.Mode == "all" {
		detection := DetectVirt()
		log.Printf("%v", detection)
	}

	if config.Mode == "network" {
		NetworkChecks()
	}
}
