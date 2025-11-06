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

	switch config.Mode {
	case "detect":
		detection := DetectVirt()
		printDetectionResults(detection)
	case "scan":
		detection := DetectVirt()
		printDetectionResults(detection)
		runRelevantChecks(detection)
	case "network":
		NetworkChecks()
	case "all":
		detection := DetectVirt()
		printDetectionResults(detection)
		runRelevantChecks(detection)
		NetworkChecks()
	}
}

func printDetectionResults(d Detection) {
	if d.Container {
		log.Printf("Container: %s, Platform: %s", d.ContainerName, d.PlatformName)
	} else if d.VM {
		log.Printf("VM: %s, Platform: %s", d.HypervisorName, d.PlatformName)

	} else {
		log.Println("No virtualization or container technology detected")
	}
}

func runRelevantChecks(d Detection) {
	if d.Container {
		if d.ContainerName == "lxc" {
			CheckLXCPrivilegedContainer()
			CheckLXCCgroupLimits()
			CheckIPv6RouterAdvertisements()
		}
	}
}
