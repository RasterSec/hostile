package main

import "log"

func main() {
	parseArgs()
	if config.All || config.Enumerate {
		detection := DetectVirt()
		log.Printf("%v", detection)
	}
}
