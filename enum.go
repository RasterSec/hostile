package main

import (
	"log"
)

type Detection struct {
	Container      bool   `json:"container_detected"`
	ContainerName  string `json:"container_name"`
	VM             bool   `json:"vm_detected"`
	HypervisorName string `json:"hypervisor_name"`
	Platform       bool   `json:"platform_detected"`
	PlatformName   string `json:"platform_name"`
}

func DetectVirt() Detection {
	var env Detection
	if isContainer, c := DetectContainer(); isContainer {
		env.Container = true
		env.ContainerName = c
		log.Println("Container detected. Skipping hypervisor checks.")
	} else {
		if isVM, v := DetectVM(); isVM {
			env.VM = true
			env.HypervisorName = v
		}
	}
	if isPlatform, p := DetectPlatform(); isPlatform {
		env.Platform = true
		env.PlatformName = p
	}
	return env
}
