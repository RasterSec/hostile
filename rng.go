package main

import (
	"log"
	"os"
)

func CheckRNG() bool {
	if val, err := os.ReadFile("/sys/devices/virtual/misc/hw_random/rng_current"); err == nil {
		if string(val) == "none" {
			log.Println("[RNG] No RNG device found")
			return false
		} else {
			log.Printf("[RNG] Device found: %s", string(val))
			return true
		}
	} else {
		log.Printf("Failed to check for RNG device: %s", err.Error())
	}
	return false
}
