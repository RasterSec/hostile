package main

import (
	"log"
	"os"
	"strings"
)

func DetectContainer() (bool, string) {
	if IsLXC() {
		return true, "lxc"
	}
	if IsOpenVZ() {
		return true, "openvz"
	}
	return false, ""
}

func IsLXC() bool {
	// Check cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "lxc") || strings.Contains(content, "lxd") {
			log.Println("[Container][LXC] /proc/1/cgroup contains lxc/lxd")
			return true
		}
	}

	// Check container environment
	if data, err := os.ReadFile("/proc/1/environ"); err == nil {
		if strings.Contains(string(data), "container=lxc") {
			log.Println("[Container][LXC] /proc/1/environ contains container=lxc")
			return true
		}
	}

	// Check systemd container file
	if data, err := os.ReadFile("/run/systemd/container"); err == nil {
		if strings.Contains(string(data), "lxc") {
			log.Println("[Container][LXC] /run/systemd/container contains lxc")
			return true
		}
	}

	return false
}

func IsOpenVZ() bool {
	// Check for user_beancounters (most reliable indicator)
	if _, err := os.Stat("/proc/user_beancounters"); err == nil {
		log.Println("[Container][OpenVZ] /proc/user_beancounters exists")
		return true
	}

	// Check for vz directory
	if _, err := os.Stat("/proc/vz"); err == nil {
		// Additional check: ensure we're in container, not host
		// In container, /proc/vz exists but is usually empty or limited
		if _, err := os.Stat("/proc/bc"); err == nil {
			log.Println("[Container][OpenVZ] /proc/vz and /proc/bc exist")
			return true
		}
	}

	// Check envID in process status
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "envID:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] != "0" {
					log.Println("[Container][OpenVZ] /proc/self/status contains non-zero envID")
					return true
				}
			}
		}
	}

	// Check cgroup for openvz
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "openvz") {
			log.Println("[Container][OpenVZ] /proc/1/cgroup contains openvz")
			return true
		}
	}

	// Check for simfs filesystem
	if data, err := os.ReadFile("/proc/filesystems"); err == nil {
		if strings.Contains(string(data), "simfs") {
			log.Println("[Container][OpenVZ] /proc/filesystems contains simfs")
			return true
		}
	}

	return false
}
