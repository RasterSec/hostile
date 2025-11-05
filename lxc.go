package main

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

func CheckLXCPrivilegedContainer() bool {
	// Check if we're running as UID 0 and if it maps to host UID 0
	// In unprivileged containers, UID 0 in container maps to high UID on host
	uidMapPath := "/proc/self/uid_map"
	data, err := os.ReadFile(uidMapPath)
	if err != nil {
		log.Printf("[LXC][PrivilegedContainer] Could not read %s: %v\n", uidMapPath, err)
		return true
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			nsUID, _ := strconv.Atoi(fields[0])
			hostUID, _ := strconv.Atoi(fields[1])

			if nsUID == 0 && hostUID == 0 {
				log.Println("[LXC][PrivilegedContainer] WARNING: Container is PRIVILEGED (UID 0 maps to host UID 0)")
				return false
			}
		}
	}

	log.Println("[LXC][PrivilegedContainer] Container is unprivileged (safe)")
	return true
}

func CheckLXCCgroupLimits() bool {
	hasLimits := false

	cgroupV2Checks := map[string]string{
		"memory.max": "/sys/fs/cgroup/memory.max",
		"cpu.max":    "/sys/fs/cgroup/cpu.max",
		"pids.max":   "/sys/fs/cgroup/pids.max",
	}

	for limitName, path := range cgroupV2Checks {
		if data, err := os.ReadFile(path); err == nil {
			value := strings.TrimSpace(string(data))
			if value != "max" && value != "" {
				log.Printf("[LXC][CgroupLimits] %s is limited: %s\n", limitName, value)
				hasLimits = true
			}
		}
	}

	cgroupV1Checks := map[string]string{
		"memory.limit_in_bytes": "/sys/fs/cgroup/memory/memory.limit_in_bytes",
		"cpu.cfs_quota_us":      "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
		"pids.max":              "/sys/fs/cgroup/pids/pids.max",
	}

	for limitName, path := range cgroupV1Checks {
		if data, err := os.ReadFile(path); err == nil {
			value := strings.TrimSpace(string(data))
			switch limitName {
			case "memory.limit_in_bytes":
				if val, err := strconv.ParseInt(value, 10, 64); err == nil {
					// 9223372036854771712 is a common "unlimited" value
					if val < 9223372036854771712 {
						log.Printf("[LXC][CgroupLimits] %s is limited: %s bytes\n", limitName, value)
						hasLimits = true
					}
				}
			case "cpu.cfs_quota_us":
				if value != "-1" {
					log.Printf("[LXC][CgroupLimits] %s is limited: %s\n", limitName, value)
					hasLimits = true
				}
			case "pids.max":
				if value != "max" {
					log.Printf("[LXC][CgroupLimits] %s is limited: %s\n", limitName, value)
					hasLimits = true
				}
			}
		}
	}

	if !hasLimits {
		log.Println("[LXC][CgroupLimits] WARNING: No cgroup resource limits detected (DoS risk)")
		return false
	}

	log.Println("[LXC][CgroupLimits] Container has cgroup resource limits")
	return true
}

func CheckIPv6RouterAdvertisements() bool {
	links, err := netlink.LinkList()
	if err != nil {
		log.Printf("[LXC][IPv6RA] ERROR: Failed to enumerate network interfaces: %v\n", err)
		return false
	}

	if len(links) == 0 {
		log.Println("[LXC][IPv6RA] No network interfaces found")
		return true
	}

	hasVulnerability := false
	checkedInterfaces := 0

	for _, link := range links {
		ifaceName := link.Attrs().Name
		acceptRAPath := "/proc/sys/net/ipv6/conf/" + ifaceName + "/accept_ra"

		data, err := os.ReadFile(acceptRAPath)
		if err != nil {
			// Interface might not support IPv6 or path doesn't exist
			log.Printf("[LXC][IPv6RA] %s: Unable to read accept_ra (may not support IPv6)\n", ifaceName)
			continue
		}

		value := strings.TrimSpace(string(data))
		acceptRA, err := strconv.Atoi(value)
		if err != nil {
			log.Printf("[LXC][IPv6RA] %s: Unable to parse accept_ra value: %s\n", ifaceName, value)
			continue
		}

		checkedInterfaces++

		if acceptRA > 0 {
			log.Printf("[LXC][IPv6RA] WARNING: %s accept_ra is set to %d (accepts malicious router advertisements)\n",
				ifaceName, acceptRA)
			hasVulnerability = true
		} else {
			log.Printf("[LXC][IPv6RA] %s accept_ra is set to %d (safe)\n", ifaceName, acceptRA)
		}
	}

	if checkedInterfaces == 0 {
		log.Println("[LXC][IPv6RA] WARNING: No interfaces could be checked for accept_ra settings")
		return false
	}

	if hasVulnerability {
		log.Println("[LXC][IPv6RA] Recommendation: Set accept_ra to 0 for all interfaces")
		return false
	}

	log.Printf("[LXC][IPv6RA] All %d checked interfaces have safe accept_ra settings\n", checkedInterfaces)
	return true
}

func RunLXCChecks() bool {
	privilegedCheck := CheckLXCPrivilegedContainer()
	cgroupCheck := CheckLXCCgroupLimits()
	ipv6RACheck := CheckIPv6RouterAdvertisements()

	allPassed := privilegedCheck && cgroupCheck && ipv6RACheck

	if allPassed {
		log.Println("[LXC][Summary] All security checks PASSED")
	} else {
		log.Println("[LXC][Summary] Some security checks FAILED - review warnings above")
	}

	return allPassed
}
