package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func getARPCache() (map[string]string, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	arpTable := make(map[string]string)
	scanner := bufio.NewScanner(file)

	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			ip := fields[0]
			mac := fields[3]
			arpTable[ip] = mac
		}
	}

	return arpTable, scanner.Err()
}

func MacToLinkLocal(mac net.HardwareAddr) net.IP {
	// EUI-64 conversion: Insert FF:FE in the middle and flip U/L bit
	if len(mac) != 6 {
		return nil
	}

	eui64 := make([]byte, 8)
	copy(eui64[0:3], mac[0:3])
	eui64[3] = 0xff
	eui64[4] = 0xfe
	copy(eui64[5:8], mac[3:6])

	// Flip the universal/local bit (7th bit of first byte)
	eui64[0] ^= 0x02

	// Create fe80:: prefix + interface ID
	ip := make(net.IP, 16)
	ip[0] = 0xfe
	ip[1] = 0x80
	copy(ip[8:], eui64)

	return ip
}

func LinkLocalAccess() {
	timeout := 2 * time.Second

	log.Println("\nGenerating link-local addresses from ARP cache:")
	arpCache, err := getARPCache()
	if err != nil {
		log.Printf("Error reading ARP cache: %v\n", err)
		return
	}

	for ipv4Str, macStr := range arpCache {
		// Skip incomplete entries
		if macStr == "00:00:00:00:00:00" {
			continue
		}

		mac, err := net.ParseMAC(macStr)
		if err != nil {
			continue
		}

		// Generate IPv6 link-local from MAC
		linkLocal := MacToLinkLocal(mac)
		if linkLocal == nil {
			continue
		}

		up := PingIP(linkLocal, timeout, config.Interface)
		if up {
			log.Printf("[NETWORK] Neighbors can be accessed via IPv6 link-local. IPv4: %s, Link-local: %s.", ipv4Str, linkLocal)
			return
		}
	}
	log.Println("Accessing neighbors via link-local is not possible")
}
