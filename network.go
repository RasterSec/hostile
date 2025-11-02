package main

import (
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
)

func NetworkChecks() {
	if config.Ipv4 {
		log.Println("Testing IPv4 network")
		TestNetwork(netlink.FAMILY_V4)
	} else if config.Ipv6 {
		log.Println("Testing IPv6 network")
		TestNetwork(netlink.FAMILY_V6)
	} else {
		log.Println("Testing IPv4 network")
		TestNetwork(netlink.FAMILY_V4)
		log.Println("Testing IPv6 network")
		TestNetwork(netlink.FAMILY_V6)
	}
	LinkLocalAccess()
}

func TestNetwork(family int) error {
	familyName := "IPv4"
	if family == netlink.FAMILY_V6 {
		familyName = "IPv6"
	}

	if config.Interface == "" {
		var err error
		config.Interface, err = GetDefaultInterface(family)
		if err != nil {
			log.Printf("Failed to detect the default network interface. Specify it with -interface: %s", err.Error())
			return err
		}
		log.Printf("Detected interface with default route or public address: %s", config.Interface)
	}

	addr, err := GetInterfaceAddr(config.Interface, family)
	if err != nil {
		log.Printf("Failed to get interface address: %s", err.Error())
		return err
	}

	externalIP, err := GetExternalIP(family)
	if err != nil {
		log.Printf("Failed to get external IP address: %s", err.Error())
		return err
	}

	if !addr.IP.Equal(net.ParseIP(externalIP)) {
		log.Printf("[NETWORK][%s][%s] NAT detected. External IP: %s, Interface IP: %s",
			config.Interface, familyName, externalIP, addr.IP.String())
	}

	neighborIP, err := FindLiveNeighbor(addr.IPNet, 20, 2*time.Second, config.Interface)
	if err != nil {
		log.Println(err.Error())
	} else {
		log.Printf("[NETWORK] Neighbor reachable: %s", neighborIP)
	}

	if config.IP != "" {
		neighborIP = net.ParseIP(config.IP)
	}

	// Attempt IP spoofing
	if err := SpoofIP(config.Interface, addr.IPNet.IP, neighborIP, addr.IPNet.Mask); err != nil {
		log.Printf("Spoofing failed: %s", err.Error())
	}

	return nil
}

// generateNeighborIPs finds neighboring IP addresses or network blocks
func generateNeighborIPs(prefix netip.Prefix, maxCount int) []netip.Prefix {
	var neighbors []netip.Prefix
	seen := make(map[netip.Addr]bool)
	addr := prefix.Addr()
	bits := prefix.Bits()
	seen[addr] = true // Don't include our own address

	// Calculate how many IPs to skip for network blocks
	blockSize := 1
	if bits < addr.BitLen() {
		// For subnets, jump by the block size
		blockSize = 1 << (addr.BitLen() - bits)
	}

	for offset := 1; len(neighbors) < maxCount; offset++ {
		if len(neighbors) < maxCount {
			candidate := addr
			for i := 0; i < offset*blockSize; i++ {
				candidate = candidate.Next()
			}
			if candidate.IsValid() && !seen[candidate] {
				seen[candidate] = true
				neighbors = append(neighbors, netip.PrefixFrom(candidate, bits))
			}
		}

		if len(neighbors) < maxCount {
			candidate := addr
			for i := 0; i < offset*blockSize; i++ {
				candidate = candidate.Prev()
			}
			if candidate.IsValid() && !seen[candidate] {
				seen[candidate] = true
				neighbors = append(neighbors, netip.PrefixFrom(candidate, bits))
			}
		}
	}

	return neighbors
}
