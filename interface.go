package main

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func GetDefaultInterface(family int) (string, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return "", fmt.Errorf("failed to get routes: %w", err)
	}

	isIPv6 := (family == netlink.FAMILY_V6)
	defaultRoute := "0.0.0.0/0"
	if isIPv6 {
		defaultRoute = "::/0"
	}

	// Find the default route
	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == defaultRoute {
			if route.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(route.LinkIndex)
				if err != nil {
					continue
				}
				return link.Attrs().Name, nil
			}
		}
	}

	// Fallback: find first non-loopback interface with an IP of the requested family
	links, err := netlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %w", err)
	}

	for _, link := range links {
		if link.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}
		if link.Attrs().Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := netlink.AddrList(link, family)
		if err != nil || len(addrs) == 0 {
			continue
		}

		// For IPv6, skip link-local only
		if isIPv6 {
			hasGlobal := false
			for _, addr := range addrs {
				if !addr.IP.IsLinkLocalUnicast() {
					hasGlobal = true
					break
				}
			}
			if !hasGlobal {
				continue
			}
		}

		return link.Attrs().Name, nil
	}

	return "", fmt.Errorf("no suitable network interface found for family %d", family)
}

func AddIP(interfaceName string, ip net.IP, mask net.IPMask) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: mask,
		},
	}

	return netlink.AddrAdd(link, addr)
}

func DeleteIP(interfaceName string, ip net.IP, mask net.IPMask) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: mask,
		},
	}

	return netlink.AddrDel(link, addr)
}
