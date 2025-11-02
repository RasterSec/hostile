package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func createInterfaceBoundDialer(iface string) (*net.Dialer, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found on interface %s: %w", iface, err)
	}

	var localAddr net.IP
	for _, addr := range addrs {
		if !addr.IP.IsLinkLocalUnicast() {
			localAddr = addr.IP
			break
		}
	}

	if localAddr == nil {
		localAddr = addrs[0].IP
	}

	// Create a dialer that binds to the specific interface address
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: localAddr,
		},
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return dialer, nil
}

func GetExternalIPFromInterface(iface string) (string, error) {
	dialer, err := createInterfaceBoundDialer(iface)
	if err != nil {
		return "", fmt.Errorf("failed to create interface-bound dialer: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}

	req, err := http.NewRequest("GET", "http://ip.me", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "curl/8.0.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	ipStr := strings.TrimSpace(string(body))
	if net.ParseIP(ipStr) == nil {
		return "", fmt.Errorf("invalid IP address received: %s", ipStr)
	}

	return ipStr, nil
}

func GetExternalIPFromInterfaceWithTimeout(iface string, timeout time.Duration) (string, error) {
	type result struct {
		ip  string
		err error
	}

	ch := make(chan result, 1)

	go func() {
		ip, err := GetExternalIPFromInterface(iface)
		ch <- result{ip, err}
	}()

	select {
	case res := <-ch:
		return res.ip, res.err
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout after %v - likely lost connectivity", timeout)
	}
}

func SpoofIP(iface string, originalIP, newIP net.IP, mask net.IPMask) error {
	log.Println("Adding neighbor IP...")
	if err := AddIP(iface, newIP, mask); err != nil {
		return fmt.Errorf("failed to add new IP: %w", err)
	}

	time.Sleep(1 * time.Second)

	log.Println("Removing original IP...")
	if err := DeleteIP(iface, originalIP, mask); err != nil {
		DeleteIP(iface, newIP, mask)
		return fmt.Errorf("failed to remove original IP: %w", err)
	}

	time.Sleep(1 * time.Second)

	log.Println("Testing connectivity with new IP...")
	detectedIP, err := GetExternalIPFromInterfaceWithTimeout(iface, 15*time.Second)

	if err != nil {
		log.Printf("Failed to connect with new IP: %v", err)
		log.Println("Reverting IP changes...")

		AddIP(iface, originalIP, mask)
		DeleteIP(iface, newIP, mask)

		return fmt.Errorf("connectivity test failed: %w", err)
	}

	log.Printf("Detected IP: %s", detectedIP)
	if detectedIP == newIP.String() {
		log.Println("[NETWORK] IP successfully spoofed!")
		return nil
	}

	log.Printf("MISMATCH: expected %s, got %s", newIP, detectedIP)
	return fmt.Errorf("IP mismatch after change")
}

func FindLiveNeighbor(ipnet *net.IPNet, maxTries int, timeout time.Duration, iface string) (net.IP, error) {
	prefix, err := netip.ParsePrefix(ipnet.String())
	if err != nil {
		return nil, fmt.Errorf("invalid prefix: %w", err)
	}

	neighbors := generateNeighborIPs(prefix, maxTries)

	for _, neighborPrefix := range neighbors {
		ip := net.IP(neighborPrefix.Addr().AsSlice())
		log.Printf("Trying to ping %s...", ip)

		if PingIP(ip, timeout, iface) {
			log.Printf("%s is UP!", ip)
			return ip, nil
		}

		log.Printf("%s is down", ip)
	}

	return nil, fmt.Errorf("no live neighbors found after %d attempts", maxTries)
}

func PingIP(ip net.IP, timeout time.Duration, iface string) bool {
	isIPv6 := ip.To4() == nil
	var network, address string
	var icmpType icmp.Type

	if isIPv6 {
		network = "ip6:ipv6-icmp"
		address = "::"
		icmpType = ipv6.ICMPTypeEchoRequest
	} else {
		network = "ip4:icmp"
		address = "0.0.0.0"
		icmpType = ipv4.ICMPTypeEcho
	}

	conn, err := icmp.ListenPacket(network, address)
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PING"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	dest := &net.IPAddr{IP: ip}
	if isIPv6 && ip.IsLinkLocalUnicast() && iface != "" {
		dest.Zone = iface
	}

	if _, err := conn.WriteTo(msgBytes, dest); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	reply := make([]byte, 1500)
	_, _, err = conn.ReadFrom(reply)
	return err == nil
}

func GetInterfaceAddr(interfaceName string, family int) (*netlink.Addr, error) {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}

	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses: %w", err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for interface %s", interfaceName)
	}

	if family == netlink.FAMILY_V6 {
		for _, addr := range addrs {
			if !addr.IP.IsLinkLocalUnicast() {
				return &addr, nil
			}
		}
		return nil, fmt.Errorf("no global IPv6 address found on interface %s", interfaceName)
	}

	return &addrs[0], nil
}

func GetExternalIP(family int) (string, error) {
	// Determine network type based on family
	network := "tcp4"
	if family == netlink.FAMILY_V6 {
		network = "tcp6"
	}

	// Create HTTP client with custom dialer
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout: 10 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}

	req, err := http.NewRequest("GET", "http://ip.me", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "curl/8.0.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	ipStr := strings.TrimSpace(string(body))
	if net.ParseIP(ipStr) == nil {
		return "", fmt.Errorf("invalid IP address received: %s", ipStr)
	}

	return ipStr, nil
}
