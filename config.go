package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

type HostileConfig struct {
	Mode string
	// Scan options
	Tech string
	// Network options
	Spoof     bool
	Interface string
	Ipv4      bool
	Ipv6      bool
	IP        string
	// Global options
	OutputFormat string
	OutputFile   string
}

var config HostileConfig

func parseArgs() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	config.Mode = os.Args[1]

	switch config.Mode {
	case "detect":
		detectCmd := flag.NewFlagSet("detect", flag.ExitOnError)
		detectCmd.String("output-format", "text", "Output format (html, text, json)")
		detectCmd.String("output-file", "hostile-report", "Name of the output report file")
		detectCmd.Parse(os.Args[2:])
		config.OutputFormat = getStringFlag(detectCmd, "output-format")
		config.OutputFile = getStringFlag(detectCmd, "output-file")

	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		scanCmd.String("tech", "all", "Technology to scan (lxc, proxmox, xen, hyperv, vmware, all)")
		scanCmd.String("output-format", "text", "Output format (html, text, json)")
		scanCmd.String("output-file", "hostile-report", "Name of the output report file")
		scanCmd.Parse(os.Args[2:])
		config.Tech = getStringFlag(scanCmd, "tech")
		config.OutputFormat = getStringFlag(scanCmd, "output-format")
		config.OutputFile = getStringFlag(scanCmd, "output-file")

	case "network":
		networkCmd := flag.NewFlagSet("network", flag.ExitOnError)
		networkCmd.Bool("spoof", false, "Enable spoofing")
		networkCmd.String("interface", "", "Interface to use for spoofing")
		networkCmd.Bool("ipv4", false, "Spoof IPv4")
		networkCmd.Bool("ipv6", false, "Spoof IPv6")
		networkCmd.String("ip", "", "Set this IP when spoofing")
		networkCmd.String("output-format", "text", "Output format (html, text, json)")
		networkCmd.String("output-file", "hostile-report", "Name of the output report file")
		networkCmd.Parse(os.Args[2:])
		config.Spoof = getBoolFlag(networkCmd, "spoof")
		config.Interface = getStringFlag(networkCmd, "interface")
		config.Ipv4 = getBoolFlag(networkCmd, "ipv4")
		config.Ipv6 = getBoolFlag(networkCmd, "ipv6")
		config.IP = getStringFlag(networkCmd, "ip")
		config.OutputFormat = getStringFlag(networkCmd, "output-format")
		config.OutputFile = getStringFlag(networkCmd, "output-file")

		// Auto-detect IP version if -ip is provided
		if config.IP != "" {
			ip := net.ParseIP(config.IP)
			if ip == nil {
				fmt.Printf("Error: invalid IP address: %s\n", config.IP)
				os.Exit(1)
			}

			// If user didn't explicitly set ipv4 or ipv6, auto-detect
			if !config.Ipv4 && !config.Ipv6 {
				if ip.To4() != nil {
					config.Ipv4 = true
				} else {
					config.Ipv6 = true
				}
			}
		}

	case "all":
		allCmd := flag.NewFlagSet("all", flag.ExitOnError)
		allCmd.String("output-format", "text", "Output format (html, text, json)")
		allCmd.String("output-file", "hostile-report", "Name of the output report file")
		allCmd.Parse(os.Args[2:])
		config.OutputFormat = getStringFlag(allCmd, "output-format")
		config.OutputFile = getStringFlag(allCmd, "output-file")

	default:
		fmt.Printf("Unknown command: %s\n", config.Mode)
		printUsage()
		os.Exit(1)
	}
}

func getStringFlag(fs *flag.FlagSet, name string) string {
	return fs.Lookup(name).Value.String()
}

func getBoolFlag(fs *flag.FlagSet, name string) bool {
	return fs.Lookup(name).Value.String() == "true"
}

func printUsage() {
	fmt.Println("Usage: hostile <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  detect               Discover container/hypervisor and resources")
	fmt.Println("  scan                 Perform security hardening checks")
	fmt.Println("  network              Network spoofing operations")
	fmt.Println("  all                  Run all operations")
	fmt.Println("\nGlobal Options:")
	fmt.Println("  -output-format       Output format (html, text, json) [default: text]")
	fmt.Println("  -output-file         Name of output report file [default: hostile-report]")
	fmt.Println("\nScan Options:")
	fmt.Println("  -tech                Technology to scan (lxc, proxmox, xen, hyperv, vmware, all) [default: all]")
	fmt.Println("\nNetwork Options:")
	fmt.Println("  -spoof               Enable spoofing")
	fmt.Println("  -interface           Interface to use for spoofing")
	fmt.Println("  -ipv4                Spoof IPv4 (auto-detected if -ip is provided)")
	fmt.Println("  -ipv6                Spoof IPv6 (auto-detected if -ip is provided)")
	fmt.Println("  -ip                  Set this IP when spoofing (auto-detects IPv4/IPv6)")
	fmt.Println("\nExamples:")
	fmt.Println("  hostile detect")
	fmt.Println("  hostile scan -tech lxc -output-format json")
	fmt.Println("  hostile network -spoof -ip 1.2.3.4 -interface eth0")
	fmt.Println("  hostile network -spoof -ipv6 -interface eth0")
	fmt.Println("  hostile all -output-file my-report")
}
