package main

import (
	"flag"
)

type HostileConfig struct {
	Enumerate    bool
	All          bool
	Spoof        bool
	Check        string
	OutputFormat string
	OutputFile   string
}

var config HostileConfig

func parseArgs() {
	flag.BoolVar(&config.Enumerate, "enum", false, "Discover container/hypervisor and resources")
	flag.BoolVar(&config.Spoof, "spoof", false, "Attempt IPv4 and IPv6 spoofing attacks")
	flag.BoolVar(&config.All, "all", false, "Enumerate, perform checks and attempt network spoofing")
	flag.StringVar(&config.Check, "check", "all", "Perform hardening checks. Default: all (runs enum first). Values: lxc, proxmox, xen, hyperv, vmware, all.")
	flag.StringVar(&config.OutputFormat, "output-format", "text", "Output format. Default: text. Values: html, text, json.")
	flag.StringVar(&config.OutputFile, "output-file", "hostile-report", "Name of the output report file")
	flag.Parse()
}
