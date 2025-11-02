package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
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

func DetectContainer() (bool, string) {
	if IsLXC() {
		return true, "lxc"
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

func DetectVM() (bool, string) {
	if IsKVM() {
		return true, "kvm"
	}
	if IsXen() {
		return true, "xen"
	}
	if IsHyperV() {
		return true, "hyperv"
	}
	if IsVMware() {
		return true, "vmware"
	}
	return false, ""
}

func IsKVM() bool {
	dmiPaths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/bios_vendor",
	}

	for _, path := range dmiPaths {
		if data, err := os.ReadFile(path); err == nil {
			content := strings.ToLower(string(data))
			if strings.Contains(content, "qemu") || strings.Contains(content, "kvm") || strings.Contains(content, "bochs") {
				log.Println("[VM][QEMU/KVM] DMI contains qemu/kvm/bochs")
				return true
			}
		}
	}

	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "hypervisor") && strings.Contains(content, "qemu") {
			log.Println("[VM][QEMU/KVM] cpuinfo contains qemu")
			return true
		}
	}

	return false
}

func IsXen() bool {
	if _, err := os.Stat("/proc/xen"); err == nil {
		log.Println("[VM][Xen] /proc/xen exists")
		return true
	}

	if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		if strings.Contains(string(data), "xen") {
			log.Println("[VM][Xen] /sys/hypervisor/type contains xen")
			return true
		}
	}

	// Check for Xen devices - must have at least one device
	if entries, err := os.ReadDir("/sys/bus/xen/devices"); err == nil {
		if len(entries) > 0 {
			log.Println("[VM][Xen] /sys/bus/xen/devices not empty")
			return true
		}
	}
	return false
}

func IsHyperV() bool {
	dmiPaths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
	}

	for _, path := range dmiPaths {
		if data, err := os.ReadFile(path); err == nil {
			content := strings.ToLower(string(data))
			if strings.Contains(content, "microsoft corporation") || strings.Contains(content, "virtual machine") {
				if strings.Contains(content, "microsoft") {
					log.Println("[VM][Hyper-V] DMI contains Microsoft")
					return true
				}
			}
		}
	}

	if data, err := os.ReadFile("/proc/modules"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "hv_vmbus") || strings.Contains(content, "hv_storvsc") || strings.Contains(content, "hyperv") {
			log.Println("[VM][Hyper-V] /proc/modules contains Hyper-V modules")
			return true
		}
	}
	return false
}

func DetectPlatform() (bool, string) {
	if IsProxmox() {
		return true, "proxmox"
	}
	if IsOpenStack() {
		return true, "openstack"
	}
	return false, ""
}

func IsProxmox() bool {
	// Check for Proxmox-specific MAC address prefix BC:24:11
	entries, err := os.ReadDir("/sys/class/net")
	if err == nil {
		for _, entry := range entries {
			if entry.Name() == "lo" {
				continue
			}
			if data, err := os.ReadFile("/sys/class/net/" + entry.Name() + "/address"); err == nil {
				mac := strings.ToUpper(strings.TrimSpace(string(data)))
				if strings.HasPrefix(mac, "BC:24:11") {
					log.Println("[Platform][Proxmox] Found default Proxmox MAC prefix (heuristic)")
					return true
				}
			}
		}
	}

	return false
}

func IsVMware() bool {
	dmiPaths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/bios_vendor",
		"/sys/class/dmi/id/board_vendor",
	}

	for _, path := range dmiPaths {
		if data, err := os.ReadFile(path); err == nil {
			content := strings.ToLower(string(data))
			if strings.Contains(content, "vmware") || strings.Contains(content, "vmw") {
				log.Println("[VM][VMware] DMI contains vmware")
				return true
			}
		}
	}

	if data, err := os.ReadFile("/proc/modules"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "vmw_") || strings.Contains(content, "vmxnet") {
			log.Println("[VM][VMware] VMware modules found")
			return true
		}
	}

	return false
}

func IsOpenStack() bool {
	// Try to reach OpenStack metadata service (with timeout)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://169.254.169.254/openstack/")
	if err == nil {
		resp.Body.Close()
		log.Println("[Platform][OpenStack] Metadata endpoint found: http://169.254.169.254 ")
		return true
	}

	// Check for config drive
	if _, err := os.Stat("/dev/disk/by-label/config-2"); err == nil {
		log.Println("[Platform][OpenStack] Config drive found /dev/disk/by-label/config-2")
		return true
	}

	dmiPaths := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/chassis_asset_tag",
	}

	for _, path := range dmiPaths {
		if data, err := os.ReadFile(path); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "openstack") {
				log.Println("[Platform][OpenStack] DMI contains openstack")
				return true
			}
		}
	}

	return false
}
