package main

import (
	"log"
	"os"
	"strings"
)

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
