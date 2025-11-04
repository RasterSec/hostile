# Hostile

**Host**ile is a framework and tooling for security testing virtualized environments such as hosting provider infrastructure. It provides guides on how to harden common hypervisors and containers.

Hostile is intended to be ran from inside of a Linux VM (eg. a VPS). It's useful for conducting black box penetration tests in virtualized environments. Instead of suggesting CVEs based on vulnerable versions, Hostile searches for common misconfigurations.

Enumeration and checks for:

- Containers:
    * LXC/LXD
    * OpenVZ
- Hypervisors:
    * Xen
    * VMware
    * KVM/QEMU
    * Hyper-V
- Platforms:
    * Proxmox
    * XCP-NG
    * OpenStack
    * SolusVM
- Network:
    * IPv4 spoofing
    * IPv6 spoofing
    * Host/router access
- Misc:
    * Cloud-init scripts/configuration

## Features

- Hypervisor/container/platform enumeration
- Network security tests
- Hardening checks
- HTML reports

Here is a list of hardening checks implented. For detailed explanations and references see the [Hostile wiki]().