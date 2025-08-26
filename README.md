# VLAN Scout

A high-performance network VLAN discovery tool that identifies active VLANs and their configurations through passive network monitoring and active probing.

## Overview

VLAN Scout monitors network traffic to discover VLAN configurations by analyzing:

- DHCP responses (IPv4 and IPv6)
- IPv6 Router Advertisements (SLAAC)
- ARP replies
- IPv6 Neighbor Discovery Protocol (NDP)
- LLDP (Link Layer Discovery Protocol) packets
- CDP (Cisco Discovery Protocol) packets
- General IPv4/IPv6 traffic

The tool passively listens for network activity while optionally sending active probes to trigger responses from network infrastructure.

## Features

- **Multi-protocol Support**: IPv4 DHCP, IPv6 DHCPv6, IPv6 SLAAC, ARP, NDP, LLDP, CDP
- **High Performance**: Optimized packet processing with pre-allocated parsers
- **Passive & Active Discovery**: Monitor existing traffic or send probes
- **Comprehensive Output**: JSON and human-readable formats
- **Cross-platform**: Linux, macOS, Windows support
- **Zero Dependencies**: Single binary with no external requirements

## Installation

### Pre-built Binaries

Download the latest release from the [GitHub releases page](https://github.com/lanrat/vlan-scout/releases).

### Build from Source

**Prerequisites:**

- Go 1.20 or later
- GCC compiler
- libpcap development headers

**Ubuntu/Debian:**

```bash
sudo apt install -y libpcap-dev gcc
make build
```

**macOS:**

```bash
# Install dependencies with Homebrew
brew install libpcap
make build
```

**Windows:**

```bash
# Requires WinPcap or Npcap installed
go build
```

## Usage

### Quick Start

**List available network interfaces:**

```bash
sudo ./vlan-scout -list
```

**Basic VLAN discovery (passive monitoring):**

```bash
sudo ./vlan-scout -iface eth0
```

**Active discovery with all probes (shortcut):**

```bash
sudo ./vlan-scout -iface eth0 -all
```

**Active discovery with specific probes:**

```bash
sudo ./vlan-scout -iface eth0 -dhcp -dhcp6 -ra
```

**Scan specific VLANs:**

```bash
sudo ./vlan-scout -iface eth0 -dhcp -vlans 1,2,4,60-70,90
```

**Output results in JSON format:**

```bash
sudo ./vlan-scout -iface eth0 -all -json
```

### Command Line Options

```text
Usage of ./vlan-scout:
  -all
     enable all active discovery methods (dhcp + dhcp6 + ra)
  -dhcp
     enable DHCP requests
  -dhcp6
     enable IPv6 DHCP requests
  -hostname string
     hostname to use for dhcp requests (default "vlan-scout")
  -iface string
     interface to test
  -json
     output to json
  -list
     print interface list and exit
  -mac string
     mac address to use for dhcp requests (default "12:34:56:78:90:AB")
  -print-packets
     print packets for debugging
  -ra
     request IPv6 router advertisements
  -random-mac
     use random mac address
  -timeout duration
     timeout to wait for responses
  -verbose
     print verbose output
  -version
     print version and exit
  -vlans string
     comma-separated VLAN list (e.g., 1,2,4,60-70,90), defaults to all
  -workers int
     number of parallel workers for VLAN scanning (default 10)
```

## Output Examples

### Human-readable Format

```text
VLAN Discovery Results:

VLAN 100:
  ├─ IPv4 DHCP: 192.168.100.0/24 (GW: 192.168.100.1, Server: 192.168.100.1)
  ├─ IPv6 SLAAC: 2001:db8:100::/64 (GW: fe80::1)
  ├─ IPv4 Hosts: 192.168.100.10, 192.168.100.20
  ├─ IPv6 Hosts: 2001:db8:100::5
  ├─ LLDP Device: sw01.example.com (Port: GigabitEthernet1/0/1) [Bridge, Router]
  └─ CDP Device: Router-01 (Port: FastEthernet0/1) [Router] - IPs: 192.168.100.1

VLAN 200:
  ├─ IPv4 DHCP: 10.0.200.0/24 (GW: 10.0.200.1, Server: 10.0.200.5)
  ├─ IPv4 Hosts: 10.0.200.15, 10.0.200.30
  └─ LLDP Device: switch-core.lan (Port: eth2) [Bridge] - IPs: 10.0.200.1
```

### JSON Format

```json
{
  "vlans": {
    "100": {
      "ipv4_dhcp": {
        "ip": "192.168.100.26/24",
        "gateway": "192.168.100.1",
        "server": "192.168.100.1"
      },
      "ipv6_slaac": {
        "ip": "2001:db8:100::/64", 
        "gateway": "fe80::1"
      },
      "hosts": {
        "ipv4": ["192.168.100.10", "192.168.100.20"],
        "ipv6": ["2001:db8:100::5"]
      },
      "devices": [
        {
          "name": "sw01.example.com",
          "port": "GigabitEthernet1/0/1", 
          "type": "LLDP",
          "description": "Cisco switch running IOS 15.2",
          "mgmt_ips": ["192.168.100.1"],
          "capabilities": ["Bridge", "Router"]
        }
      ]
    },
    "200": {
      "ipv4_dhcp": {
        "ip": "10.0.200.0/24",
        "gateway": "10.0.200.1",
        "server": "10.0.200.5"
      },
      "hosts": {
        "ipv4": ["10.0.200.15", "10.0.200.30"]
      },
      "devices": [
        {
          "name": "Router-01",
          "port": "FastEthernet0/1",
          "type": "CDP", 
          "description": "Cisco 2960 running IOS 12.2",
          "mgmt_ips": ["10.0.200.1"],
          "capabilities": ["Router"],
          "native_vlan": 200
        }
      ]
    }
  }
}
```

## How It Works

### Passive Discovery

VLAN Scout captures and analyzes:

- **DHCP Responses**: Extracts network configuration from DHCP offers/acks
- **Router Advertisements**: Discovers IPv6 prefixes and SLAAC configuration  
- **ARP Traffic**: Identifies active IPv4 hosts
- **NDP Traffic**: Discovers IPv6 neighbors and routers
- **LLDP Packets**: Discovers network devices, their capabilities, and management IPs
- **CDP Packets**: Discovers Cisco devices, platforms, and native VLAN information
- **General IP Traffic**: Maps additional active hosts

### Active Discovery

When enabled, the tool sends:

- **DHCP Discover**: Triggers DHCP responses revealing network config
- **DHCPv6 Solicit**: Discovers IPv6 network configuration
- **Router Solicitation**: Triggers Router Advertisements from routers

### Packet Processing

- Uses optimized `DecodingLayerParser` for high-performance packet analysis
- Pre-allocated layer structs minimize memory allocations
- Supports VLAN-tagged (802.1Q) traffic
- Filters multicast traffic for NDP and device discovery

### Device Discovery

VLAN Scout automatically discovers network infrastructure devices:

- **LLDP (IEEE 802.1AB)**: Standard protocol supported by most modern switches and routers
  - Device name, port identifiers, system description
  - Management IP addresses (IPv4/IPv6)
  - Device capabilities (Bridge, Router, WLAN-AP, etc.)
  
- **CDP (Cisco Discovery Protocol)**: Cisco proprietary protocol  
  - Device name, platform, software version
  - Port identifiers and native VLAN information
  - Management IP addresses and device capabilities

Both protocols operate at Layer 2 and work across VLAN boundaries, making them ideal for network topology discovery.

## Security Considerations

- **Root privileges required** for packet capture
- **Passive mode recommended** for production networks  
- **Active probing** may trigger security alerts
- **Network impact**: Active discovery generates additional traffic
