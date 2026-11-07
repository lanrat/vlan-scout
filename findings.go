package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// Findings maps VLAN IDs to their corresponding network findings.
// VLAN 0 is the untagged network.
type Findings struct {
	mu    sync.Mutex
	own   map[string]struct{}
	Vlans map[uint16]*VlanFinding `json:"vlans"`
}

// DHCPResponse represents a DHCP response containing network configuration.
type DHCPResponse struct {
	IP      net.IPNet `json:"-"`       // IP address and subnet mask
	IPstr   string    `json:"ip"`      // String representation of IP for JSON
	Gateway net.IP    `json:"gateway"` // Default gateway IP
	Server  net.IP    `json:"server"`  // DHCP server IP
}

// IPv6SLAAC represents an IPv6 Router Advertisement response.
type IPv6SLAAC struct {
	IP      net.IPNet `json:"-"`       // IPv6 address and prefix
	IPstr   string    `json:"ip"`      // String representation of IP for JSON
	Gateway net.IP    `json:"gateway"` // IPv6 gateway IP
}

// DeviceInfo represents a discovered network device from LLDP or CDP.
type DeviceInfo struct {
	Name         string   `json:"name"`                  // Device name/ID
	Port         string   `json:"port"`                  // Port identifier
	Type         string   `json:"type"`                  // Discovery protocol (LLDP/CDP)
	Description  string   `json:"description"`           // System description
	MgmtIPs      []string `json:"mgmt_ips"`              // Management IP addresses
	Capabilities []string `json:"capabilities"`          // Device capabilities (Router, Bridge, etc.)
	NativeVLAN   uint16   `json:"native_vlan,omitempty"` // Native VLAN (CDP only)
}

type Hosts struct {
	IPv4      []string        `json:"ipv4"`
	IPv6      []string        `json:"ipv6"`
	HostsIPv4 map[string]bool `json:"-"` // Set of discovered IPv4 hosts
	HostsIPv6 map[string]bool `json:"-"` // Set of discovered IPv6 hosts

}

// VlanFinding contains all discovered information for a specific VLAN.
type VlanFinding struct {
	Vlan    uint16        `json:"-"`          // VLAN ID
	IPv4    *DHCPResponse `json:"ipv4_dhcp"`  // IPv4 DHCP configuration
	IPv6    *DHCPResponse `json:"ipv6_dhcp"`  // IPv6 DHCP configuration
	IPv6RA  *IPv6SLAAC    `json:"ipv6_slaac"` // IPv6 router advertisement
	Hosts   Hosts         `json:"hosts"`
	Devices []DeviceInfo  `json:"devices"` // Discovered network devices
}

// VlanList returns a sorted list of all VLAN IDs that have findings.
func (f *Findings) VlanList() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vlanIDs()
}

func (f *Findings) vlanIDs() []int {
	out := make([]int, 0, len(f.Vlans))
	for vlan := range f.Vlans {
		out = append(out, int(vlan))
	}
	sort.Ints(out)
	return out
}

// MarkOwnIP records an address that belongs to this scan. Host lists skip it,
// including addresses already recorded.
func (f *Findings) MarkOwnIP(ip net.IP) {
	if ip == nil || ip.IsUnspecified() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.own == nil {
		f.own = make(map[string]struct{})
	}
	s := ip.String()
	f.own[s] = struct{}{}
	for _, vf := range f.Vlans {
		delete(vf.Hosts.HostsIPv4, s)
		delete(vf.Hosts.HostsIPv6, s)
	}
}

func (f *Findings) isOwn(ip net.IP) bool {
	if ip == nil || f.own == nil {
		return false
	}
	_, ok := f.own[ip.String()]
	return ok
}

func vlanLabel(id uint16) string {
	if id == 0 {
		return "untagged"
	}
	return fmt.Sprintf("%d", id)
}

// StatusString returns a human-friendly string representation showing discovered VLANs.
// Uses detailed format for few VLANs, condensed summary for many VLANs.
func (f *Findings) StatusString() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statusString()
}

func (f *Findings) statusString() string {
	if len(f.Vlans) == 0 {
		return "Discovered VLANs: none"
	}

	// Use condensed format if there are many VLANs to avoid long status lines
	if len(f.Vlans) > 10 {
		return f.condensedStatusString()
	}

	// Detailed format for few VLANs
	out := "Discovered VLANs: "
	vlanParts := make([]string, 0, len(f.Vlans))

	for _, v := range f.vlanIDs() {
		vf := f.Vlans[uint16(v)]
		totalHosts := len(vf.Hosts.HostsIPv4) + len(vf.Hosts.HostsIPv6)
		totalDevices := len(vf.Devices)

		// Build service list
		services := make([]string, 0, 2)
		if vf.IPv4 != nil {
			services = append(services, "DHCP")
		}
		if vf.IPv6 != nil {
			services = append(services, "DHCP6")
		}
		if vf.IPv6RA != nil {
			services = append(services, "RA")
		}

		// Build VLAN description
		vlanDesc := vlanLabel(vf.Vlan) + "("
		if len(services) > 0 {
			vlanDesc += strings.Join(services, "+")
			if totalHosts > 0 {
				vlanDesc += fmt.Sprintf("+%dhosts", totalHosts)
			}
			if totalDevices > 0 {
				vlanDesc += fmt.Sprintf("+%ddevs", totalDevices)
			}
		} else if totalHosts > 0 || totalDevices > 0 {
			var parts []string
			if totalHosts > 0 {
				parts = append(parts, fmt.Sprintf("%dhosts", totalHosts))
			}
			if totalDevices > 0 {
				parts = append(parts, fmt.Sprintf("%ddevs", totalDevices))
			}
			vlanDesc += strings.Join(parts, "+")
		} else {
			vlanDesc += "detected"
		}
		vlanDesc += ")"

		vlanParts = append(vlanParts, vlanDesc)
	}

	return out + strings.Join(vlanParts, " ")
}

// condensedStatusString returns a summary format for many VLANs.
// Format: "Found 15 VLANs (8 with DHCP, 5 with IPv6, 120 total hosts, 25 devices)"
func (f *Findings) condensedStatusString() string {
	vlanCount := len(f.Vlans)
	dhcpCount := 0
	ipv6Count := 0
	totalHosts := 0
	totalDevices := 0

	for _, vf := range f.Vlans {
		if vf.IPv4 != nil {
			dhcpCount++
		}
		if vf.IPv6 != nil {
			ipv6Count++
		}
		if vf.IPv6RA != nil {
			ipv6Count++
		}
		totalHosts += len(vf.Hosts.HostsIPv4) + len(vf.Hosts.HostsIPv6)
		totalDevices += len(vf.Devices)
	}

	// Build summary parts
	parts := make([]string, 0, 4)
	if dhcpCount > 0 {
		parts = append(parts, fmt.Sprintf("%d with DHCP", dhcpCount))
	}
	if ipv6Count > 0 {
		parts = append(parts, fmt.Sprintf("%d with IPv6", ipv6Count))
	}
	if totalHosts > 0 {
		parts = append(parts, fmt.Sprintf("%d total hosts", totalHosts))
	}
	if totalDevices > 0 {
		parts = append(parts, fmt.Sprintf("%d devices", totalDevices))
	}

	result := fmt.Sprintf("Found %d VLANs", vlanCount)
	if len(parts) > 0 {
		result += " (" + strings.Join(parts, ", ") + ")"
	}

	return result
}

// String returns a detailed string representation of all findings.
func (f *Findings) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.Vlans) == 0 {
		return "No VLANs discovered."
	}

	out := "VLAN Discovery Results:\n\n"

	// Sort VLAN IDs for consistent output
	var vlanIDs []uint16
	for vlanID := range f.Vlans {
		vlanIDs = append(vlanIDs, vlanID)
	}
	sort.Slice(vlanIDs, func(i, j int) bool {
		return vlanIDs[i] < vlanIDs[j]
	})

	for i, vlanID := range vlanIDs {
		out += f.Vlans[vlanID].String()
		// Add blank line between VLANs except for the last one
		if i < len(vlanIDs)-1 {
			out += "\n"
		}
	}
	return out
}

// checkVlan ensures a VlanFinding entry exists for the given VLAN ID.
func (f *Findings) checkVlan(vlan uint16) {
	if _, ok := f.Vlans[vlan]; !ok {
		f.Vlans[vlan] = &VlanFinding{
			Vlan: vlan,
			Hosts: Hosts{
				HostsIPv4: make(map[string]bool),
				HostsIPv6: make(map[string]bool),
			},
		}
	}
}

// ToJson converts findings to JSON format, preparing host arrays for serialization.
func (f *Findings) ToJson() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.Vlans {
		v.Hosts.IPv4 = make([]string, 0, len(v.Hosts.HostsIPv4))
		for host := range v.Hosts.HostsIPv4 {
			v.Hosts.IPv4 = append(v.Hosts.IPv4, host)
		}
		sort.Strings(v.Hosts.IPv4)
		v.Hosts.IPv6 = make([]string, 0, len(v.Hosts.HostsIPv6))
		for host := range v.Hosts.HostsIPv6 {
			v.Hosts.IPv6 = append(v.Hosts.IPv6, host)
		}
		sort.Strings(v.Hosts.IPv6)

		if v.IPv4 != nil {
			v.IPv4.IPstr = v.IPv4.IP.String()
		}
		if v.IPv6 != nil {
			v.IPv6.IPstr = v.IPv6.IP.String()
		}
		if v.IPv6RA != nil {
			v.IPv6RA.IPstr = v.IPv6RA.IP.String()
		}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	check(err)
	return string(b)
}

// AddIPv4Host adds an IPv4 host to the specified VLAN's findings.
func (f *Findings) AddIPv4Host(vlan uint16, ip net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addIPv4Host(vlan, ip)
}

func (f *Findings) addIPv4Host(vlan uint16, ip net.IP) {
	if ip == nil || ip.IsUnspecified() || f.isOwn(ip) {
		return
	}
	f.checkVlan(vlan)
	f.Vlans[vlan].Hosts.HostsIPv4[ip.String()] = true
}

// AddIPv6Host adds an IPv6 host to the specified VLAN's findings.
func (f *Findings) AddIPv6Host(vlan uint16, ip net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addIPv6Host(vlan, ip)
}

func (f *Findings) addIPv6Host(vlan uint16, ip net.IP) {
	if ip == nil || ip.IsUnspecified() || f.isOwn(ip) {
		return
	}
	f.checkVlan(vlan)
	f.Vlans[vlan].Hosts.HostsIPv6[ip.String()] = true
}

// AddIPv4DHCP records a DHCP response for the specified VLAN.
func (f *Findings) AddIPv4DHCP(vlan uint16, ip net.IPNet, gateway net.IP, server net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkVlan(vlan)
	f.Vlans[vlan].IPv4 = &DHCPResponse{
		IP:      ip,
		Gateway: gateway,
		Server:  server,
	}
}

// AddIPv6DHCP records a DHCP response for the specified VLAN.
func (f *Findings) AddIPv6DHCP(vlan uint16, ip net.IPNet, gateway net.IP, server net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkVlan(vlan)
	f.Vlans[vlan].IPv6 = &DHCPResponse{
		IP:      ip,
		Gateway: gateway,
		Server:  server,
	}
}

// AddIPv6SLAAC records an IPv6 Router Advertisement for the specified VLAN.
func (f *Findings) AddIPv6SLAAC(vlan uint16, ip net.IPNet, gateway net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkVlan(vlan)
	f.Vlans[vlan].IPv6RA = &IPv6SLAAC{
		IP:      ip,
		Gateway: gateway,
	}
}

// AddLLDPDevice adds an LLDP-discovered device to the specified VLAN's findings.
func (f *Findings) AddLLDPDevice(vlan uint16, name, port, description string, mgmtIPs []net.IP, capabilities []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkVlan(vlan)

	// Convert IP addresses to strings
	mgmtIPStrings := make([]string, len(mgmtIPs))
	for i, ip := range mgmtIPs {
		mgmtIPStrings[i] = ip.String()
		// Also add to hosts
		if ip.To4() != nil {
			f.addIPv4Host(vlan, ip)
		} else {
			f.addIPv6Host(vlan, ip)
		}
	}

	device := DeviceInfo{
		Name:         name,
		Port:         port,
		Type:         "LLDP",
		Description:  description,
		MgmtIPs:      mgmtIPStrings,
		Capabilities: capabilities,
	}

	f.Vlans[vlan].Devices = append(f.Vlans[vlan].Devices, device)
}

// AddCDPDevice adds a CDP-discovered device to the specified VLAN's findings.
func (f *Findings) AddCDPDevice(vlan uint16, name, port, description string, mgmtIPs []net.IP, capabilities []string, nativeVLAN uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkVlan(vlan)

	// Convert IP addresses to strings
	mgmtIPStrings := make([]string, len(mgmtIPs))
	for i, ip := range mgmtIPs {
		mgmtIPStrings[i] = ip.String()
		// Also add to hosts
		if ip.To4() != nil {
			f.addIPv4Host(vlan, ip)
		} else {
			f.addIPv6Host(vlan, ip)
		}
	}

	device := DeviceInfo{
		Name:         name,
		Port:         port,
		Type:         "CDP",
		Description:  description,
		MgmtIPs:      mgmtIPStrings,
		Capabilities: capabilities,
		NativeVLAN:   nativeVLAN,
	}

	f.Vlans[vlan].Devices = append(f.Vlans[vlan].Devices, device)
}

// String returns a formatted string representation of the VLAN finding.
func (v *VlanFinding) String() string {
	title := fmt.Sprintf("VLAN %d", v.Vlan)
	if v.Vlan == 0 {
		title = "Untagged"
	}
	out := title + ":\n"

	var items []string

	// Add IPv4 DHCP info
	if v.IPv4 != nil {
		items = append(items, fmt.Sprintf("IPv4 DHCP: %s (GW: %s, Server: %s)",
			v.IPv4.IP.String(), v.IPv4.Gateway.String(), v.IPv4.Server.String()))
	}

	// Add IPv6 DHCP info
	if v.IPv6 != nil {
		items = append(items, fmt.Sprintf("IPv6 DHCP: %s (GW: %s, Server: %s)",
			v.IPv6.IP.String(), v.IPv6.Gateway.String(), v.IPv6.Server.String()))
	}

	// Add IPv6 SLAAC info
	if v.IPv6RA != nil {
		items = append(items, fmt.Sprintf("IPv6 SLAAC: %s (GW: %s)",
			v.IPv6RA.IP.String(), v.IPv6RA.Gateway.String()))
	}

	// Collect and sort IPv4 hosts
	var ipv4Hosts []string
	for host := range v.Hosts.HostsIPv4 {
		ipv4Hosts = append(ipv4Hosts, host)
	}
	if len(ipv4Hosts) > 0 {
		sort.Strings(ipv4Hosts)
		items = append(items, fmt.Sprintf("IPv4 Hosts: %s", strings.Join(ipv4Hosts, ", ")))
	}

	// Collect and sort IPv6 hosts
	var ipv6Hosts []string
	for host := range v.Hosts.HostsIPv6 {
		ipv6Hosts = append(ipv6Hosts, host)
	}
	if len(ipv6Hosts) > 0 {
		sort.Strings(ipv6Hosts)
		items = append(items, fmt.Sprintf("IPv6 Hosts: %s", strings.Join(ipv6Hosts, ", ")))
	}

	// Add discovered devices
	if len(v.Devices) > 0 {
		for _, device := range v.Devices {
			deviceDesc := fmt.Sprintf("%s Device: %s", device.Type, device.Name)
			if device.Port != "" {
				deviceDesc += fmt.Sprintf(" (Port: %s)", device.Port)
			}
			if len(device.Capabilities) > 0 {
				deviceDesc += fmt.Sprintf(" [%s]", strings.Join(device.Capabilities, ", "))
			}
			if len(device.MgmtIPs) > 0 {
				deviceDesc += fmt.Sprintf(" - IPs: %s", strings.Join(device.MgmtIPs, ", "))
			}
			items = append(items, deviceDesc)
		}
	}

	// Add items with proper tree formatting
	for i, item := range items {
		if i == len(items)-1 {
			out += "  └─ " + item + "\n"
		} else {
			out += "  ├─ " + item + "\n"
		}
	}

	return out
}

// String returns a formatted string representation of the DHCP response.
func (d *DHCPResponse) String() string {
	out := ""
	out += "  IP: " + d.IP.String() + "\n"
	out += "  Gateway: " + d.Gateway.String() + "\n"
	out += "  Server: " + d.Server.String() + "\n"
	return out
}

// String returns a formatted string representation of the IPv6 RA.
func (d *IPv6SLAAC) String() string {
	out := ""
	out += "  IP: " + d.IP.String() + "\n"
	out += "  Gateway: " + d.Gateway.String() + "\n"
	return out
}
