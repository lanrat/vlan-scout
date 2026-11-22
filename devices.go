package main

import (
	"encoding/json"
	"net"

	"github.com/google/gopacket/pcap"
)

// deviceList is the -list -json document.
type deviceList struct {
	Devices []listedDevice `json:"devices"`
}

// listedDevice is everything pcap and the operating system report for one
// interface.
type listedDevice struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	MAC         string          `json:"mac,omitempty"`
	Flags       deviceFlags     `json:"flags"`
	VLANCapable *bool           `json:"vlan_capable,omitempty"`
	Addresses   []listedAddress `json:"addresses"`
}

// deviceFlags is the libpcap interface flag word in fields.
type deviceFlags struct {
	Up         bool   `json:"up"`
	Running    bool   `json:"running"`
	Loopback   bool   `json:"loopback"`
	Wireless   bool   `json:"wireless"`
	Connection string `json:"connection"`
}

// listedAddress is one address bound to an interface.
type listedAddress struct {
	IP        string `json:"ip"`
	Netmask   string `json:"netmask,omitempty"`
	Prefix    int    `json:"prefix,omitempty"`
	Broadcast string `json:"broadcast,omitempty"`
	Peer      string `json:"peer,omitempty"`
}

// devicesToJSON renders the interfaces -list would print.
func devicesToJSON(devices []pcap.Interface, macs map[string]string) string {
	out := deviceList{Devices: make([]listedDevice, 0, len(devices))}
	for _, device := range devices {
		out.Devices = append(out.Devices, deviceRecord(device, macs[device.Name]))
	}
	b, err := json.MarshalIndent(out, "", "  ")
	check(err)
	return string(b)
}

func deviceRecord(device pcap.Interface, mac string) listedDevice {
	rec := listedDevice{
		Name:        device.Name,
		Description: device.Description,
		MAC:         mac,
		Flags:       deviceFlagRecord(device.Flags),
		Addresses:   make([]listedAddress, 0, len(device.Addresses)),
	}
	if capable, known := knownVLANCapable(device.Name); known {
		rec.VLANCapable = &capable
	}
	for _, addr := range device.Addresses {
		if len(addr.IP) == 0 {
			continue
		}
		rec.Addresses = append(rec.Addresses, addressRecord(addr))
	}
	return rec
}

func deviceFlagRecord(flags uint32) deviceFlags {
	return deviceFlags{
		Up:         flags&PCAP_IF_UP != 0,
		Running:    flags&PCAP_IF_RUNNING != 0,
		Loopback:   flags&PCAP_IF_LOOPBACK != 0,
		Wireless:   flags&PCAP_IF_WIRELESS != 0,
		Connection: connectionStatus(flags),
	}
}

func connectionStatus(flags uint32) string {
	switch flags & PCAP_IF_CONNECTION_STATUS {
	case PCAP_IF_CONNECTION_STATUS_CONNECTED:
		return "connected"
	case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
		return "disconnected"
	case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
		return "not_applicable"
	default:
		return "unknown"
	}
}

func addressRecord(addr pcap.InterfaceAddress) listedAddress {
	out := listedAddress{IP: addr.IP.String()}
	if len(addr.Netmask) > 0 {
		out.Netmask = net.IP(addr.Netmask).String()
		if ones, bits := addr.Netmask.Size(); bits > 0 {
			out.Prefix = ones
		}
	}
	if len(addr.Broadaddr) > 0 {
		out.Broadcast = addr.Broadaddr.String()
	}
	if len(addr.P2P) > 0 {
		out.Peer = addr.P2P.String()
	}
	return out
}
