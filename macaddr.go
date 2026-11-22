package main

import "net"

// interfaceMACs maps an interface name to its hardware address. Names match
// what pcap reports on Linux and macOS. Windows aliases are added separately.
func interfaceMACs() map[string]string {
	out := make(map[string]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		if len(ifi.HardwareAddr) == 0 {
			continue
		}
		out[ifi.Name] = ifi.HardwareAddr.String()
	}
	addPlatformMACs(out)
	return out
}
