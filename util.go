package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// v prints verbose output when the verbose flag is enabled.
// It automatically adds a newline if the format string doesn't end with one.
func v(format string, args ...interface{}) {
	if *verbose {
		if format[len(format)-1] != '\n' {
			format += "\n"
		}
		// Clear the status line before printing verbose output
		fmt.Printf("\r" + strings.Repeat(" ", 80) + "\r")
		log.Printf(format, args...)
	}
}

// check is a helper function that exits the program if an error is not nil.
func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// GenerateRandomMAC returns a random unicast, locally administered MAC address.
// The I/G bit (least significant bit of the first octet) must be clear.
// A multicast source address is not a valid station address; switches and
// macOS drop those frames, so probes sent with one get no replies.
func GenerateRandomMAC() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("generate random MAC: %v", err)
	}

	// U/L (0x02) = locally administered. I/G (0x01) = multicast; force it off.
	buf[0] = (buf[0] | 0x02) &^ 0x01

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

// validateSourceMAC reports an error when mac cannot be used as an Ethernet
// source address for probes.
func validateSourceMAC(mac string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}
	if len(hw) != 6 {
		return fmt.Errorf("MAC address %s must be a 6-byte Ethernet address", mac)
	}
	if hw[0]&0x01 != 0 {
		return fmt.Errorf("MAC address %s is multicast; probes need a unicast source address", mac)
	}
	return nil
}

// captureFilter selects VLAN traffic, probes sent from mac, and the
// discovery multicasts. ifaceName's hardware address is included so a
// reply still matches if the OS substitutes that address for mac.
func captureFilter(mac, ifaceName string) string {
	hosts := "ether host " + mac
	if ifi, err := net.InterfaceByName(ifaceName); err == nil && len(ifi.HardwareAddr) == 6 {
		hw := ifi.HardwareAddr.String()
		if hw != mac {
			hosts += " or ether host " + hw
		}
	}
	return "vlan or " + hosts + " or ether multicast or ether dst 01:80:c2:00:00:0e or ether dst 01:00:0c:cc:cc:cc"
}

// macToLinkLocal generates an IPv6 link-local address from a MAC address
// using the EUI-64 format.
func macToLinkLocal(mac net.HardwareAddr) (net.IP, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("MAC address must be 6 bytes long for EUI-64 conversion")
	}

	// EUI-64 conversion from 48-bit MAC:
	// 1. Split MAC into two 3-byte parts.
	// 2. Insert 0xFFFE between them to form a 64-bit interface identifier.
	// 3. Invert the 7th bit (the "Universal/Local" bit) of the first byte.
	// 4. Prepend the link-local prefix fe80::/64.

	eui64 := make([]byte, 8)
	copy(eui64[0:3], mac[0:3])
	eui64[3] = 0xff
	eui64[4] = 0xfe
	copy(eui64[5:8], mac[3:6])

	// Invert the U/L bit (the 7th bit of the first byte, which is bit 1 of the byte)
	eui64[0] ^= 0x02

	// Create the link-local IP address: fe80::/64 + EUI-64
	ip := make(net.IP, net.IPv6len)
	ip[0] = 0xfe
	ip[1] = 0x80
	// The next 6 bytes are zero for a link-local address.
	copy(ip[8:], eui64)

	return ip, nil
}

// IP2IPNet creates a net.IPNet from an IP address and subnet mask.
func IP2IPNet(ip net.IP, mask net.IPMask) net.IPNet {
	return net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

// parseVlanList parses a comma-separated list of VLANs and ranges.
// Supports individual VLANs (e.g., "1,2,4") and ranges (e.g., "60-70").
// Returns a slice of VLAN IDs to scan.
func parseVlanList(vlanStr string) ([]uint16, error) {
	if vlanStr == "" {
		// 0 is the untagged network. Tagged IDs run through 4094.
		vlans := make([]uint16, 0, VLAN_MAX-VLAN_MIN+2)
		vlans = append(vlans, 0)
		for i := VLAN_MIN; i <= VLAN_MAX; i++ {
			vlans = append(vlans, uint16(i))
		}
		return vlans, nil
	}

	var vlans []uint16
	parts := strings.Split(vlanStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if this is a range (contains "-")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start of range: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end of range: %s", rangeParts[1])
			}

			// Validate range
			if err := validateVLAN(start); err != nil {
				return nil, fmt.Errorf("start VLAN %d out of valid range (0-%d)", start, VLAN_MAX)
			}
			if err := validateVLAN(end); err != nil {
				return nil, fmt.Errorf("end VLAN %d out of valid range (0-%d)", end, VLAN_MAX)
			}
			if start > end {
				return nil, fmt.Errorf("invalid range: start %d > end %d", start, end)
			}

			// Add all VLANs in range
			for i := start; i <= end; i++ {
				vlans = append(vlans, uint16(i))
			}
		} else {
			// Single VLAN ID
			vlan, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid VLAN ID: %s", part)
			}

			if err := validateVLAN(vlan); err != nil {
				return nil, err
			}

			vlans = append(vlans, uint16(vlan))
		}
	}

	return vlans, nil
}

// validateVLAN accepts 0 for the untagged network and 1-4094 for tagged VLANs.
func validateVLAN(id int) error {
	if id == 0 || (id >= VLAN_MIN && id <= VLAN_MAX) {
		return nil
	}
	return fmt.Errorf("VLAN %d out of valid range (0-%d); 0 is the untagged network", id, VLAN_MAX)
}

// rememberProbeAddresses keeps the probe's own IPv6 link-local address out of host lists.
func rememberProbeAddresses(mac string) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return
	}
	ip, err := macToLinkLocal(hw)
	if err != nil {
		return
	}
	findings.MarkOwnIP(ip)
}
