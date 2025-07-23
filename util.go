package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
)

// v prints verbose output when the verbose flag is enabled.
// It automatically adds a newline if the format string doesn't end with one.
func v(fmt string, args ...interface{}) {
	if *verbose {
		if fmt[len(fmt)-1] != '\n' {
			fmt += " \n"
		}
		log.Printf("\r"+fmt, args...)
	}
}

// check is a helper function that exits the program if an error is not nil.
func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// GenerateRandomMAC generates a random MAC address.
// A MAC address is a 6-byte identifier. This function creates a byte slice of
// length 6 and fills it with random values using the crypto/rand package,
// which is suitable for cryptographic operations.
// It then formats the byte slice into the standard MAC address format
// (e.g., 00:1B:44:11:3A:B7).
func GenerateRandomMAC() string {
	// Create a 6-byte slice to hold the MAC address.
	buf := make([]byte, 6)

	// Read random bytes into the buffer.
	// rand.Read is a cryptographically secure random number generator.
	_, _ = rand.Read(buf)

	// To ensure it's a locally administered, unicast address,
	// set the second-least-significant bit of the first byte.
	// This prevents conflicts with universally administered addresses.
	buf[0] |= 2

	// Format the byte slice into a MAC address string.
	// The format is XX:XX:XX:XX:XX:XX.
	macAddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])

	return macAddress
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
