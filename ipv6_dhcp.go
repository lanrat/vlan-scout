package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// sendDHCPv6Solicit constructs and sends a DHCPv6 Solicit packet with hostname
// to request IPv6 configuration from DHCPv6 servers on a specific VLAN.
func sendDHCPv6Solicit(vlanID uint16) error {
	srcMac, err := net.ParseMAC(*macAddress)
	if err != nil {
		return fmt.Errorf("invalid source MAC address: %w", err)
	}

	linkLocalIP, err := macToLinkLocal(srcMac)
	if err != nil {
		return fmt.Errorf("failed to generate link-local IP: %w", err)
	}

	// DHCPv6 multicast destination: ff02::1:2 (All_DHCP_Relay_Agents_and_Servers)
	dstIP := net.ParseIP("ff02::1:2")
	// Corresponding multicast MAC: 33:33:00:01:00:02
	dstMac, _ := net.ParseMAC("33:33:00:01:00:02")

	// Ethernet Layer
	eth := &layers.Ethernet{
		SrcMAC: srcMac,
		DstMAC: dstMac,
	}

	// IPv6 Layer
	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		SrcIP:      linkLocalIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolUDP,
	}

	// UDP Layer (DHCPv6 uses UDP port 546 client, 547 server)
	udp := &layers.UDP{
		SrcPort: 546,
		DstPort: 547,
	}
	if err := udp.SetNetworkLayerForChecksum(ipv6); err != nil {
		return fmt.Errorf("failed to set network layer for DHCPv6 checksum: %w", err)
	}

	// Generate random transaction ID (3 bytes)
	transactionID := make([]byte, 3)
	_, err = rand.Read(transactionID)
	if err != nil {
		return fmt.Errorf("failed to generate transaction ID: %w", err)
	}

	// Create DHCPv6 Solicit packet
	dhcpv6 := &layers.DHCPv6{
		MsgType:       1, // DHCPv6 Solicit = 1
		TransactionID: transactionID,
		Options:       make(layers.DHCPv6Options, 0),
	}

	// Add Client ID option (required for DHCPv6)
	// DUID-LL (DUID based on Link-Layer address) = Type 3
	clientDUID := make([]byte, 10)
	clientDUID[0] = 0x00         // DUID Type high byte
	clientDUID[1] = 0x03         // DUID Type low byte (DUID-LL)
	clientDUID[2] = 0x00         // Hardware Type high byte
	clientDUID[3] = 0x01         // Hardware Type low byte (Ethernet)
	copy(clientDUID[4:], srcMac) // MAC address

	clientIDOption := layers.NewDHCPv6Option(layers.DHCPv6OptClientID, clientDUID)
	dhcpv6.Options = append(dhcpv6.Options, clientIDOption)

	// Add FQDN option (option 39) with hostname
	if hostname != nil && *hostname != "" {
		// FQDN option format: flags(1) + encoded domain name
		fqdnData := make([]byte, 1+len(*hostname)+1)
		fqdnData[0] = 0x00 // Flags: S=0, O=0, N=0 (server should update DNS)
		copy(fqdnData[1:], []byte(*hostname))
		// Add null terminator for the domain name
		fqdnData[len(fqdnData)-1] = 0x00

		fqdnOption := layers.NewDHCPv6Option(39, fqdnData) // Option 39 = FQDN
		dhcpv6.Options = append(dhcpv6.Options, fqdnOption)
	}

	// Add Option Request Option (ORO) to request common options
	// Request: DNS servers (23), domain search list (24), FQDN (39)
	oroData := []byte{
		0x00, 0x17, // Option 23: DNS recursive name server
		0x00, 0x18, // Option 24: Domain search list
		0x00, 0x27, // Option 39: FQDN option
	}
	oroOption := layers.NewDHCPv6Option(6, oroData) // Option 6 = ORO
	dhcpv6.Options = append(dhcpv6.Options, oroOption)

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Construct the full packet with or without a VLAN tag
	if vlanID > 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		dot1q := &layers.Dot1Q{
			VLANIdentifier: vlanID,
			Type:           layers.EthernetTypeIPv6,
		}
		err = gopacket.SerializeLayers(buf, opts, eth, dot1q, ipv6, udp, dhcpv6)
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		err = gopacket.SerializeLayers(buf, opts, eth, ipv6, udp, dhcpv6)
	}
	if err != nil {
		return fmt.Errorf("failed to serialize DHCPv6 layers: %w", err)
	}

	// Send packet
	handle, err := pcap.OpenLive(*iface, int32(65535), false, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("pcap.OpenLive failed: %w", err)
	}
	defer handle.Close()

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write DHCPv6 packet data: %w", err)
	}

	//v("Sent DHCPv6 Solicit on VLAN %d", vlanID)
	return nil
}
