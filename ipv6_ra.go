package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// sendRouterSolicitation constructs and sends an ICMPv6 Router Solicitation packet
// on a specific VLAN. If vlanID is 0, the packet is sent untagged.
func sendRouterSolicitation(vlanID uint16) error {
	srcMac, err := net.ParseMAC(*macAddress)
	if err != nil {
		return fmt.Errorf("invalid source MAC address: %w", err)
	}

	linkLocalIP, err := macToLinkLocal(srcMac)
	if err != nil {
		return fmt.Errorf("failed to generate link-local IP: %w", err)
	}

	// The destination MAC for IPv6 multicast is derived from the destination IP address.
	// For ff02::2 (all-routers multicast), the MAC is 33:33:00:00:00:02.
	dstMac, _ := net.ParseMAC("33:33:00:00:00:02")

	// Ethernet Layer
	eth := &layers.Ethernet{
		SrcMAC: srcMac,
		DstMAC: dstMac,
	}

	// IPv6 Layer
	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255, // As per RFC 4861, section 4.1
		SrcIP:      linkLocalIP,
		DstIP:      net.ParseIP("ff02::2"), // All Routers Link-Local Multicast Address
		NextHeader: layers.IPProtocolICMPv6,
	}

	// ICMPv6 Layer
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0),
	}
	// The checksum is calculated with the IPv6 pseudo-header.
	if err := icmpv6.SetNetworkLayerForChecksum(ipv6); err != nil {
		return fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	// ICMPv6 Router Solicitation Layer with Source Link-Layer Address option
	rs := &layers.ICMPv6RouterSolicitation{}
	slla := layers.ICMPv6Option{
		Type: layers.ICMPv6OptSourceAddress,
		Data: []byte(srcMac),
	}
	rs.Options = append(rs.Options, slla)

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Construct the full packet with or without a VLAN tag.
	if vlanID > 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		dot1q := &layers.Dot1Q{
			VLANIdentifier: vlanID,
			Type:           layers.EthernetTypeIPv6,
		}
		err = gopacket.SerializeLayers(buf, opts, eth, dot1q, ipv6, icmpv6, rs)
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		err = gopacket.SerializeLayers(buf, opts, eth, ipv6, icmpv6, rs)
	}
	if err != nil {
		return fmt.Errorf("failed to serialize layers: %w", err)
	}

	// Send packet using a temporary pcap handle, consistent with dhcp.go
	handle, err := pcap.OpenLive(*iface, int32(65535), false, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("pcap.OpenLive failed: %w", err)
	}
	defer handle.Close()

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write packet data: %w", err)
	}

	//v("Sent IPv6 Router Solicitation on VLAN %d", vlanID)
	return nil
}
