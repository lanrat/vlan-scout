package main

import (
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// sendDHCPDiscover sends a DHCP sendDHCPDiscover packet on the specified VLAN to probe for DHCP servers.
func sendDHCPDiscover(vlanID uint16) error {
	options := make([]layers.DHCPOption, 0, 5)
	options = append(options, layers.DHCPOption{Type: layers.DHCPOptHostname, Data: []byte(*hostname)})
	clientMacAddr, err := net.ParseMAC(*macAddress)
	if err != nil {
		return err
	}
	err = sendPacket(clientMacAddr, layers.DHCPMsgTypeDiscover, options, vlanID)
	if err != nil {
		return err
	}
	return nil
}

// sendPacket creates and sends a DHCP packet with the specified parameters.
func sendPacket(madAddr net.HardwareAddr, msgType layers.DHCPMsgType, options []layers.DHCPOption, vlanID uint16) error {
	return sendMulticast(madAddr, newPacket(madAddr, msgType, options), vlanID)
}

// newPacket creates a DHCPv4 packet with the specified MAC address, message type, and options.
func newPacket(madAddr net.HardwareAddr, msgType layers.DHCPMsgType, options []layers.DHCPOption) *layers.DHCPv4 {
	packet := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: madAddr,
		Xid:          rand.Uint32(), // Transaction ID
	}

	packet.Options = append(packet.Options, layers.DHCPOption{
		Type:   layers.DHCPOptMessageType,
		Data:   []byte{byte(msgType)},
		Length: 1,
	})

	// append DHCP options
	for _, option := range options {
		packet.Options = append(packet.Options, layers.DHCPOption{
			Type:   option.Type,
			Data:   option.Data,
			Length: uint8(len(option.Data)),
		})
	}

	return &packet
}

// sendMulticast broadcasts a DHCP packet on the network interface, optionally with VLAN tagging.
// If vlanID is between 1-4094, the packet is sent with 802.1Q VLAN tagging.
func sendMulticast(madAddr net.HardwareAddr, dhcp *layers.DHCPv4, vlanID uint16) error {
	eth := layers.Ethernet{SrcMAC: madAddr, DstMAC: layers.EthernetBroadcast}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    []byte{0, 0, 0, 0},
		DstIP:    []byte{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
	}
	udp := layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err := udp.SetNetworkLayerForChecksum(&ip)
	if err != nil {
		return err
	}

	// A valid VLAN ID is between 1 and 4094.
	if vlanID > 0 && vlanID < 4095 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		dot1q := &layers.Dot1Q{
			VLANIdentifier: uint16(vlanID),
			Type:           layers.EthernetTypeIPv4,
		}
		err = gopacket.SerializeLayers(buf, opts, &eth, dot1q, &ip, &udp, dhcp)
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, dhcp)
	}
	if err != nil {
		return err
	}

	handle, err := pcap.OpenLive(
		*iface, // device
		int32(65535),
		false,
		100*time.Millisecond,
	)
	if err != nil {
		return err
	}
	defer handle.Close()

	//send
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
