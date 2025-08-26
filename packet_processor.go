package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketProcessor holds pre-allocated layers and parser for efficient packet processing
type PacketProcessor struct {
	parser        *gopacket.DecodingLayerParser
	vlans         map[uint16]bool
	decodedLayers []gopacket.LayerType
	eth           layers.Ethernet
	dot1q         layers.Dot1Q
	ipv4          layers.IPv4
	ipv6          layers.IPv6
	arp           layers.ARP
	udp           layers.UDP
	icmpv6        layers.ICMPv6
	icmpv6NA      layers.ICMPv6NeighborAdvertisement
	icmpv6NS      layers.ICMPv6NeighborSolicitation
	icmpv6RS      layers.ICMPv6RouterSolicitation
	icmpv6RA      layers.ICMPv6RouterAdvertisement
	dhcpv4        layers.DHCPv4
	dhcpv6        layers.DHCPv6
}

// NewPacketProcessor creates a new PacketProcessor with pre-allocated layers
func NewPacketProcessor() *PacketProcessor {
	pp := &PacketProcessor{
		decodedLayers: make([]gopacket.LayerType, 0, 10),
	}

	pp.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&pp.eth,
		&pp.dot1q,    // 802.1Q VLAN tag
		&pp.arp,      // ARP comes directly after Ethernet/VLAN
		&pp.ipv4,     // Network layer
		&pp.ipv6,     // Network layer
		&pp.udp,      // Transport layer
		&pp.icmpv6,   // Transport layer
		&pp.icmpv6NA, // ICMPv6 subtypes
		&pp.icmpv6NS,
		&pp.icmpv6RS,
		&pp.icmpv6RA,
		&pp.dhcpv4, // Application layer
		&pp.dhcpv6, // Application layer
	)

	if (*vlanList) != "" {
		pp.vlans = make(map[uint16]bool)
		for _, vlan := range vlansToScan {
			pp.vlans[vlan] = true
		}
	}

	return pp
}

// HandlePacket processes captured network packets using pre-allocated layers for better performance
func (pp *PacketProcessor) HandlePacket(data []byte) {
	// Create a gopacket.Packet object if needed for detailed analysis
	// This is more memory intensive but provides full packet access
	if *printPackets || *verbose {
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		log.Println(packet)
	}

	// Parse the packet data
	err := pp.parser.DecodeLayers(data, &pp.decodedLayers)
	if err != nil {
		v("Partial decoding error: %v", err)
		// Continue processing what was successfully decoded
	}

	// Check if we have VLAN tag
	hasVLAN := false
	var vlan uint16
	for _, layerType := range pp.decodedLayers {
		if layerType == layers.LayerTypeDot1Q {
			hasVLAN = true
			vlan = pp.dot1q.VLANIdentifier
			break
		}
	}

	// Handle LLDP and CDP packets separately as they need full packet parsing
	pp.handleLLDPCDP(data, vlan)

	if !hasVLAN {
		return
	}

	if pp.vlans != nil {
		if !pp.vlans[vlan] {
			return
		}
	}

	// Skip packets from our own MAC address
	if pp.eth.SrcMAC.String() == *macAddress {
		return
	}

	// Process each decoded layer
	for _, layerType := range pp.decodedLayers {
		switch layerType {
		case layers.LayerTypeARP:
			arpSrcIP := net.IP(pp.arp.SourceProtAddress)
			v("vlan %d ARP Reply for: %s", vlan, arpSrcIP)
			findings.AddIPv4Host(vlan, arpSrcIP)

		case layers.LayerTypeICMPv6NeighborAdvertisement:
			v("vlan %d NDP Neighbor Advertisement - Target IP: %s", vlan, pp.icmpv6NA.TargetAddress)
			findings.AddIPv6Host(vlan, pp.icmpv6NA.TargetAddress)

		case layers.LayerTypeICMPv6NeighborSolicitation:
			v("vlan %d NDP Neighbor Solicitation - Target IP: %s", vlan, pp.icmpv6NS.TargetAddress)
			findings.AddIPv6Host(vlan, pp.icmpv6NS.TargetAddress)

		case layers.LayerTypeICMPv6RouterSolicitation:
			v("vlan %d Received ICMPv6 Router Solicitation from: %s", vlan, pp.ipv6.SrcIP)
			findings.AddIPv6Host(vlan, pp.ipv6.SrcIP)

		case layers.LayerTypeICMPv6RouterAdvertisement:
			v("vlan %d Received ICMPv6 Router Advertisement", vlan)
			gateway := pp.ipv6.SrcIP
			findings.AddIPv6Host(vlan, gateway)

			var slaacIP net.IPNet

			for _, option := range pp.icmpv6RA.Options {
				switch option.Type {
				case layers.ICMPv6OptPrefixInfo:
					// Prefix Information option (RFC 4861, Section 4.6.2)
					// Data length must be 30 bytes. We only take the first prefix found.
					if len(option.Data) == 30 && slaacIP.IP == nil {
						prefixLen := int(option.Data[0])
						prefix := net.IP(option.Data[14:])
						slaacIP = IP2IPNet(prefix, net.CIDRMask(prefixLen, 128))
						v("vlan %d RA: Found Prefix %s", vlan, slaacIP.String())
					}
				}
			}

			// If we found a prefix, we can record the finding. The gateway is always present.
			if slaacIP.IP != nil {
				findings.AddIPv6SLAAC(vlan, slaacIP, gateway)
			}

		case layers.LayerTypeIPv4:
			v("vlan %d IPv4 Packet - Src: %s Dst: %s", vlan, pp.ipv4.SrcIP, pp.ipv4.DstIP)
			findings.AddIPv4Host(vlan, pp.ipv4.SrcIP)

		case layers.LayerTypeIPv6:
			v("vlan %d IPv6 Packet - Src: %s Dst: %s", vlan, pp.ipv6.SrcIP, pp.ipv6.DstIP)
			findings.AddIPv6Host(vlan, pp.ipv6.SrcIP)

		case layers.LayerTypeDHCPv4:
			if pp.dhcpv4.Operation == layers.DHCPOpReply {
				v("DHCP Reply - your client ip: %s", pp.dhcpv4.YourClientIP.String())

				var netmask net.IPMask
				var gateway net.IP
				var server net.IP

				for _, opt := range pp.dhcpv4.Options {
					v("option: %v", opt)
					switch opt.Type {
					case layers.DHCPOptSubnetMask:
						netmask = net.IPMask(opt.Data)
					case layers.DHCPOptRouter:
						gateway = net.IP(opt.Data)
						findings.AddIPv4Host(vlan, net.IP(opt.Data))
					case layers.DHCPOptServerID:
						server = net.IP(opt.Data)
						findings.AddIPv4Host(vlan, net.IP(opt.Data))
					}
				}

				ip := IP2IPNet(pp.dhcpv4.YourClientIP, netmask)
				findings.AddIPv4DHCP(vlan, ip, gateway, server)
			}

		case layers.LayerTypeDHCPv6:
			v("DHCPv6 packet received - MsgType: %d, VLAN: %d", pp.dhcpv6.MsgType, vlan)
			// Handle DHCPv6 Advertise (2) and Reply (7) messages
			if pp.dhcpv6.MsgType == 2 || pp.dhcpv6.MsgType == 7 {
				v("DHCPv6 %s - Transaction ID: %x",
					func() string {
						if pp.dhcpv6.MsgType == 2 {
							return "Advertise"
						}
						return "Reply"
					}(),
					pp.dhcpv6.TransactionID)
				var serverIP net.IP
				var assignedPrefix net.IPNet

				serverIP = pp.ipv6.SrcIP
				findings.AddIPv6Host(vlan, serverIP)

				var gatewayIP net.IP

				for _, opt := range pp.dhcpv6.Options {
					v("DHCPv6 option: %d, len: %d", opt.Code, opt.Length)
					switch opt.Code {
					case layers.DHCPv6OptServerID:
						v("DHCPv6 Server ID found")
					case 3: // IA_NA (Identity Association for Non-temporary Addresses)
						if len(opt.Data) >= 12 { // Minimum IA_NA size (IAID + T1 + T2)
							v("DHCPv6 IA_NA found")
							// Parse IA_NA sub-options to find IAADDR options
							// IA_NA format: IAID(4) + T1(4) + T2(4) + sub-options
							subOptData := opt.Data[12:] // Skip IAID, T1, T2

							// Parse sub-options within IA_NA
							for len(subOptData) >= 4 {
								subOptCode := uint16(subOptData[0])<<8 | uint16(subOptData[1])
								subOptLen := uint16(subOptData[2])<<8 | uint16(subOptData[3])

								if len(subOptData) < int(4+subOptLen) {
									break // Not enough data
								}

								subOptPayload := subOptData[4 : 4+subOptLen]

								if subOptCode == 5 && len(subOptPayload) >= 24 { // IAADDR option
									// IAADDR format: IPv6 address(16) + preferred-lifetime(4) + valid-lifetime(4) + sub-options
									addr := net.IP(subOptPayload[:16])
									v("DHCPv6 assigned address: %s", addr.String())

									// For DHCPv6, individual addresses are typically /128 unless part of a larger prefix
									// Most DHCPv6 deployments use /64 prefixes for the link
									prefixLen := 64 // Common DHCPv6 prefix length

									assignedPrefix := net.IPNet{
										IP:   addr,
										Mask: net.CIDRMask(prefixLen, 128),
									}
									findings.AddIPv6Host(vlan, addr)

									// For DHCPv6, the gateway is typically the server's link-local address
									// We'll use the server IP as the gateway since DHCPv6 doesn't provide explicit gateway info
									currentGateway := gatewayIP
									if currentGateway == nil {
										currentGateway = serverIP
									}
									findings.AddIPv6DHCP(vlan, assignedPrefix, currentGateway, serverIP)
								}

								// Move to next sub-option
								subOptData = subOptData[4+subOptLen:]
							}
						}
					case 25: // IA_PD (Identity Association for Prefix Delegation)
						if len(opt.Data) >= 12 { // Minimum IA_PD size
							v("DHCPv6 IA_PD (Prefix Delegation) found")
							// IA_PD contains IAPREFIX options with delegated prefixes
							// This would contain the actual subnet mask information
						}
					case 26: // IAPREFIX (IA Prefix)
						if len(opt.Data) >= 25 { // 4 + 4 + 1 + 16 bytes minimum
							// Parse delegated prefix: preferred-lifetime + valid-lifetime + prefix-length + prefix
							prefixLength := int(opt.Data[8]) // Prefix length at offset 8
							prefix := net.IP(opt.Data[9:25]) // IPv6 prefix at offset 9
							v("DHCPv6 delegated prefix: %s/%d", prefix.String(), prefixLength)

							// Use delegated prefix information
							assignedPrefix = net.IPNet{
								IP:   prefix,
								Mask: net.CIDRMask(prefixLength, 128),
							}
							findings.AddIPv6Host(vlan, prefix)
						}
					case 5: // IAADDR (IA Address)
						if len(opt.Data) >= 24 { // IAADDR requires 24 bytes minimum (16 addr + 4 preferred + 4 valid)
							// Extract IPv6 address (first 16 bytes)
							addr := net.IP(opt.Data[:16])
							v("DHCPv6 assigned address: %s", addr.String())
							// For DHCPv6, individual addresses are typically /128 unless part of a delegated prefix
							// Check if this is part of a larger prefix by looking at network context
							prefixLen := 128 // Default to individual address

							// If the address appears to be part of a common subnet, adjust prefix
							// This is heuristic - proper prefix delegation would use IA_PD option
							if addr.IsGlobalUnicast() {
								// Most DHCPv6 deployments use /64 prefixes for link-local subnets
								prefixLen = 64
							}

							assignedPrefix = net.IPNet{
								IP:   addr,
								Mask: net.CIDRMask(prefixLen, 128),
							}
							findings.AddIPv6Host(vlan, addr)
						}
					case 23: // DNS recursive name server
						if len(opt.Data) >= 16 && len(opt.Data)%16 == 0 {
							// Each DNS server is 16 bytes (IPv6 address)
							for i := 0; i < len(opt.Data); i += 16 {
								dnsIP := net.IP(opt.Data[i : i+16])
								v("DHCPv6 DNS server: %s", dnsIP.String())
								// Do not save DNS server IPs as they may not be on the local network
							}
						}
					case 24: // Option 24: Route Information (RFC 4191)
						if len(opt.Data) >= 16 {
							v("DHCPv6 Route Information found")
							// Parse route information - this is complex and vendor-specific
							// For now, just log that we found it
						}
					case 39: // FQDN option
						if len(opt.Data) > 1 {
							hostname := string(opt.Data[1 : len(opt.Data)-1]) // Skip flags and null terminator
							v("DHCPv6 FQDN: %s", hostname)
						}
					case 242: // Option 242: Default Router (vendor-specific, some implementations)
						if len(opt.Data) >= 16 {
							gatewayIP = net.IP(opt.Data[:16])
							v("DHCPv6 Default Router: %s", gatewayIP.String())
							findings.AddIPv6Host(vlan, gatewayIP)
						}
					}
				}

				if gatewayIP == nil {
					gatewayIP = serverIP
				}

				if assignedPrefix.IP != nil {
					findings.AddIPv6DHCP(vlan, assignedPrefix, gatewayIP, serverIP)
				}
			}
		}
	}
}

// handleLLDPCDP processes LLDP and CDP packets using full packet parsing
func (pp *PacketProcessor) handleLLDPCDP(data []byte, vlan uint16) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Handle LLDP packets
	if lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldpLayer != nil {
		lldp := lldpLayer.(*layers.LinkLayerDiscovery)
		pp.processLLDPPacket(lldp, vlan)
	}

	// Handle CDP packets
	if cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscovery); cdpLayer != nil {
		cdp := cdpLayer.(*layers.CiscoDiscovery)
		pp.processCDPPacket(cdp, vlan)
	}
}

// processLLDPPacket extracts device information from LLDP packets
func (pp *PacketProcessor) processLLDPPacket(lldp *layers.LinkLayerDiscovery, vlan uint16) {
	var deviceName, portID, systemDesc string
	var mgmtIPs []net.IP
	var capabilities []string

	v("vlan %d LLDP packet from Chassis ID: %s", vlan, string(lldp.ChassisID.ID))

	// Extract basic mandatory fields
	deviceName = string(lldp.ChassisID.ID)
	portID = string(lldp.PortID.ID)

	// Process optional TLV values
	for _, tlv := range lldp.Values {
		switch tlv.Type {
		case 5: // System Name TLV
			if len(tlv.Value) > 0 {
				deviceName = string(tlv.Value)
			}
		case 6: // System Description TLV
			systemDesc = string(tlv.Value)
		case 7: // System Capabilities TLV
			if len(tlv.Value) >= 4 {
				enabled := uint16(tlv.Value[2])<<8 | uint16(tlv.Value[3])
				if enabled&0x0004 != 0 { // Bridge capability
					capabilities = append(capabilities, "Bridge")
				}
				if enabled&0x0010 != 0 { // Router capability
					capabilities = append(capabilities, "Router")
				}
				if enabled&0x0020 != 0 { // WLAN AP capability
					capabilities = append(capabilities, "WLAN-AP")
				}
				if enabled&0x0040 != 0 { // Station capability
					capabilities = append(capabilities, "Station")
				}
			}
		case 8: // Management Address TLV
			if len(tlv.Value) >= 9 {
				addrLen := int(tlv.Value[0])
				if addrLen >= 5 && len(tlv.Value) >= addrLen+1 {
					addrType := tlv.Value[1]
					if addrType == 1 && addrLen == 5 { // IPv4
						ip := net.IP(tlv.Value[2:6])
						mgmtIPs = append(mgmtIPs, ip)
					} else if addrType == 2 && addrLen == 17 { // IPv6
						ip := net.IP(tlv.Value[2:18])
						mgmtIPs = append(mgmtIPs, ip)
					}
				}
			}
		}
	}

	v("vlan %d LLDP Device: %s, Port: %s, Desc: %s, Caps: %v", vlan, deviceName, portID, systemDesc, capabilities)

	// Add device to findings
	findings.AddLLDPDevice(vlan, deviceName, portID, systemDesc, mgmtIPs, capabilities)
}

// processCDPPacket extracts device information from CDP packets
func (pp *PacketProcessor) processCDPPacket(cdp *layers.CiscoDiscovery, vlan uint16) {
	var deviceName, portID, platform, version string
	var mgmtIPs []net.IP
	var nativeVLAN uint16
	var capabilities []string

	v("vlan %d CDP packet", vlan)

	// Process CDP TLV values
	for _, tlv := range cdp.Values {
		switch tlv.Type {
		case layers.CDPTLVDevID:
			deviceName = string(tlv.Value)
		case layers.CDPTLVPortID:
			portID = string(tlv.Value)
		case layers.CDPTLVPlatform:
			platform = string(tlv.Value)
		case layers.CDPTLVVersion:
			version = string(tlv.Value)
		case layers.CDPTLVAddress:
			// CDP addresses are complex TLV structures
			if len(tlv.Value) >= 8 {
				numAddrs := uint32(tlv.Value[0])<<24 | uint32(tlv.Value[1])<<16 | uint32(tlv.Value[2])<<8 | uint32(tlv.Value[3])
				offset := 4
				for i := uint32(0); i < numAddrs && offset < len(tlv.Value); i++ {
					if offset+8 <= len(tlv.Value) {
						// Skip protocol type and length fields
						addrLen := int(tlv.Value[offset+7])
						offset += 8
						if offset+addrLen <= len(tlv.Value) && addrLen == 4 {
							// IPv4 address
							ip := net.IP(tlv.Value[offset : offset+4])
							mgmtIPs = append(mgmtIPs, ip)
						}
						offset += addrLen
					} else {
						break
					}
				}
			}
		case layers.CDPTLVCapabilities:
			if len(tlv.Value) >= 4 {
				caps := uint32(tlv.Value[0])<<24 | uint32(tlv.Value[1])<<16 | uint32(tlv.Value[2])<<8 | uint32(tlv.Value[3])
				if caps&0x01 != 0 {
					capabilities = append(capabilities, "Router")
				}
				if caps&0x02 != 0 {
					capabilities = append(capabilities, "Bridge")
				}
				if caps&0x04 != 0 {
					capabilities = append(capabilities, "Source-Route-Bridge")
				}
				if caps&0x08 != 0 {
					capabilities = append(capabilities, "Switch")
				}
				if caps&0x10 != 0 {
					capabilities = append(capabilities, "Host")
				}
				if caps&0x20 != 0 {
					capabilities = append(capabilities, "IGMP")
				}
				if caps&0x40 != 0 {
					capabilities = append(capabilities, "Repeater")
				}
			}
		case layers.CDPTLVNativeVLAN:
			if len(tlv.Value) >= 2 {
				nativeVLAN = uint16(tlv.Value[0])<<8 | uint16(tlv.Value[1])
			}
		}
	}

	systemDesc := platform
	if version != "" {
		systemDesc += " running " + version
	}

	v("vlan %d CDP Device: %s, Port: %s, Platform: %s, Native VLAN: %d, Caps: %v", vlan, deviceName, portID, platform, nativeVLAN, capabilities)

	// Add device to findings
	findings.AddCDPDevice(vlan, deviceName, portID, systemDesc, mgmtIPs, capabilities, nativeVLAN)
}
