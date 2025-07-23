package main

// PCap interface flags constants matching libpcap interface flags.
// These flags indicate the status and capabilities of network interfaces.
const (
	PCAP_IF_LOOPBACK                         = 0x00000001 // interface is loopback
	PCAP_IF_UP                               = 0x00000002 // interface is up
	PCAP_IF_RUNNING                          = 0x00000004 // interface is running
	PCAP_IF_WIRELESS                         = 0x00000008 // interface is wireless (*NOT* necessarily Wi-Fi!)
	PCAP_IF_CONNECTION_STATUS                = 0x00000030 // connection status mask
	PCAP_IF_CONNECTION_STATUS_UNKNOWN        = 0x00000000 // unknown connection status
	PCAP_IF_CONNECTION_STATUS_CONNECTED      = 0x00000010 // connected
	PCAP_IF_CONNECTION_STATUS_DISCONNECTED   = 0x00000020 // disconnected
	PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030 // not applicable
)

// GetFlags converts PCap interface flags to a human-readable string representation.
// Returns a formatted string like "[UP,RUNNING]" or "NONE" if no flags are set.
func GetFlags(flags uint32) string {
	var result []string

	if flags&PCAP_IF_LOOPBACK != 0 {
		result = append(result, "LOOPBACK")
	}
	if flags&PCAP_IF_UP != 0 {
		result = append(result, "UP")
	}
	if flags&PCAP_IF_RUNNING != 0 {
		result = append(result, "RUNNING")
	}
	if flags&PCAP_IF_WIRELESS != 0 {
		result = append(result, "WIRELESS")
	}

	// Connection status is a mask, so check it specifically
	switch flags & PCAP_IF_CONNECTION_STATUS {
	case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
		result = append(result, "CONNECTION_STATUS_UNKNOWN")
	case PCAP_IF_CONNECTION_STATUS_CONNECTED:
		result = append(result, "CONNECTION_STATUS_CONNECTED")
	case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
		result = append(result, "CONNECTION_STATUS_DISCONNECTED")
	case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
		result = append(result, "CONNECTION_STATUS_NOT_APPLICABLE")
	}

	if len(result) == 0 {
		return "NONE"
	}
	return "[" + joinStrings(result, ",") + "]"
}

// joinStrings joins a slice of strings with the specified separator.
// This helper avoids importing the "strings" package.
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	out := strs[0]
	for i := 1; i < len(strs); i++ {
		out += sep + strs[i]
	}
	return out
}
