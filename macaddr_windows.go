//go:build windows

package main

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// addPlatformMACs records hardware addresses under the Npcap device path and
// the friendly name. pcap lists Windows interfaces as \Device\NPF_{GUID},
// which is not the name net.Interfaces uses.
func addPlatformMACs(dst map[string]string) {
	flags := uint32(windows.GAA_FLAG_INCLUDE_ALL_INTERFACES)
	var size uint32 = 15000
	var buf []byte
	var addrs *windows.IpAdapterAddresses
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		addrs = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, addrs, &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return
		}
		addrs = nil
	}
	if addrs == nil {
		return
	}
	for a := addrs; a != nil; a = a.Next {
		n := int(a.PhysicalAddressLength)
		if n <= 0 || n > len(a.PhysicalAddress) {
			continue
		}
		mac := net.HardwareAddr(a.PhysicalAddress[:n]).String()
		guid := windows.BytePtrToString(a.AdapterName)
		keys := []string{
			windows.UTF16PtrToString(a.FriendlyName),
			windows.UTF16PtrToString(a.Description),
		}
		if guid != "" {
			keys = append(keys, guid, `\Device\NPF_`+guid)
		}
		for _, key := range keys {
			if key != "" {
				dst[key] = mac
			}
		}
	}
}
