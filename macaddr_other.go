//go:build !windows

package main

// addPlatformMACs adds operating-system names that differ from net.Interfaces.
// Linux and macOS already use the same names as pcap.
func addPlatformMACs(map[string]string) {}
