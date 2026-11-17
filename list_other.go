//go:build !darwin

package main

// interfaceCanVLAN reports whether name can carry an 802.1Q tag. The macOS
// driver check does not apply here, so link-status filtering stands alone.
func interfaceCanVLAN(string) bool { return true }
