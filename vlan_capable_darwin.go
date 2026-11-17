//go:build darwin

package main

// knownVLANCapable reports whether name's driver advertises 802.1Q support.
func knownVLANCapable(name string) (bool, bool) {
	return interfaceCanVLAN(name), true
}
