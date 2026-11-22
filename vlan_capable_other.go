//go:build !darwin

package main

// knownVLANCapable has no driver check on this platform.
func knownVLANCapable(string) (bool, bool) {
	return false, false
}
