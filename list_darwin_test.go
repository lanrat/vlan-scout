//go:build darwin

package main

import (
	"net"
	"testing"
)

func TestInterfaceCanVLAN(t *testing.T) {
	present := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		present[ifi.Name] = true
	}

	if present["en0"] && !interfaceCanVLAN("en0") {
		t.Fatal("en0 should stay listed; its driver advertises VLAN support")
	}
	for _, name := range []string{"utun0", "lo0", "awdl0", "llw0", "ap1", "bridge0"} {
		if present[name] && interfaceCanVLAN(name) {
			t.Fatalf("%s cannot carry an 802.1Q tag", name)
		}
	}
}
