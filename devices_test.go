package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestDeviceRecordIncludesAvailableInfo(t *testing.T) {
	dev := pcap.Interface{
		Name:        "en0",
		Description: "Ethernet",
		Flags:       PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_CONNECTED,
		Addresses: []pcap.InterfaceAddress{{
			IP:        net.ParseIP("10.47.22.152").To4(),
			Netmask:   net.CIDRMask(24, 32),
			Broadaddr: net.ParseIP("10.47.22.255").To4(),
		}},
	}
	rec := deviceRecord(dev, "9c:76:0e:2e:3e:89")
	if rec.Name != "en0" || rec.Description != "Ethernet" || rec.MAC != "9c:76:0e:2e:3e:89" {
		t.Fatalf("identity: %+v", rec)
	}
	if !rec.Flags.Up || !rec.Flags.Running || rec.Flags.Loopback || rec.Flags.Wireless || rec.Flags.Connection != "connected" {
		t.Fatalf("flags: %+v", rec.Flags)
	}
	if len(rec.Addresses) != 1 || rec.Addresses[0].IP != "10.47.22.152" || rec.Addresses[0].Netmask != "255.255.255.0" || rec.Addresses[0].Prefix != 24 || rec.Addresses[0].Broadcast != "10.47.22.255" {
		t.Fatalf("address: %+v", rec.Addresses)
	}

	js := devicesToJSON([]pcap.Interface{dev}, map[string]string{dev.Name: "9c:76:0e:2e:3e:89"})
	var parsed deviceList
	if err := json.Unmarshal([]byte(js), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Devices) != 1 || !strings.Contains(js, "9c:76:0e:2e:3e:89") {
		t.Fatalf("json: %s", js)
	}
}

func TestDeviceRecordOmitsMissingMAC(t *testing.T) {
	dev := pcap.Interface{Name: "utun0", Flags: PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE}
	js := devicesToJSON([]pcap.Interface{dev}, nil)
	if strings.Contains(js, `"mac"`) {
		t.Fatalf("empty mac was included: %s", js)
	}
	if !strings.Contains(js, `"connection": "not_applicable"`) || !strings.Contains(js, `"addresses": []`) {
		t.Fatalf("json: %s", js)
	}
}
