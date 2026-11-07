package main

import (
	"bytes"
	"flag"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestGenerateRandomMACIsUnicastLocal(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		s := GenerateRandomMAC()
		hw, err := net.ParseMAC(s)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", s, err)
		}
		if hw[0]&0x01 != 0 {
			t.Fatalf("multicast source %s", s)
		}
		if hw[0]&0x02 == 0 {
			t.Fatalf("universally administered source %s", s)
		}
		if err := validateSourceMAC(s); err != nil {
			t.Fatalf("validateSourceMAC(%s): %v", s, err)
		}
		seen[s] = true
	}
	if len(seen) < 900 {
		t.Fatalf("expected mostly unique addresses, got %d", len(seen))
	}
}

func TestCaptureFilterIncludesProbeAndInterfaceMAC(t *testing.T) {
	const probe = "02:00:00:00:00:01"
	f := captureFilter(probe, "no-such-iface-vlan-scout")
	if !strings.Contains(f, "ether host "+probe) {
		t.Fatalf("filter missing probe MAC: %s", f)
	}
	if strings.Contains(f, "no-such-iface") {
		t.Fatalf("filter should ignore a missing interface: %s", f)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if len(ifi.HardwareAddr) != 6 {
			continue
		}
		f = captureFilter(probe, ifi.Name)
		hw := ifi.HardwareAddr.String()
		if hw != probe && !strings.Contains(f, "ether host "+hw) {
			t.Fatalf("filter %s missing interface MAC %s", f, hw)
		}
		return
	}
	t.Skip("no interface with a hardware address")
}

func TestUsageIncludesHowToRun(t *testing.T) {
	var buf bytes.Buffer
	orig := flag.CommandLine.Output()
	flag.CommandLine.SetOutput(&buf)
	t.Cleanup(func() { flag.CommandLine.SetOutput(orig) })

	usage()
	out := buf.String()
	for _, want := range []string{
		os.Args[0] + " -iface <name>",
		os.Args[0] + " -list",
		os.Args[0] + " -version",
		"-all",
		"-random-mac",
		"-hostname computer101",
		"interface to capture on (required to scan)",
		"Examples:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q\n%s", want, out)
		}
	}
}

func TestParseVlanListDefaultIncludesUntaggedAndLastID(t *testing.T) {
	got, err := parseVlanList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != VLAN_MAX-VLAN_MIN+2 {
		t.Fatalf("len %d", len(got))
	}
	if got[0] != 0 || got[len(got)-1] != VLAN_MAX {
		t.Fatalf("ends %d..%d", got[0], got[len(got)-1])
	}

	got, err = parseVlanList("0,4094")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 0 || got[1] != 4094 {
		t.Fatalf("%v", got)
	}
	if _, err := parseVlanList("4095"); err == nil {
		t.Fatal("expected 4095 to be rejected")
	}
}

func TestProbeLinkLocalIsNotListedAsHost(t *testing.T) {
	hw, err := net.ParseMAC("8e:29:09:b6:01:bd")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := macToLinkLocal(hw)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "fe80::8c29:9ff:feb6:1bd" {
		t.Fatalf("link local %s", ip)
	}

	f := &Findings{Vlans: map[uint16]*VlanFinding{}}
	f.AddIPv6Host(86, ip)
	f.MarkOwnIP(ip)
	f.AddIPv6Host(86, net.ParseIP("fe80::1"))
	if _, ok := f.Vlans[86].Hosts.HostsIPv6[ip.String()]; ok {
		t.Fatal("probe link-local was kept")
	}
	if len(f.Vlans[86].Hosts.HostsIPv6) != 1 {
		t.Fatalf("hosts: %v", f.Vlans[86].Hosts.HostsIPv6)
	}
}

func TestUntaggedFindingLabel(t *testing.T) {
	f := &Findings{Vlans: map[uint16]*VlanFinding{}}
	f.AddIPv4Host(0, net.ParseIP("10.47.22.1"))
	if !strings.Contains(f.StatusString(), "untagged(") {
		t.Fatalf("status: %s", f.StatusString())
	}
	if !strings.Contains(f.String(), "Untagged:") {
		t.Fatalf("report: %s", f.String())
	}
}

func TestToJsonSortsHosts(t *testing.T) {
	f := &Findings{Vlans: map[uint16]*VlanFinding{}}
	f.AddIPv4Host(4, net.ParseIP("10.0.0.9"))
	f.AddIPv4Host(4, net.ParseIP("10.0.0.1"))
	js := f.ToJson()
	if strings.Index(js, "10.0.0.1") > strings.Index(js, "10.0.0.9") {
		t.Fatalf("hosts not sorted: %s", js)
	}
}

func TestHasIPAddress(t *testing.T) {
	if hasIPAddress(nil) {
		t.Fatal("nil address list")
	}
	if hasIPAddress([]pcap.InterfaceAddress{{}}) {
		t.Fatal("empty address")
	}
	if !hasIPAddress([]pcap.InterfaceAddress{{IP: net.ParseIP("10.47.22.152")}}) {
		t.Fatal("expected an address")
	}
}

func TestValidateSourceMAC(t *testing.T) {
	if err := validateSourceMAC("12:34:56:78:90:ab"); err != nil {
		t.Fatal(err)
	}
	if err := validateSourceMAC("01:00:00:00:00:01"); err == nil {
		t.Fatal("expected multicast address to be rejected")
	}
	if err := validateSourceMAC("not-a-mac"); err == nil {
		t.Fatal("expected invalid address to be rejected")
	}
}
