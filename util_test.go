package main

import (
	"bytes"
	"flag"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
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

func TestCaptureFilterMatchesInterfaceOnlyForProbeReplies(t *testing.T) {
	const probe = "02:00:00:00:00:01"
	f := captureFilter(probe, nil)
	if !strings.Contains(f, "ether host "+probe) {
		t.Fatalf("filter missing probe MAC: %s", f)
	}
	if strings.Contains(f, "udp port 68") {
		t.Fatalf("filter without an interface MAC should not match DHCP client port: %s", f)
	}
	if _, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, f); err != nil {
		t.Fatal(err)
	}

	hw := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	f = captureFilter(probe, hw)
	if strings.Contains(f, "ether host "+hw.String()) {
		t.Fatalf("filter matches all traffic for the interface: %s", f)
	}
	want := "ether dst " + hw.String() + " and (udp port 68 or udp port 546 or icmp6[icmp6type] == icmp6-routeradvert)"
	if !strings.Contains(f, want) {
		t.Fatalf("filter %s missing %s", f, want)
	}
	if _, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, f); err != nil {
		t.Fatal(err)
	}

	f = captureFilter(hw.String(), hw)
	if strings.Contains(f, "udp port 68") {
		t.Fatalf("probe MAC is the interface MAC, so no extra clause is needed: %s", f)
	}
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
		os.Args[0] + " -list [-a]",
		os.Args[0] + " -list -a",
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
	f.MarkOwnIP(86, ip)
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

func TestOwnIPIsKeptPerVLAN(t *testing.T) {
	ip := net.ParseIP("192.168.1.50")
	f := &Findings{Vlans: map[uint16]*VlanFinding{}}
	f.AddIPv4Host(10, ip)
	f.AddIPv4Host(20, ip)
	f.MarkOwnIP(10, ip)
	if _, ok := f.Vlans[10].Hosts.HostsIPv4[ip.String()]; ok {
		t.Fatal("own address kept on its VLAN")
	}
	if _, ok := f.Vlans[20].Hosts.HostsIPv4[ip.String()]; !ok {
		t.Fatal("same address removed from another VLAN")
	}
	f.AddIPv4Host(10, ip)
	if _, ok := f.Vlans[10].Hosts.HostsIPv4[ip.String()]; ok {
		t.Fatal("own address was added again")
	}
}

func TestDHCPClientMatch(t *testing.T) {
	orig := *macAddress
	*macAddress = "02:00:00:00:00:0a"
	t.Cleanup(func() { *macAddress = orig })

	probe, err := net.ParseMAC(*macAddress)
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.ParseMAC("02:00:00:00:00:0b")
	if err != nil {
		t.Fatal(err)
	}
	if !clientHWIsProbe(probe) {
		t.Fatal("probe MAC did not match")
	}
	if clientHWIsProbe(other) {
		t.Fatal("other MAC matched the probe")
	}

	ours := layers.DHCPv6Options{{
		Code: layers.DHCPv6OptClientID,
		Data: append([]byte{0x00, 0x03, 0x00, 0x01}, probe...),
	}}
	theirs := layers.DHCPv6Options{{
		Code: layers.DHCPv6OptClientID,
		Data: append([]byte{0x00, 0x03, 0x00, 0x01}, other...),
	}}
	if !dhcpv6ClientIsProbe(ours) {
		t.Fatal("expected our DUID-LL")
	}
	if dhcpv6ClientIsProbe(theirs) {
		t.Fatal("other client's DUID matched")
	}
	if dhcpv6ClientIsProbe(nil) {
		t.Fatal("empty options matched")
	}
}

func TestFrameFromUsIncludesInterfaceMAC(t *testing.T) {
	origMAC := *macAddress
	origHW := ifaceHW
	*macAddress = "02:00:00:00:00:0a"
	ifaceHW = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	t.Cleanup(func() {
		*macAddress = origMAC
		ifaceHW = origHW
	})

	probe, err := net.ParseMAC(*macAddress)
	if err != nil {
		t.Fatal(err)
	}
	if !frameFromUs(probe) || !frameFromUs(ifaceHW) {
		t.Fatal("expected probe and interface sources to be skipped")
	}
	other := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}
	if frameFromUs(other) {
		t.Fatal("another host was treated as ours")
	}
}

func TestInterfaceMACsMatchNet(t *testing.T) {
	macs := interfaceMACs()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		got := macs[ifi.Name]
		want := ""
		if len(ifi.HardwareAddr) > 0 {
			want = ifi.HardwareAddr.String()
		}
		if got != want {
			t.Fatalf("%s: got %q want %q", ifi.Name, got, want)
		}
	}
}

func TestShowDeviceListAll(t *testing.T) {
	orig := *listAll
	t.Cleanup(func() { *listAll = orig })

	inactive := uint32(PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
	*listAll = false
	if showDevice("en1", inactive) {
		t.Fatal("inactive interface listed")
	}
	if showDevice("any", PCAP_IF_UP) || showDevice("bluetooth0", PCAP_IF_UP) {
		t.Fatal("virtual interface listed")
	}
	*listAll = true
	if !showDevice("en1", inactive) || !showDevice("any", 0) || !showDevice("utun0", 0) {
		t.Fatal("-a hid an interface")
	}
}

func TestInterfaceIsInactive(t *testing.T) {
	connected := uint32(PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_CONNECTED)
	inactive := uint32(PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
	tunnel := uint32(PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)
	down := uint32(PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)
	unknown := uint32(PCAP_IF_UP | PCAP_IF_RUNNING)

	if interfaceIsInactive(connected) || interfaceIsInactive(tunnel) || interfaceIsInactive(unknown) {
		t.Fatal("connected, tunnel, and unknown-status interfaces should stay listed")
	}
	if !interfaceIsInactive(inactive) {
		t.Fatal("disconnected interface should be hidden")
	}
	if !interfaceIsInactive(down) {
		t.Fatal("down interface with no connection status should be hidden")
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
