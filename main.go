// Package main implements a VLAN discovery tool that probes network VLANs
// using DHCP requests and IPv6 Router Advertisements to identify active VLANs
// and their network configurations.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Command line flags for configuring the VLAN discovery tool.
var (
	version      = "dev"                                                     // Version string, set at build time
	iface        = flag.String("iface", "", "interface to test")             // Network interface name
	list         = flag.Bool("list", false, "print interface list and exit") // List available interfaces
	dhcpv4       = flag.Bool("dhcp", false, "enable DHCP requests")
	dhcpv6       = flag.Bool("dhcp6", false, "enable IPv6 DHCP requests")                          // Enable DHCP discovery
	sendRA       = flag.Bool("ra", false, "request IPv6 router advertisements")                    // Enable IPv6 RA requests
	macAddress   = flag.String("mac", "12:34:56:78:90:AB", "mac address to use for dhcp requests") // Source MAC
	printPackets = flag.Bool("print-packets", false, "print packets")                              // Debug packet printing
	hostname     = flag.String("hostname", "vlan-scout", "hostname to use for dhcp requests")      // DHCP hostname
	verbose      = flag.Bool("verbose", false, "print verbose output")                             // Verbose logging
	toJSON       = flag.Bool("json", false, "output to json")                                      // JSON output format
	randomMAC    = flag.Bool("random-mac", false, "use random mac address")                        // Generate random MAC
	showVersion  = flag.Bool("version", false, "print version and exit")                           // Show version
	workers      = flag.Int("workers", 10, "number of parallel workers for VLAN scanning")         // Parallel workers
	timeout      = flag.Duration("timeout", 0, "timeout to wait for responses")                    // Response timeout
)

// VLAN ID constants defining the valid range (1-4094).
const (
	VLAN_MIN = 1    // Minimum VLAN ID (0 = untagged)
	VLAN_MAX = 4094 // Maximum VLAN ID per 802.1Q standard
)

// Global state variables for tracking discoveries and test progress.
var findings = &Findings{
	Vlans: make(map[uint16]*VlanFinding),
} // Stores all VLAN discovery results
var (
	activeVlanTest     = uint16(0)
	activeTestComplete = false
	active             = false
)

// main is the entry point of the VLAN discovery tool.
// It parses command line arguments and initiates the discovery process.
func main() {
	flag.Parse()
	active = *dhcpv4 || *sendRA || *dhcpv6

	if *showVersion {
		fmt.Println(version)
		return
	}

	if *list {
		printDevices()
		return
	}
	if *randomMAC {
		*macAddress = GenerateRandomMAC()
		v("Using random mac address: %s", *macAddress)
	}
	// normalize mac address
	*macAddress = strings.ToLower(*macAddress)

	if len(*iface) == 0 {
		log.Fatal("must pass iface")
	}
	start()
}

// start initializes and runs the main VLAN discovery process.
// It sets up signal handling, starts DHCP/RA probing goroutines,
// and begins packet capture for response analysis.
func start() {
	// Create a waitgroup to ensure sender goroutines finish before shutdown.
	var wg sync.WaitGroup

	// Create a channel to listen for OS signals.
	sigs := make(chan os.Signal, 1)

	// Register the channel to receive SIGINT (Ctrl+C) and SIGTERM signals.
	// SIGTERM is often used for graceful shutdowns by process managers.
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// Create a channel to signal when the program should exit after handling the signal.
	done := make(chan bool, 2) // Increased buffer to handle both signal and timeout goroutines

	// Start a goroutine to handle the received signals.
	go func() {
		sig := <-sigs // Block until a signal is received
		fmt.Printf("\nReceived signal: %s. Performing graceful shutdown...\n", sig)
		signal.Stop(sigs) // allow a second signal to kill

		// Perform cleanup or other actions here before exiting.
		// For example, close database connections, save data, etc.

		done <- true // Signal that cleanup is done and the main goroutine can exit
		close(done)
	}()

	if active {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Second / 2)
			v("sending active requests with %d workers", *workers)
			//runDHCPWorkers(*workers)
			runWorkers(*workers)
			v("Done sending active requests")
		}()
	}

	// Goroutine to wait for senders and then signal shutdown after a timeout
	go func() {
		waitTimeout := *timeout
		if active && waitTimeout == 0 {
			// Active mode: wait for senders to complete, then wait for responses
			wg.Wait() // Wait for all sender goroutines to complete
			waitTimeout = time.Second * 3
			v("All requests sent. Waiting %s for responses...", waitTimeout.String())
		}

		if waitTimeout == 0 {
			// no timeout, run forever or until user cancels
			return
		}

		// Use timer that can be interrupted by signals
		timer := time.NewTimer(waitTimeout)
		defer timer.Stop()

		select {
		case <-timer.C:
			// Timeout reached normally
			done <- true
			close(done)
		case <-sigs:
			// Signal received, don't send to done channel as signal handler will do it
			return
		}
	}()

	filter := fmt.Sprintf("vlan or ether host %s or ether multicast", *macAddress)
	v("listening for packets on %s with filter '%s'", *iface, filter)
	if handle, err := pcap.OpenLive(*iface, int32(65535), true, pcap.BlockForever); err != nil {
		// The pcap library doesn't export specific error types for many
		// conditions, so we have to rely on string matching for some errors.
		if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "permitted") {
			log.Fatalf("Error: You don't have permission to capture on '%s'. Please try running with sudo or as root.\nDetails: %v", *iface, err)
		}
		if strings.Contains(err.Error(), "No such device exists") {
			log.Fatalf("Error: %v", err)
		}
		log.Fatalf("Open Error: %v", err)
	} else if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("SetBPFFilter Error: %v", err)
	} else {
		defer handle.Close()
		fmt.Println("Program running. Press Ctrl+C to trigger graceful shutdown.")
		go printStatus(done)

		// Create PacketProcessor for better performance
		processor := NewPacketProcessor()

		// Anonymous function to scope the packet handling loop
		func() {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetChan := packetSource.Packets()
			for {
				select {
				case packet := <-packetChan:
					processor.HandlePacket(packet.Data())
				case <-done:
					fmt.Println() // Print a newline to avoid overwriting the status line
					v("Exiting gracefully...")
					return
				}
			}
		}()
	}

	<-done // Block the main goroutine until the 'done' channel receives a value

	if *toJSON {
		fmt.Println(findings.ToJson())
	} else {
		fmt.Println(findings.String())
	}
	v("Program exited.")
}

// printDevices lists all available network interfaces with their addresses.
// It filters out inactive, Bluetooth, and virtual interfaces.
func printDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	check(err)

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		// skip CONNECTION_STATUS_NOT_APPLICABLE if not also UP
		if device.Flags&PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE != 0 && device.Flags&PCAP_IF_UP == 0 {
			continue
		}
		// skip bluetooth
		if strings.HasPrefix(device.Name, "bluetooth") {
			continue
		}
		// skip any
		if device.Name == "any" {
			continue
		}
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			ip := IP2IPNet(address.IP, address.Netmask)
			fmt.Println("- IP address: ", ip.String())
		}
	}
}

func runWorkers(numWorkers int) {
	// Create a channel to send VLAN IDs to workers
	vlanChan := make(chan uint16, numWorkers*2)

	// Create a wait group for workers
	var workerWG sync.WaitGroup

	// Track progress with a mutex for thread safety
	var progressMutex sync.Mutex

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			for vlanID := range vlanChan {
				if *dhcpv4 {
					v("Worker %d: Sending DHCP request on VLAN %d", workerID, vlanID)
					if err := sendDHCPDiscover(vlanID); err != nil {
						log.Printf("Worker %d: DHCP Discover failed on VLAN %d: %v", workerID, vlanID, err)
					}
				}

				if *sendRA {
					v("Worker %d: Sending RA request on VLAN %d", workerID, vlanID)
					if err := sendRouterSolicitation(vlanID); err != nil {
						log.Printf("Worker %d: IPv6 RA Solicit failed on VLAN %d: %v", workerID, vlanID, err)
					}
				}

				if *dhcpv6 {
					// Also send DHCPv6 Solicit to discover DHCPv6 servers
					// (some networks have DHCPv6 without Router Advertisements)
					v("Worker %d: Sending DHCPv6 Solicit on VLAN %d", workerID, vlanID)
					if err := sendDHCPv6Solicit(vlanID); err != nil {
						log.Printf("Worker %d: DHCPv6 Solicit failed on VLAN %d: %v", workerID, vlanID, err)
					}
				}

				// Update progress safely
				progressMutex.Lock()
				if vlanID > activeVlanTest {
					activeVlanTest = vlanID
				}
				progressMutex.Unlock()

				// Small delay to avoid overwhelming the network
				time.Sleep(time.Millisecond * 50)
			}
		}(i)
	}

	// Send all VLAN IDs to the channel
	go func() {
		defer close(vlanChan)
		for i := VLAN_MIN; i < VLAN_MAX; i++ {
			vlanChan <- uint16(i)
		}
	}()

	// Wait for all workers to complete
	workerWG.Wait()
	v("All workers done")
	activeTestComplete = true
}

// printStatus displays real-time progress of VLAN discovery.
// It shows current test progress and discovered VLANs until signaled to stop.
func printStatus(done <-chan bool) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			progressParts := make([]string, 0, 2)

			if active {
				if activeTestComplete {
					progressParts = append(progressParts, "scan: done")
				} else if activeVlanTest > 0 {
					progress := float64(activeVlanTest) / float64(VLAN_MAX) * 100
					progressParts = append(progressParts, fmt.Sprintf("scan: %.0f%%", progress))
				}
			}

			progressStr := ""
			if len(progressParts) > 0 {
				progressStr = " | " + strings.Join(progressParts, " ")
			}

			fmt.Printf("\r%s%s", findings.StatusString(), progressStr)
		case <-done:
			return
		}
	}
}
