package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Command line flags
	interfaceName := flag.String("interface", "eth0", "Network interface to listen on")
	port := flag.Int("port", 8125, "UDP port to listen for")
	promiscuous := flag.Bool("promisc", true, "Put interface in promiscuous mode")
	reportInterval := flag.Int("report", 1, "Reporting interval in seconds")
	flag.Parse()

	// List all available interfaces if none specified
	if *interfaceName == "" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("Failed to find devices: %v", err)
		}
		if len(devices) == 0 {
			log.Fatal("No devices found.")
		}
		fmt.Println("Available devices:")
		for _, device := range devices {
			fmt.Printf("Name: %s\n", device.Name)
			fmt.Printf("Description: %s\n", device.Description)
			fmt.Println("Addresses:")
			for _, address := range device.Addresses {
				fmt.Printf("  IP: %s, Netmask: %s\n", address.IP, address.Netmask)
			}
			fmt.Println("-----------------------------------")
		}
		log.Fatal("Please specify an interface name with -interface")
	}

	// Set up pcap capture
	handle, err := pcap.OpenLive(*interfaceName, 65536, *promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device %s: %v", *interfaceName, err)
	}
	defer handle.Close()

	// Set filter to capture only UDP packets on the specified port
	filter := fmt.Sprintf("udp and port %d", *port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Failed to set BPF filter: %v", err)
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// Variables for statistics
	var mu sync.Mutex
	var packetsReceived uint64 = 0
	var bytesReceived uint64 = 0
	startTime := time.Now()

	// Create a stop channel
	stopChan := make(chan struct{})

	// Start reporter
	go func() {
		ticker := time.NewTicker(time.Duration(*reportInterval) * time.Second)
		defer ticker.Stop()

		var lastPackets uint64 = 0
		var lastBytes uint64 = 0

		for {
			select {
			case <-ticker.C:
				mu.Lock()
				currentPackets := packetsReceived
				currentBytes := bytesReceived
				intervalPackets := currentPackets - lastPackets
				intervalBytes := currentBytes - lastBytes
				lastPackets = currentPackets
				lastBytes = currentBytes
				mu.Unlock()

				elapsedSec := time.Since(startTime).Seconds()
				bitrate := float64(intervalBytes) * 8 / float64(*reportInterval) / 1_000_000 // Mbps
				avgPacketRate := float64(currentPackets) / elapsedSec

				fmt.Printf("Incoming bitrate: %.2f Mbps | Packets: %d (%.2f pps avg) | Total received: %.2f MB\n",
					bitrate, intervalPackets, avgPacketRate, float64(currentBytes)/1_000_000)

			case <-stopChan:
				return
			}
		}
	}()

	// Start packet processing
	go func() {
		for {
			select {
			case packet := <-packetSource.Packets():
				// Process packet
				if packet == nil {
					continue
				}

				// Calculate packet size
				packetSize := len(packet.Data())

				// Extract UDP layer if needed for more detailed info
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					_ = udp // Can be used for additional info if needed
				}

				mu.Lock()
				packetsReceived++
				bytesReceived += uint64(packetSize)
				mu.Unlock()

			case <-stopChan:
				return
			}
		}
	}()

	// Wait for interrupt
	<-sigChan
	fmt.Println("\nShutting down...")
	close(stopChan)

	// Final statistics
	time.Sleep(200 * time.Millisecond)
	elapsedSec := time.Since(startTime).Seconds()
	mu.Lock()
	finalPackets := packetsReceived
	finalBytes := bytesReceived
	mu.Unlock()

	avgBitrate := float64(finalBytes) * 8 / elapsedSec / 1_000_000
	fmt.Printf("\nTotal packets: %d | Total bytes: %.2f MB | Avg bitrate: %.2f Mbps | Duration: %.2f sec\n",
		finalPackets, float64(finalBytes)/1_000_000, avgBitrate, elapsedSec)
}
