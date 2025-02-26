package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
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
	interfaceName := flag.String("interface", "eth0", "Network interface to use")
	destMAC := flag.String("destmac", "", "Destination MAC address (default: broadcast)")
	destIP := flag.String("destip", "255.255.255.255", "Destination IP address")
	srcIP := flag.String("srcip", "192.168.1.2", "Source IP address")
	destPort := flag.Int("destport", 8125, "Destination UDP port")
	srcPort := flag.Int("srcport", 12345, "Source UDP port")
	pps := flag.Int("pps", 1000, "Packets per second to send")
	payloadSize := flag.Int("size", 1400, "Payload size in bytes")
	duration := flag.Duration("duration", 0, "Duration to send (0 for indefinite)")
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

	// Open the device for sending
	handle, err := pcap.OpenLive(*interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device %s: %v", *interfaceName, err)
	}
	defer handle.Close()

	// Get interface information
	iface, err := net.InterfaceByName(*interfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", *interfaceName, err)
	}

	// Get source MAC address from the interface
	srcMAC := iface.HardwareAddr

	// Set destination MAC address
	var dstMAC net.HardwareAddr
	if *destMAC == "" {
		// Use broadcast MAC address if not specified
		dstMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	} else {
		dstMAC, err = net.ParseMAC(*destMAC)
		if err != nil {
			log.Fatalf("Invalid MAC address format: %v", err)
		}
	}

	// Parse source and destination IP addresses
	srcIPAddr := net.ParseIP(*srcIP)
	if srcIPAddr == nil {
		log.Fatalf("Invalid source IP address: %s", *srcIP)
	}

	dstIPAddr := net.ParseIP(*destIP)
	if dstIPAddr == nil {
		log.Fatalf("Invalid destination IP address: %s", *destIP)
	}

	// Create random payload
	payload := make([]byte, *payloadSize)
	rand.Read(payload)

	// Create packet layers
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIPAddr,
		DstIP:    dstIPAddr,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(*srcPort),
		DstPort: layers.UDPPort(*destPort),
	}

	// Set checksum for UDP layer
	err = udp.SetNetworkLayerForChecksum(&ip)
	if err != nil {
		log.Fatalf("Failed to set network layer for checksum: %v", err)
	}

	// Create serializer and buffer
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Create serialization buffer
	buf := gopacket.NewSerializeBuffer()

	// Signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// Variables for statistics
	var mu sync.Mutex
	var packetsSent uint64 = 0
	var bytesSent uint64 = 0
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
				currentPackets := packetsSent
				currentBytes := bytesSent
				intervalPackets := currentPackets - lastPackets
				intervalBytes := currentBytes - lastBytes
				lastPackets = currentPackets
				lastBytes = currentBytes
				mu.Unlock()

				elapsedSec := time.Since(startTime).Seconds()
				bitrate := float64(intervalBytes) * 8 / float64(*reportInterval) / 1_000_000 // Mbps
				avgPacketRate := float64(currentPackets) / elapsedSec

				fmt.Printf("Outgoing bitrate: %.2f Mbps | Packets: %d (%.2f pps avg) | Total sent: %.2f MB\n",
					bitrate, intervalPackets, avgPacketRate, float64(currentBytes)/1_000_000)

			case <-stopChan:
				return
			}
		}
	}()

	// Packet sender
	go func() {
		// Calculate sleep duration for rate limiting
		sleepDuration := time.Duration(1000000/(*pps)) * time.Microsecond

		endTime := time.Time{}
		if *duration > 0 {
			endTime = startTime.Add(*duration)
		}

		for {
			select {
			case <-stopChan:
				return
			default:
				// Check if we've exceeded the duration
				if *duration > 0 && time.Now().After(endTime) {
					close(stopChan)
					return
				}

				// Serialize the packet with payload
				err = gopacket.SerializeLayers(buf, opts,
					&eth, &ip, &udp, gopacket.Payload(payload))
				if err != nil {
					log.Printf("Failed to serialize packet: %v", err)
					continue
				}

				// Send the packet
				packetData := buf.Bytes()
				err = handle.WritePacketData(packetData)
				if err != nil {
					log.Printf("Failed to send packet: %v", err)
					continue
				}

				mu.Lock()
				packetsSent++
				bytesSent += uint64(len(packetData))
				mu.Unlock()

				// Sleep to maintain packet rate
				time.Sleep(sleepDuration)
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
	finalPackets := packetsSent
	finalBytes := bytesSent
	mu.Unlock()

	avgBitrate := float64(finalBytes) * 8 / elapsedSec / 1_000_000
	fmt.Printf("\nTotal packets: %d | Total bytes: %.2f MB | Avg bitrate: %.2f Mbps | Duration: %.2f sec\n",
		finalPackets, float64(finalBytes)/1_000_000, avgBitrate, elapsedSec)
}
