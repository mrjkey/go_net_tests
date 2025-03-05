package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	// interfaceName = "\\Device\\NPF_{70AD64C5-34A6-4ECA-9FB4-B11CB6006D9A}" // my wifi
	// interfaceName = "\\Device\\NPF_{95A9BED4-3C01-41DD-BB5C-1244AAE94A95}" // my ethernet
	interfaceName = "\\Device\\NPF_{96065AE6-861D-443F-96DC-5586B880BB6D}" // my ethernet

	duration = 5 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <pcap file>\n", os.Args[0])
	}

	// List all available interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to find devices: %v", err)
	}

	if len(devices) == 0 {
		log.Fatal("No devices found.")
	}

	// fmt.Println("Available devices:")
	// for _, device := range devices {
	// 	fmt.Printf("Name: %s\n", device.Name)
	// 	fmt.Printf("Description: %s\n", device.Description)
	// 	fmt.Println("Addresses:")
	// 	for _, address := range device.Addresses {
	// 		fmt.Printf("  IP: %s, Netmask: %s\n", address.IP, address.Netmask)
	// 	}
	// 	fmt.Println("-----------------------------------")
	// }

	pcapFile := os.Args[1]
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatalf("Failed to open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	firstPacket := []byte{}

	for packet := range packetSource.Packets() {
		firstPacket = packet.Data()
		break
	}

	if len(firstPacket) == 0 {
		log.Fatal("No packets found in PCAP file.")
	}

	// Open network interface for packet injection
	sendHandle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device %s: %v", interfaceName, err)
	}
	defer sendHandle.Close()

	log.Println("Starting packet replay...")
	startTime := time.Now()
	packetsSent := 0

	for time.Since(startTime) < duration {
		err = sendHandle.WritePacketData(firstPacket)
		if err != nil {
			log.Fatalf("Failed to send packet: %v", err)
		}
		packetsSent++
	}

	// log.Printf("Sent %d packets in %v\n", packetsSent, duration)
	// fmt.Println("Packet replay completed.")

	// Calculate transmission speed
	elapsedTime := time.Since(startTime).Seconds()
	totalBytesSent := packetsSent * len(firstPacket)
	mbps := (float64(totalBytesSent) * 8) / (elapsedTime * 1_000_000)

	log.Printf("Sent %d packets (%d bytes each) in %.2f seconds", packetsSent, len(firstPacket), elapsedTime)
	log.Printf("Transmission speed: %.2f Mbps", mbps)
	fmt.Println("Packet replay completed.")
}
