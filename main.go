package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface    = "lo0"
	snaplen  = int32(1600)
	promisc  = false
	timeout  = pcap.BlockForever
	filter   = "tcp and port 4224"
	devFound = false
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln(err)
	}

	for _, d := range devices {
		if d.Name == iface {
			devFound = true
		}
	}
	if !devFound {
		log.Panicf("Device named '%s' does not exist\n", iface)
	}

	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	defer handle.Close()
	if err != nil {
		log.Panicln(err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Panicln(err)
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")

			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN {
				fmt.Printf("SYN %v\n", tcp.SYN)
			}
			if tcp.ACK {
				fmt.Printf("ACK %v\n", tcp.ACK)
			}
			if tcp.RST {
				fmt.Printf("RST %v\n", tcp.RST)
			}
		}
	}
}
