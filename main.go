package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}

	for _, d := range devices {
		fmt.Println(d.Name)
		for _, a := range d.Addresses {
			fmt.Printf("   IP:      %s\n", a.IP)
			fmt.Printf("   Netmask: %s\n", a.Netmask)
		}
	}
}
