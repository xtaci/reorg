package main

import (
	"log"

	"github.com/songgao/water"
)

func main() {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "O_O"

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}
	packet := make([]byte, 1500)
	for {
		n, err := ifce.Read(packet)
		if err != nil {
			log.Fatal(err)
		}
		packet = packet[:n]

		log.Printf("Protocol: % x\n", packet[0]>>4)
	}
}
