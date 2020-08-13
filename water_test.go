package main

import (
	"testing"

	"github.com/songgao/water"
)

func BenchmarkIface(b *testing.B) {
	// create a tun device
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		b.Fatal(err)
	}

	buffer := make([]byte, 1500)
	b.SetBytes(int64(len(buffer)))
	for i := 0; i < b.N; i++ {
		n, err := iface.Write(buffer)
		if err != nil {
			b.Fatal(err, n)
		}
	}
}
