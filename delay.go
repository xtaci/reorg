package main

import "time"

type reorgPacket struct {
	packet []byte
	seq    uint32
	ts     time.Time
}

// a heap for delayed packet
type delayedPacketHeap []reorgPacket

func (h delayedPacketHeap) Len() int { return len(h) }
func (h delayedPacketHeap) Less(i, j int) bool {
	return h[i].ts.Before(h[j].ts) || (h[i].ts.Equal(h[j].ts) && h[i].seq < h[j].seq)
}
func (h delayedPacketHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *delayedPacketHeap) Push(x interface{}) { *h = append(*h, x.(reorgPacket)) }
func (h *delayedPacketHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1].packet = nil // avoid memory leak
	*h = old[0 : n-1]
	return x
}
