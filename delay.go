package main

import "time"

type delayedPacket struct {
	packet []byte
	ts     time.Time
}

// a heap for delayed packet
type delayedPacketHeap []delayedPacket

func (h delayedPacketHeap) Len() int            { return len(h) }
func (h delayedPacketHeap) Less(i, j int) bool  { return h[i].ts.Before(h[j].ts) }
func (h delayedPacketHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *delayedPacketHeap) Push(x interface{}) { *h = append(*h, x.(delayedPacket)) }
func (h *delayedPacketHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1].packet = nil // avoid memory leak
	*h = old[0 : n-1]
	return x
}
