package main

// reorgPacket carry extra information along with packet
type reorgPacket struct {
	packet []byte
	seq    uint32 // the sender's packet sequence
	ts     uint32 // the sender's packet transmit time to smooth jitter
}

// a heap for delayed packet
type delayedPacketHeap []reorgPacket

func (h delayedPacketHeap) Len() int            { return len(h) }
func (h delayedPacketHeap) Less(i, j int) bool  { return _itimediff(h[i].seq, h[j].seq) < 0 }
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
