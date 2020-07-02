package main

type reorgPacket struct {
	packet []byte
	seq    uint32
	ts     uint32
}

// a heap for delayed packet
type delayedPacketHeap []reorgPacket

func (h delayedPacketHeap) Len() int { return len(h) }
func (h delayedPacketHeap) Less(i, j int) bool {
	return _itimediff(h[i].ts, h[j].ts) < 0 || (h[i].ts == h[j].ts && h[i].seq < h[j].seq)
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
