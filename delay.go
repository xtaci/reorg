package main

// reorgPacket carry extra information along with packet
type reorgPacket struct {
	packet []byte
	seq    uint32 // the sender's packet sequence
	ts     uint32 // the time to deliver to local tun
}

// a heap for delayed packet
type delayedPacketHeap []reorgPacket

func (h delayedPacketHeap) Len() int { return len(h) }
func (h delayedPacketHeap) Less(i, j int) bool {
	if _itimediff(h[i].ts, h[j].ts) < 0 {
		return true
	} else if _itimediff(h[i].ts, h[j].ts) == 0 && _itimediff(h[i].seq, h[j].seq) == 0 {
		return true
	}
	return false
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
