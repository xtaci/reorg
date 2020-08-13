package main

import (
	"container/heap"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/tcpraw"
	"golang.org/x/crypto/pbkdf2"
)

const (
	latencyUpdatePeriod = 60000 // 60s
	defaultRTOSamples   = 128
)

const (
	defaultPacketQueue = 1024 // packet IO queue of device
)

const (
	defaultServerTunIP = "10.1.0.1/24"
	defaultClientTunIP = "10.1.0.2/24"
)

const (
	hdrSize   = 10 // extra header size for each packet
	seqOffset = 2
	tsOffset  = 6
)

// Reorg defines a packet organizer to add extra latency in exchange for smoothness and throughput
// from multiple link
type Reorg struct {
	config *Config        // the system config.
	block  kcp.BlockCrypt // the initialized block cipher.

	iface   *water.Interface // tun device
	linkmtu int              // the link mtu of this tun device

	chBalancer chan reorgPacket // packets received from tun device will be delivered to balancer
	chKcpTX    chan reorgPacket // packets received from balancer will be delivered to this chan.
	chTunTX    chan reorgPacket // packets from kcp session will be sent here awaiting to deliver to device

	chSamplesRTO chan uint32 //  all nearest latency samples from different links
	currentRTO   uint32

	die     chan struct{} // closing signal.
	dieOnce sync.Once
}

// currentMs returns current elasped monotonic milliseconds since program startup
func currentMs() uint32 { return uint32(time.Now().UnixNano() / int64(time.Millisecond)) }

func _itimediff(later, earlier uint32) int32 {
	return (int32)(later - earlier)
}

// NewReorg initialize a Reorg object for data exchanging between
// tun-device & kcp session
func NewReorg(config *Config) *Reorg {
	log.Println("initiating key derivation")
	pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
	log.Println("key derivation done")
	var block kcp.BlockCrypt
	switch config.Crypt {
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	default:
		config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}

	// create a tun device
	iface, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: config.Tun},
	})
	if err != nil {
		log.Fatal(err)
	}

	// config the tun device's ip and mtu
	tundevice, _ := netlink.LinkByName(config.Tun)
	var addr *netlink.Addr
	if config.TunIP == "" {
		if config.Client { // default address to 10.1.0.2 as client, and 10.1.0.1 as server
			addr, _ = netlink.ParseAddr(defaultClientTunIP)
		} else {
			addr, _ = netlink.ParseAddr(defaultServerTunIP)
		}
		netlink.AddrAdd(tundevice, addr)
	} else {
		addr, err = netlink.ParseAddr(config.TunIP)
		if err != nil {
			log.Fatal("netlink.ParseAddr", "err", err)
		}
	}
	// set address
	netlink.AddrAdd(tundevice, addr)
	// set mtu
	linkmtu := config.MTU - hdrSize
	netlink.LinkSetMTU(tundevice, linkmtu)
	// set up
	netlink.LinkSetUp(tundevice)

	log.Println("TUN interface name:", config.Tun)
	log.Println("TUN device MTU:", linkmtu)
	log.Println("TUN device IP:", addr)

	// create the object
	reorg := new(Reorg)
	reorg.config = config
	reorg.block = block
	reorg.chBalancer = make(chan reorgPacket, defaultPacketQueue)
	reorg.chKcpTX = make(chan reorgPacket)
	reorg.chTunTX = make(chan reorgPacket)
	reorg.die = make(chan struct{})
	reorg.iface = iface
	reorg.linkmtu = linkmtu
	reorg.chSamplesRTO = make(chan uint32, defaultRTOSamples)
	reorg.currentRTO = uint32(config.Latency)
	return reorg
}

// Serve starts serving tunnel service
func (reorg *Reorg) Serve() {
	go reorg.sampler()
	// spin-up tun-device reader/writer
	go reorg.balancer()
	go reorg.tunRX()
	go reorg.tunTX()

	if reorg.config.Client {
		// client creates aggregator on tun
		// the client connections will re-new itself periodically
		for k, remote := range reorg.config.RemoteAddr {
			// we start client with some latency for each client
			// to prevent from stop & re-connecting simultaneously.
			log.Printf("connecting client#%v to %v", k, remote)
			go reorg.client(remote)
			<-time.After(time.Second)
		}
	} else {
		// start server
		go reorg.server()
	}

	// wait on termination signal
	select {
	case <-reorg.die:
		return
	}
}

// terminate the re-organizer
func (reorg *Reorg) Close() {
	reorg.dieOnce.Do(func() {
		close(reorg.die)
		reorg.iface.Close()
	})
}

// sampler is a goroutine to estimate the best RTO for multiple links
func (reorg *Reorg) sampler() {
	// a sliding samples window
	samples := make([]uint32, defaultRTOSamples)
	for k := range samples {
		samples[k] = uint32(reorg.config.Latency)
	}
	var seq uint32

	ticker := time.NewTicker(latencyUpdatePeriod * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case rto := <-reorg.chSamplesRTO:
			idx := seq % defaultRTOSamples
			samples[idx] = rto
			seq++
		case <-ticker.C:
			max := samples[0]
			for i := 1; i < len(samples); i++ {
				if samples[i] > max {
					max = samples[i]
				}
			}

			atomic.StoreUint32(&reorg.currentRTO, max)
			log.Println("setting current RTO to:", max)
		case <-reorg.die:
			return
		}
	}
}

func (reorg *Reorg) reportRTO(rto uint32) {
	select {
	case reorg.chSamplesRTO <- rto:
	case <-reorg.die:
		return
	}
}

// tunRX is a goroutine for tun-device to receive incoming packets
func (reorg *Reorg) tunRX() {
	var seq uint32
	buffer := make([]byte, reorg.linkmtu)
	for {
		n, err := reorg.iface.Read(buffer[:])
		if err != nil {
			log.Println("tunReader", "err", err, "n", n)
		}

		// create a copy of packets with closest buffer size to avoid wasting memory
		packet := defaultAllocator.Get(n)
		copy(packet, buffer)

		select {
		case reorg.chBalancer <- reorgPacket{packet, seq, currentMs()}:
			// seq is monotonic for a tun-device
			seq++
		case <-reorg.die:
			return
		}
	}
}

// balancer is a groutine to balance packets from tun to different kcp link
func (reorg *Reorg) balancer() {
	var reorgPackets []reorgPacket
	var chKcpTX chan reorgPacket
	var nextPacket reorgPacket

	for {
		select {
		case p := <-reorg.chBalancer:
			// staging all packets from tun to prevent packet lost while tun txqueue becomes full
			reorgPackets = append(reorgPackets, p)
			chKcpTX = reorg.chKcpTX
			nextPacket = reorgPackets[0]
		case chKcpTX <- nextPacket:
			// distribute packets evenly into kcp sessions via channel
			reorgPackets = reorgPackets[1:]
			if len(reorgPackets) != 0 {
				nextPacket = reorgPackets[0]
			} else {
				chKcpTX = nil // stop sending by setting chan to nil
			}
		case <-reorg.die:
			return
		}
	}
}

// tunTX is a goroutine to delay the sending of incoming packet to a fixed interval,
// this works as a low-pass filter for latency deviation to mitigate types of noise, such as:
// runtime scheduler's channel send/recv delay, multi link latency.
// the algorithm follows the rules below:
//
// 1. try best to delivery the packet(from multiple links) in order
// 2. if packets arrived out of order, wait at most interval(like 40ms) before delivery.
//
func (reorg *Reorg) tunTX() {
	var packetHeap delayedPacketHeap
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	flush := func() {
		// try flush packets in order
		for packetHeap.Len() > 0 {
			if _itimediff(currentMs(), packetHeap[0].ts) >= 0 {
				// and if expired, force delivery
				packet := heap.Pop(&packetHeap).(reorgPacket).packet
				n, err := reorg.iface.Write(packet)
				defaultAllocator.Put(packet) // recycle after write
				if err != nil {
					log.Println("tunTX", "err", err, "n", n)
				}
			} else {
				break
			}
		}
	}

	// the core reorganizing loop will check timeout periodically
	for {
		select {
		case dp := <-reorg.chTunTX:
			heap.Push(&packetHeap, dp)
			flush()
		case <-ticker.C:
			flush()
		case <-reorg.die:
			return
		}
	}
}

// kcpTX is a goroutine to carry packets from tun device to kcp session.
func (reorg *Reorg) kcpTX(conn *kcp.UDPSession, rxStopChan <-chan struct{}, isClient bool) {
	timeout := time.Duration(reorg.config.KeepAlive/2) * time.Second

	var autoExpireChan <-chan time.Time
	if isClient { // only client side expires
		autoExpireChan = time.After(time.Duration(reorg.config.AutoExpire) * time.Second)
	}

	keepaliveTimer := time.NewTimer(0)
	defer keepaliveTimer.Stop()

	hdr := make([]byte, hdrSize)

	for {
		select {
		case rpacket := <-reorg.chKcpTX:
			// 2-bytes size
			binary.LittleEndian.PutUint16(hdr, uint16(len(rpacket.packet)))
			// 4-bytes seqid
			binary.LittleEndian.PutUint32(hdr[seqOffset:], rpacket.seq)
			// 4-bytes timestamp
			binary.LittleEndian.PutUint32(hdr[tsOffset:], rpacket.ts)

			// write data
			conn.SetWriteDeadline(time.Now().Add(timeout))
			n, err := conn.WriteBuffers([][]byte{hdr, rpacket.packet})
			// return memory
			defaultAllocator.Put(rpacket.packet)
			if err != nil {
				log.Println("kcpTX", "err", err, "n", n)
				return
			}
		case <-keepaliveTimer.C:
			binary.LittleEndian.PutUint16(hdr, uint16(0)) // a zero-sized packet to keepalive
			conn.SetWriteDeadline(time.Now().Add(timeout))
			n, err := conn.Write(hdr)
			if err != nil {
				log.Println("kcpTX", "err", err, "n", n)
				return
			}

			keepaliveTimer.Reset(timeout)
		case <-autoExpireChan:
			// (client only)
			// if autoexpired triggered, stop transmitting now
			// we won't close the kcp session but keep kcpRX working for
			// incoming packets. the remote will stop sending packets to this kcp session
			// after KeepAlive
			return
		case <-rxStopChan: // kcpRX closed
			return
		case <-reorg.die:
			return
		}
	}
}

// kcpRX is a goroutine to decapsualte incoming packets from kcp session to tun device.
func (reorg *Reorg) kcpRX(conn *kcp.UDPSession, rxStopChan chan struct{}) {
	defer close(rxStopChan)

	timeout := time.Duration(reorg.config.KeepAlive) * time.Second
	hdr := make([]byte, hdrSize)

	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := io.ReadFull(conn, hdr)
		if err != nil {
			log.Println("kcpRX", "err", err, "n", n)
			return
		}

		// adaptive latency updater
		// we have to take the packets count into consideration for latency accurency
		now := currentMs()
		latency := atomic.LoadUint32(&reorg.currentRTO)
		reorg.reportRTO(conn.GetRTO())

		// packets handler
		size := binary.LittleEndian.Uint16(hdr)
		if size > 0 { // payload
			payload := defaultAllocator.Get(int(size))
			n, err = io.ReadFull(conn, payload)
			if err != nil {
				log.Println("kcpRX", "err", err, "n", n)
				return
			}

			seq := binary.LittleEndian.Uint32(hdr[seqOffset:])
			ts := binary.LittleEndian.Uint32(hdr[tsOffset:])
			diff := _itimediff(now, ts)
			if diff < 0 {
				diff = 0
			}

			compensate := _itimediff(uint32(latency), uint32(diff))
			if compensate < 0 {
				compensate = 0
			}
			select {
			case reorg.chTunTX <- reorgPacket{payload, seq, now + uint32(compensate)}:
			case <-reorg.die:
				return
			}
		}
	}
}

// create conn initialize a new kcp session
func (reorg *Reorg) createConn(remote string, config *Config, block kcp.BlockCrypt) (*kcp.UDPSession, error) {
	kcpconn, err := dial(config.TCP, remote, config.DataShard, config.ParityShard, block)
	if err != nil {
		return nil, errors.Wrap(err, "dial()")
	}
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)

	if err := kcpconn.SetDSCP(config.DSCP); err != nil {
		log.Println("SetDSCP:", err)
	}
	if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
		log.Println("SetWriteBuffer:", err)
	}
	return kcpconn, nil
}

// wait until a connection is ready
func (reorg *Reorg) waitConn(remote string, config *Config, block kcp.BlockCrypt) *kcp.UDPSession {
	for {
		if session, err := reorg.createConn(remote, config, block); err == nil {
			return session
		} else {
			log.Println("re-connecting:", err)
			time.Sleep(time.Second)
		}
	}
}

// start as client, client will respwan itself if stopped
func (reorg *Reorg) client(remote string) {
	for {
		// establish UDP connection
		conn := reorg.waitConn(remote, reorg.config, reorg.block)
		// the control struct
		rxStopChan := make(chan struct{})
		go reorg.kcpTX(conn, rxStopChan, true)
		go reorg.kcpRX(conn, rxStopChan)

		// wait for receiving stops
		<-rxStopChan
		conn.Close()
		log.Println("restarting client to remote #:", remote)
	}
}

// start as server
func (reorg *Reorg) server() {
	config := reorg.config

	// listen on dual or udp mode
	var listener *kcp.Listener
	if config.TCP { // tcp dual stack
		conn, err := tcpraw.Listen("tcp", config.Listen)
		checkError(err)
		lis, err := kcp.ServeConn(reorg.block, config.DataShard, config.ParityShard, conn)
		checkError(err)
		listener = lis
	} else {
		// udp stack
		lis, err := kcp.ListenWithOptions(config.Listen, reorg.block, config.DataShard, config.ParityShard)
		checkError(err)
		listener = lis
	}

	// apply settings
	if err := listener.SetDSCP(config.DSCP); err != nil {
		log.Println("SetDSCP:", err)
	}
	if err := listener.SetReadBuffer(config.SockBuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := listener.SetWriteBuffer(config.SockBuf); err != nil {
		log.Println("SetWriteBuffer:", err)
	}

	for {
		conn, err := listener.AcceptKCP()
		checkError(err)
		log.Println("remote address:", conn.RemoteAddr())
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		conn.SetMtu(config.MTU)
		conn.SetWindowSize(config.SndWnd, config.RcvWnd)

		// the control struct
		rxStopChan := make(chan struct{})
		go reorg.kcpTX(conn, rxStopChan, false)
		go reorg.kcpRX(conn, rxStopChan)
		go func() {
			<-rxStopChan
			conn.Close()
		}()
	}
}
