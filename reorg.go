package main

import (
	"crypto/sha1"
	"encoding/binary"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/songgao/water"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/tcpraw"
	"golang.org/x/crypto/pbkdf2"
)

const (
	TUN_MTU      = 1500 // default tun-device MTU
	PACKET_QUEUE = 1024 // packet IO queue of device
)

// Packet definition
type Packet []byte

// Reorg defines a packet organizer to maximize throughput via configurable multiple links
type Reorg struct {
	config *Config        // the system config.
	block  kcp.BlockCrypt // the initialized block cipher.

	iface      *water.Interface // tun device
	chBalancer chan Packet      // packets received from tun device will be delivered to balancer
	chKcpTX    chan Packet      // packets received from balancer will be delivered to this chan.
	chTunTX    chan Packet      // packets from kcp session will be sent here awaiting to deliver to device

	die     chan struct{} // closing signal.
	dieOnce sync.Once
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

	// create the object
	reorg := new(Reorg)
	reorg.config = config
	reorg.block = block
	reorg.chBalancer = make(chan Packet, PACKET_QUEUE)
	reorg.chKcpTX = make(chan Packet, PACKET_QUEUE)
	reorg.chTunTX = make(chan Packet, PACKET_QUEUE)
	reorg.die = make(chan struct{})
	reorg.iface = iface

	return reorg
}

// Serve starts serving tunnel service
func (reorg *Reorg) Serve() {
	// spin-up tun-device reader/writer
	go reorg.balancer()
	go reorg.tunRX()
	go reorg.tunTX()

	if reorg.config.Client {
		// client creates aggregator on tun
		// the client connections will re-new itself periodically
		for i := 0; i < reorg.config.Conn; i++ {
			go reorg.client()
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

// tunTX transmits packets from the tun-device queue
func (reorg *Reorg) tunTX() {
	var seq uint32
	buffer := make([]byte, TUN_MTU)
	for {
		n, err := reorg.iface.Read(buffer)
		if err != nil {
			log.Println("tunReader", "err", err, "n", n)
		}

		// copy to an appopriate buffer
		packet := defaultAllocator.Get(n)
		copy(packet, buffer)

		// deliver to the balancer, balancer will cache all packets
		select {
		case reorg.chBalancer <- packet:
			seq++
		case <-reorg.die:
			return
		}
	}
}

// tunRX receives packets from kcp links
func (reorg *Reorg) tunRX() {
	for {
		select {
		case packet := <-reorg.chTunTX:
			n, err := reorg.iface.Write(packet)
			defaultAllocator.Put(packet) // put back after write
			if err != nil {
				log.Println("tunTX", "err", err, "n", n)
			}
		case <-reorg.die:
			return
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// balancer is a groutine to balance packets from tun to different kcp link
func (reorg *Reorg) balancer() {
	var pendingPackets []Packet
	var chKcpTX chan Packet
	var nextPacket Packet

	for {
		select {
		case p := <-reorg.chBalancer: // always cache the packets
			pendingPackets = append(pendingPackets, p)
			chKcpTX = reorg.chKcpTX
			nextPacket = pendingPackets[0]
		case chKcpTX <- nextPacket: // distribute to any receiver
			pendingPackets = pendingPackets[1:]
			if len(pendingPackets) == 0 {
				chKcpTX = nil // stop sending
			} else {
				nextPacket = pendingPackets[0]
			}
		case <-reorg.die:
			return
		}
	}
}

// kcpTX is a goroutine to carry packets from tun device to kcp session.
func (reorg *Reorg) kcpTX(conn *kcp.UDPSession, stopFunc func(), stopChan <-chan struct{}) {
	defer stopFunc()

	// the keepalive timer
	timeout := time.Duration(reorg.config.KeepAlive) * time.Second / 2
	keepaliveTimer := time.NewTimer(0)
	defer keepaliveTimer.Stop()

	// record the last packet tx time
	var lastPacketTime time.Time

	// 2-byte size to describe the packet size in a stream
	hdr := make([]byte, 2)
	for {
		select {
		case packet := <-reorg.chKcpTX:
			// 2-bytes size
			binary.LittleEndian.PutUint16(hdr, uint16(len(packet)))
			// write data
			conn.SetWriteDeadline(time.Now().Add(timeout))
			n, err := conn.WriteBuffers([][]byte{hdr, packet})
			// return memory
			defaultAllocator.Put(packet)
			if err != nil {
				log.Println("kcpTX", "err", err, "n", n)
				return
			}
			lastPacketTime = time.Now()
		case <-keepaliveTimer.C:
			if time.Now().Sub(lastPacketTime) > timeout { // only when no packet has send within 'timeout' interval
				binary.LittleEndian.PutUint16(hdr, uint16(0)) // a zero-sized packet to keepalive
				conn.SetWriteDeadline(time.Now().Add(timeout))
				n, err := conn.Write(hdr)
				if err != nil {
					log.Println("kcpTX", "err", err, "n", n)
					return
				}
			}

			// reset timer
			keepaliveTimer.Reset(timeout)
		case <-stopChan:
			return
		case <-reorg.die:
			return
		}
	}
}

// kcpRX is a goroutine to decapsualte incoming packets from kcp session to tun device.
func (reorg *Reorg) kcpRX(conn *kcp.UDPSession, stopFunc func()) {
	defer stopFunc()

	keepalive := time.Duration(reorg.config.KeepAlive) * time.Second
	hdr := make([]byte, 2)
	for {
		conn.SetReadDeadline(time.Now().Add(keepalive))
		n, err := io.ReadFull(conn, hdr)
		if err != nil {
			log.Println("kcpRX", "err", err, "n", n)
			return
		}

		size := binary.LittleEndian.Uint16(hdr)
		if size > 0 { // non-keepalive
			payload := defaultAllocator.Get(int(size))
			n, err = io.ReadFull(conn, payload)
			if err != nil {
				log.Println("kcpRX", "err", err, "n", n)
				return
			}

			select {
			case reorg.chTunTX <- payload:
			case <-reorg.die:
				return
			}
		}
	}
}

// create conn initialize a new kcp session
func (reorg *Reorg) createConn(config *Config, block kcp.BlockCrypt) (*kcp.UDPSession, error) {
	kcpconn, err := dial(config, block)
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
func (reorg *Reorg) waitConn(config *Config, block kcp.BlockCrypt) *kcp.UDPSession {
	for {
		if session, err := reorg.createConn(config, block); err == nil {
			return session
		} else {
			log.Println("re-connecting:", err)
			time.Sleep(time.Second)
		}
	}
}

// start as client
func (reorg *Reorg) client() {
	for {
		// establish UDP connection
		conn := reorg.waitConn(reorg.config, reorg.block)
		// the control struct
		var stopOnce sync.Once
		stopChan := make(chan struct{})
		stopFunc := func() {
			stopOnce.Do(func() {
				conn.Close()
				close(stopChan)
			})
		}
		go reorg.kcpTX(conn, stopFunc, stopChan)
		go reorg.kcpRX(conn, stopFunc)

		// wait for connection termination
		<-stopChan
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
		var stopOnce sync.Once
		stopFunc := func() {
			stopOnce.Do(func() {
				conn.Close()
			})
		}

		go reorg.kcpTX(conn, stopFunc, nil)
		go reorg.kcpRX(conn, stopFunc)
	}
}
