package main

import (
	"container/heap"
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
	TUN_MTU         = 1500 // default tun-device MTU
	TUN_DEVICEQUEUE = 1024 // packet IO queue of device
)

// Reorg defines a packet organizer to maximize throughput via configurable multiple links
type Reorg struct {
	config *Config        // the system config.
	block  kcp.BlockCrypt // the initialized block cipher.

	iface       *water.Interface   // tun device
	chDeviceIn  chan []byte        // packets received from tun device will be delivered to this chan.
	chDeviceOut chan delayedPacket // packets from kcp session will be sent here awaiting to deliver to device

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
		PlatformSpecificParams: water.PlatformSpecificParams{Name: "kcp"},
	})

	if err != nil {
		log.Fatal(err)
	}

	// create the object
	reorg := new(Reorg)
	reorg.config = config
	reorg.block = block
	reorg.chDeviceIn = make(chan []byte)
	reorg.chDeviceOut = make(chan delayedPacket, TUN_DEVICEQUEUE)
	reorg.die = make(chan struct{})
	reorg.iface = iface

	return reorg
}

// Serve starts serving tunnel service
func (reorg *Reorg) Serve() {
	// spin-up tun-device reader/writer
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

// tunRX is a goroutine for tun-device to receive incoming packets
func (reorg *Reorg) tunRX() {
	buffer := make([]byte, TUN_MTU)
	for {
		n, err := reorg.iface.Read(buffer)
		if err != nil {
			log.Println("tunReader", "err", err, "n", n)
		}

		// make a copy and deliver
		packet := make([]byte, n)
		copy(packet, buffer)

		select {
		case reorg.chDeviceIn <- packet:
		case <-reorg.die:
			return
		}
	}
}

// tunTX is a goroutine to delay the sending of incoming packet to a fixed interval,
// this works as a low-phase filter for latency to mitigate system noise, such as:
// scheduler's delay
func (reorg *Reorg) tunTX() {
	var packetHeap delayedPacketHeap
	timer := time.NewTimer(0)
	drained := false

	for {
		select {
		case dp := <-reorg.chDeviceOut:
			now := time.Now()
			if now.After(dp.ts) {
				// already delayed! deliver immediately
				// this might be caused by a scheduling delay
				n, err := reorg.iface.Write(heap.Pop(&packetHeap).(delayedPacket).packet)
				if err != nil {
					log.Println("tunTX", "err", err, "n", n)
				}
			} else {
				heap.Push(&packetHeap, dp)
				// properly reset timer to trigger based on the top element
				stopped := timer.Stop()
				if !stopped && !drained {
					<-timer.C
				}
				timer.Reset(packetHeap[0].ts.Sub(now))
				drained = false
			}
		case now := <-timer.C:
			drained = true
			for packetHeap.Len() > 0 {
				if now.After(packetHeap[0].ts) {
					n, err := reorg.iface.Write(heap.Pop(&packetHeap).(delayedPacket).packet)
					if err != nil {
						log.Println("tunTX", "err", err, "n", n)
					}
				} else {
					timer.Reset(packetHeap[0].ts.Sub(now))
					drained = false
					break
				}
			}
		case <-reorg.die:
			return
		}
	}
}

/*
func (reorg *Reorg) tunTX() {
	ticker := time.NewTicker(time.Duration(reorg.config.Latency) * time.Millisecond)
	defer ticker.Stop()
	var batch [][]byte
	for {
		select {
		case dp := <-reorg.chDeviceOut:
			batch = append(batch, dp.packet)
		case <-ticker.C:
			for k := range batch {
				n, err := reorg.iface.Write(batch[k])
				if err != nil {
					log.Println("tunTX", "err", err, "n", n)
				}
			}
			batch = batch[:0]
		case <-reorg.die:
			return
		}
	}
}
*/

// kcpTX is a goroutine to carry packets from tun device to kcp session.
func (reorg *Reorg) kcpTX(conn *kcp.UDPSession, stopFunc func()) {
	defer stopFunc()

	keepalive := time.Duration(reorg.config.KeepAlive) * time.Second
	keepaliveTimer := time.NewTimer(0)
	defer keepaliveTimer.Stop()

	hdr := make([]byte, 6)

	for {
		select {
		case packet := <-reorg.chDeviceIn:
			// 2-bytes size
			binary.LittleEndian.PutUint16(hdr, uint16(len(packet)))
			// 4-bytes timestamp in secs
			binary.LittleEndian.PutUint32(hdr[2:], uint32(currentMs()))
			conn.SetWriteDeadline(time.Now().Add(keepalive))
			n, err := conn.WriteBuffers([][]byte{hdr, packet})
			if err != nil {
				log.Println("kcpTX", "err", err, "n", n)
				return
			}
		case <-keepaliveTimer.C:
			binary.LittleEndian.PutUint16(hdr, uint16(0)) // a zero-sized packet to keepalive
			binary.LittleEndian.PutUint32(hdr[2:], uint32(currentMs()))
			conn.SetWriteDeadline(time.Now().Add(keepalive))
			n, err := conn.Write(hdr)
			if err != nil {
				log.Println("kcpTX", "err", err, "n", n)
				return
			}

			keepaliveTimer.Reset(time.Duration(reorg.config.KeepAlive/2) * time.Second)
		case <-reorg.die:
			return
		}
	}
}

// kcpRX is a goroutine to decapsualte incoming packets from kcp session to tun device.
func (reorg *Reorg) kcpRX(conn *kcp.UDPSession, stopFunc func()) {
	defer stopFunc()

	keepalive := time.Duration(reorg.config.KeepAlive) * time.Second
	hdr := make([]byte, 6)
	for {
		conn.SetReadDeadline(time.Now().Add(keepalive))
		n, err := io.ReadFull(conn, hdr)
		if err != nil {
			log.Println("kcpRX", "err", err, "n", n)
			return
		}

		size := binary.LittleEndian.Uint16(hdr)
		if size > 0 { // non-keepalive
			payload := make([]byte, size)
			n, err = io.ReadFull(conn, payload)
			if err != nil {
				log.Println("kcpRX", "err", err, "n", n)
				return
			}

			// a longer end-to-end pipe to smooth transfer & avoid packet loss to tcp
			timestamp := binary.LittleEndian.Uint32(hdr[2:])
			compensation := reorg.config.Latency - int(_itimediff(currentMs(), timestamp))

			log.Println("compensation:", compensation)
			select {
			case reorg.chDeviceOut <- delayedPacket{payload, time.Now().Add(time.Duration(compensation) * time.Millisecond)}:
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
		stopped := make(chan struct{})
		stopFunc := func() {
			stopOnce.Do(func() {
				conn.Close()
				close(stopped)
			})
		}
		go reorg.kcpTX(conn, stopFunc)
		go reorg.kcpRX(conn, stopFunc)

		// wait for connection termination
		<-stopped
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

		go reorg.kcpTX(conn, stopFunc)
		go reorg.kcpRX(conn, stopFunc)
	}
}
