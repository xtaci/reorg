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

const TUN_MTU = 1500 // default tun-device MTU

// Reorg defines a packet organizer to maximize throughput via configurable multiple links
type Reorg struct {
	config *Config        // the system config.
	block  kcp.BlockCrypt // the initialized block cipher.

	iface       *water.Interface // tun device
	chDeviceIn  chan []byte      // packets received from tun device will be delivered to this chan.
	chDeviceOut chan []byte      // packets sent to this chan will be wired with tun-devices.

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
	reorg.chDeviceOut = make(chan []byte)
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
			return
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

// tunTX is a goroutine for tun-device to wire outgoing packets
func (reorg *Reorg) tunTX() {
	for {
		select {
		case packet := <-reorg.chDeviceOut:
			n, err := reorg.iface.Write(packet)
			if err != nil {
				log.Println("tunWriter", "err", err, "n", n)
				return
			}
		case <-reorg.die:
			return
		}
	}
}

// kcpTX is a goroutine to transmit incoming packets from tun device to kcp session.
func (reorg *Reorg) kcpTX(conn *kcp.UDPSession) {
	hdr := make([]byte, 2)
	for {
		select {
		case packet := <-reorg.chDeviceIn:
			binary.LittleEndian.PutUint16(hdr, uint16(len(packet)))
			n, err := conn.WriteBuffers([][]byte{hdr, packet})
			if err != nil {
				log.Println("kcpTX", "err", err, "n", n)
				// put back the packet before return
				reorg.chDeviceIn <- packet
				return
			}
		case <-reorg.die:
			return
		}
	}
}

// kcpRX is a goroutine to transmit incoming packets from kcp session to tun device.
func (reorg *Reorg) kcpRX(conn *kcp.UDPSession) {
	expire := time.Duration(reorg.config.AutoExpire) * time.Second
	hdr := make([]byte, 2)
	for {
		conn.SetReadDeadline(time.Now().Add(expire))
		n, err := io.ReadFull(conn, hdr)
		if err != nil {
			log.Println("kcpRX", "err", err, "n", n)
			return
		}

		conn.SetReadDeadline(time.Now().Add(expire))
		payload := make([]byte, binary.LittleEndian.Uint16(hdr))
		n, err = io.ReadFull(conn, payload)
		if err != nil {
			log.Println("kcpRX", "err", err, "n", n)
			return
		}

		select {
		case reorg.chDeviceOut <- payload:
		case <-reorg.die:
			return
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
	kcpconn.SetACKNoDelay(config.AckNodelay)

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
	// establish UDP connection
	conn := reorg.waitConn(reorg.config, reorg.block)
	go reorg.kcpTX(conn)
	go reorg.kcpRX(conn)

	ticker := time.NewTicker(time.Duration(reorg.config.AutoExpire) * time.Second)
	defer ticker.Stop()

	select {
	case <-ticker.C: // renewal of kcp session to avoid UDP blocking
		newconn := reorg.waitConn(reorg.config, reorg.block)
		go reorg.kcpTX(newconn)
		go reorg.kcpRX(newconn)
		log.Println("new connection established:", newconn.LocalAddr(), "->", newconn.RemoteAddr())
		log.Println("closing previous connection", conn.LocalAddr(), "->", conn.RemoteAddr())
		// stop current conn & set the new conn
		conn.Close()
		conn = newconn
	case <-reorg.die:
		conn.Close()
		return
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
		conn.SetACKNoDelay(config.AckNodelay)

		go reorg.kcpTX(conn)
		go reorg.kcpRX(conn)
	}
}
