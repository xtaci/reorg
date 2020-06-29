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

// Reorg defines a packet organizer to maximize throughput via multiple links
type Reorg struct {
	config *Config        // the system config
	block  kcp.BlockCrypt // the initialized block cipher

	iface *water.Interface // tun device

	chFromTun chan []byte // packets received from tun device
	chToTun   chan []byte // packets to wire on tun device

	die     chan struct{} // closing signal
	dieOnce sync.Once
}

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

	reorg := new(Reorg)
	reorg.config = config
	reorg.block = block
	reorg.chFromTun = make(chan []byte)
	reorg.chToTun = make(chan []byte)

	return reorg
}

func (reorg *Reorg) Start() {
	// create tun device
	iface, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: "kcp"},
	})

	if err != nil {
		log.Fatal(err)
	}
	reorg.iface = iface

	// start tun-device reader/writer
	go reorg.tunReader()
	go reorg.tunWriter()

	if reorg.config.Client { // client creates aggregator on tun
		for k := 0; k < reorg.config.Conn; k++ {
			conn := reorg.waitConn(reorg.config, reorg.block)
			go reorg.tun2kcp(conn)
			go reorg.kcp2tun(conn)
		}
	} else { // server accepts and reorg
		go reorg.server()
	}
}

func (reorg *Reorg) Close() {
	reorg.dieOnce.Do(func() {
		close(reorg.die)
	})
}

// tunReader is a goroutine to keep on read on tun device
func (reorg *Reorg) tunReader() {
	// tun reader
	buffer := make([]byte, 1500)
	for {
		n, err := reorg.iface.Read(buffer)
		if err != nil {
			log.Fatal("tunReader", "err", err, "n", n)
		}

		packet := make([]byte, n)
		copy(packet, buffer)

		select {
		case reorg.chFromTun <- packet:
		case <-reorg.die:
			return
		}
	}
}

// tunWriter is a goroutine to keep on writing to tun device
func (reorg *Reorg) tunWriter() {
	for {
		select {
		case packet := <-reorg.chToTun:
			n, err := reorg.iface.Write(packet)
			if err != nil {
				log.Fatal("tunWriter", "err", err, "n", n)
			}
		case <-reorg.die:
			return
		}
	}
}

// a goroutine to transmit packets from tun to kcp session
func (reorg *Reorg) tun2kcp(conn *kcp.UDPSession) {
	size := make([]byte, 2)
	for {
		select {
		case packet := <-reorg.chFromTun:
			binary.LittleEndian.PutUint16(size, uint16(len(packet)))
			n, err := conn.WriteBuffers([][]byte{size, packet})
			if err != nil {
				log.Fatal("tun2kcp", "err", err, "n", n)
			}
		case <-reorg.die:
			return
		}
	}
}

// a goroutine to transmit packets to tun from kcp session
func (reorg *Reorg) kcp2tun(conn *kcp.UDPSession) {
	//expired := time.NewTimer(time.Duration(reorg.config.ScavengeTTL) * time.Second)
	size := make([]byte, 2)
	for {
		n, err := io.ReadFull(conn, size)
		if err != nil {
			log.Fatal("kcp2tun", "err", err, "n", n)
		}
		payload := make([]byte, binary.LittleEndian.Uint16(size))
		n, err = io.ReadFull(conn, payload)
		if err != nil {
			log.Fatal("kcp2tun", "err", err, "n", n)
		}

		select {
		case reorg.chToTun <- payload:
		case <-reorg.die:
			return
		}
	}
}

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

		go reorg.tun2kcp(conn)
		go reorg.kcp2tun(conn)
	}
}
