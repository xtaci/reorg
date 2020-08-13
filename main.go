package main

import (
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/urfave/cli"
)

const (
	// SALT is use for pbkdf2 key expansion
	SALT = "reorg"
)

// VERSION is injected by buildflags
var VERSION = "SELFBUILD"

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	myApp := cli.NewApp()
	myApp.Name = "Reorg"
	myApp.Usage = "Packet reorganizer"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "client",
			Usage: "run as client, otherwise run as server",
		},
		cli.StringSliceFlag{
			Name:  "remoteaddr, r",
			Usage: "reorg server address, you can specifiy this parameter many times",
		},
		cli.StringFlag{
			Name:  "listen,l",
			Value: ":29900",
			Usage: "reorg server listen address",
		},
		cli.StringFlag{
			Name:  "tun",
			Value: "reorg",
			Usage: "name of the tun device",
		},
		cli.IntFlag{
			Name:  "latency",
			Value: 300,
			Usage: "latency to reorganization packets in sender's sequence in(ms)",
		},
		cli.IntFlag{
			Name:  "autoexpire",
			Value: 600,
			Usage: "(client only) set auto expiration time(in seconds) for a single UDP connection, 0 to disable",
		},
		cli.StringFlag{
			Name:  "key",
			Value: "reorger",
			Usage: "pre-shared secret between client and server",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: 1400,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 128,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 512,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "datashard,ds",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 3,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set DSCP(6bit)",
		},
		cli.BoolFlag{
			Name:  "nocomp",
			Usage: "disable compression",
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  50,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:  "sockbuf",
			Value: 4194304, // socket buffer size in bytes
			Usage: "per-socket buffer in bytes",
		},
		cli.IntFlag{
			Name:  "keepalive",
			Value: 10, // nat keepalive interval in seconds
			Usage: "seconds between heartbeats",
		},
		cli.StringFlag{
			Name:  "snmplog",
			Value: "",
			Usage: "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log",
		},
		cli.IntFlag{
			Name:  "snmpperiod",
			Value: 60,
			Usage: "snmp collect period, in seconds",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "specify a log file to output, default goes to stderr",
		},
		cli.BoolFlag{
			Name:  "quiet",
			Usage: "to suppress the 'stream open/close' messages",
		},
		cli.BoolFlag{
			Name:  "tcp",
			Usage: "to emulate a TCP connection(linux)",
		},
		cli.StringFlag{
			Name:  "c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.Listen = c.String("listen")
		config.RemoteAddr = c.StringSlice("remoteaddr")
		config.Client = c.Bool("client")
		config.Latency = c.Int("latency")
		config.AutoExpire = c.Int("autoexpire")
		config.Tun = c.String("tun")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.MTU = c.Int("mtu")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.KeepAlive = c.Int("keepalive")
		config.Log = c.String("log")
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.Quiet = c.Bool("quiet")

		if c.String("c") != "" {
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
		}

		// log redirect
		if config.Log != "" {
			f, err := os.OpenFile(config.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			checkError(err)
			defer f.Close()
			log.SetOutput(f)
		}

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}

		if config.Client {
			log.Printf("run as client with %v server", len(config.RemoteAddr))
			if len(config.RemoteAddr) == 0 {
				log.Fatal("0 server address specified")
			}
			for k := range config.RemoteAddr {
				log.Printf("server %v:%v", k, config.RemoteAddr[k])
			}
		} else {
			log.Println("server")
			log.Println("listening on:", config.Listen)
		}

		if config.KeepAlive == 0 {
			log.Fatal("keepalive must be postive")
		}

		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("tun:", config.Tun)
		log.Println("KCP mtu:", config.MTU)
		log.Println("latency:", config.Latency)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("autoexpire:", config.AutoExpire)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("quiet:", config.Quiet)

		// start snmp logger
		go SnmpLogger(config.SnmpLog, config.SnmpPeriod)

		// start reorg
		reorg := NewReorg(&config)
		reorg.Serve()
		return nil
	}
	myApp.Run(os.Args)
}
