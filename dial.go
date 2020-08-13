package main

import (
	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/tcpraw"
)

func dial(remote string, config *Config, block kcp.BlockCrypt) (*kcp.UDPSession, error) {
	if config.TCP {
		conn, err := tcpraw.Dial("tcp", remote)
		if err != nil {
			return nil, errors.Wrap(err, "tcpraw.Dial()")
		}
		return kcp.NewConn(remote, block, config.DataShard, config.ParityShard, conn)
	}
	return kcp.DialWithOptions(remote, block, config.DataShard, config.ParityShard)
}
