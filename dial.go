package main

import (
	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/tcpraw"
)

func dial(tcp bool, remote string, datashard int, parityshard int, block kcp.BlockCrypt) (*kcp.UDPSession, error) {
	if tcp {
		conn, err := tcpraw.Dial("tcp", remote)
		if err != nil {
			return nil, errors.Wrap(err, "tcpraw.Dial()")
		}
		return kcp.NewConn(remote, block, datashard, parityshard, conn)
	}
	return kcp.DialWithOptions(remote, block, datashard, parityshard)
}
