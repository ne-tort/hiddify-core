//go:build unix

package netutil

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func readTCPInfo(c net.Conn) TCPInfoSnapshot {
	if c == nil {
		return TCPInfoSnapshot{}
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		if u, ok := c.(interface{ NetConn() net.Conn }); ok {
			return readTCPInfo(u.NetConn())
		}
		return TCPInfoSnapshot{}
	}
	raw, err := sc.SyscallConn()
	if err != nil || raw == nil {
		return TCPInfoSnapshot{}
	}
	var (
		info  *unix.TCPInfo
		cc    string
		opErr error
	)
	err = raw.Control(func(fd uintptr) {
		info, opErr = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
		if name, e := unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION); e == nil {
			cc = name
		}
	})
	if err != nil || opErr != nil || info == nil {
		return TCPInfoSnapshot{}
	}
	return TCPInfoSnapshot{
		OK:            true,
		Congestion:    cc,
		State:         info.State,
		RTTUs:         info.Rtt,
		RTTVarUs:      info.Rttvar,
		SndCwnd:       info.Snd_cwnd,
		SndWnd:        info.Snd_wnd,
		RcvSpace:      info.Rcv_space,
		RcvSsthresh:   info.Rcv_ssthresh,
		Unacked:       info.Unacked,
		Sacked:        info.Sacked,
		Lost:          info.Lost,
		Retrans:       info.Retrans,
		TotalRetrans:  info.Total_retrans,
		BytesReceived: info.Bytes_received,
		BytesSent:     info.Bytes_sent,
		BytesRetrans:  info.Bytes_retrans,
		BytesAcked:    info.Bytes_acked,
		DeliveryRate:  info.Delivery_rate,
		RwndLimited:   info.Rwnd_limited,
		SndbufLimited: info.Sndbuf_limited,
	}
}
