package netutil

import "net"

// TCPInfoSnapshot is a portable view of Linux TCP_INFO (zeros on unsupported OS).
// Used to catch underlay loss/retrans that iperf inside the tunnel cannot see.
type TCPInfoSnapshot struct {
	OK            bool   `json:"ok"`
	Congestion    string `json:"congestion,omitempty"` // TCP_CONGESTION name (bbr/cubic/hybla/…)
	State         uint8  `json:"state,omitempty"`     // Linux tcpi_state (1=ESTABLISHED)
	RTTUs         uint32 `json:"rtt_us"`
	RTTVarUs      uint32 `json:"rttvar_us"`
	SndCwnd       uint32 `json:"snd_cwnd"`       // packets
	SndWnd        uint32 `json:"snd_wnd"`        // peer advertised window (bytes)
	RcvSpace      uint32 `json:"rcv_space"`      // local receive space (bytes)
	RcvSsthresh   uint32 `json:"rcv_ssthresh"`   // ~32KiB ⇒ SO_RCVBUF lock class (~8 Mbit @30ms)
	Unacked       uint32 `json:"unacked"`        // packets
	Sacked        uint32 `json:"sacked"`
	Lost          uint32 `json:"lost"`           // packets marked lost
	Retrans       uint32 `json:"retrans"`        // packets currently retransmitting
	TotalRetrans  uint32 `json:"total_retrans"`  // lifetime retransmit segments
	BytesReceived uint64 `json:"bytes_received"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesRetrans  uint64 `json:"bytes_retrans"`
	BytesAcked    uint64 `json:"bytes_acked"`
	DeliveryRate  uint64 `json:"delivery_rate"` // bytes/sec
	RwndLimited   uint64 `json:"rwnd_limited"`  // usec sender stalled on peer RWND
	SndbufLimited uint64 `json:"sndbuf_limited"`
}

// ReadTCPInfo fills a snapshot from c when it exposes syscall.Conn (TCP underlay).
func ReadTCPInfo(c net.Conn) TCPInfoSnapshot {
	return readTCPInfo(c)
}
