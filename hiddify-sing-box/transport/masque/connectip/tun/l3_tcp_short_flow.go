package tun

import (
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// ShortFlowHook runs after tun L3 overlay forwards a TCP FIN/RST (nc probe or bulk teardown).
type ShortFlowHook func(dst netip.AddrPort, egressBytes uint64)

// L3BulkFlowEgressThreshold separates probe-sized flows from bulk TCP legs (iperf upload).
const L3BulkFlowEgressThreshold = 64 * 1024

const shortFlowHookMinInterval = 300 * time.Millisecond

// IPv4TCPFinOrRst reports whether pkt is IPv4 TCP with FIN or RST set.
func IPv4TCPFinOrRst(pkt []byte) (ok bool, dst netip.AddrPort) {
	if len(pkt) < header.IPv4MinimumSize+header.TCPMinimumSize {
		return false, netip.AddrPort{}
	}
	if pkt[0]>>4 != 4 {
		return false, netip.AddrPort{}
	}
	ihl := int((pkt[0] & 0x0f) * 4)
	if ihl < header.IPv4MinimumSize || len(pkt) < ihl+header.TCPMinimumSize {
		return false, netip.AddrPort{}
	}
	tcp := header.TCP(pkt[ihl:])
	flags := tcp.Flags()
	if flags&header.TCPFlagFin == 0 && flags&header.TCPFlagRst == 0 {
		return false, netip.AddrPort{}
	}
	dstAddr, ok := ipv4Destination(pkt)
	if !ok {
		return false, netip.AddrPort{}
	}
	return true, netip.AddrPortFrom(dstAddr, tcp.DestinationPort())
}

func (b *L3OverlayBridge) noteShortFlow(pkt []byte) {
	if b == nil || b.shortFlowHook == nil {
		return
	}
	ok, dst := IPv4TCPFinOrRst(pkt)
	if !ok {
		return
	}
	b.shortHookMu.Lock()
	defer b.shortHookMu.Unlock()
	if !b.shortHookLast.IsZero() && time.Since(b.shortHookLast) < shortFlowHookMinInterval {
		return
	}
	b.shortHookLast = time.Now()
	hook := b.shortFlowHook
	egressBytes := b.flowEgressBytes.Swap(0)
	go hook(dst, egressBytes)
}

func (b *L3OverlayBridge) accountFlowEgress(pkt []byte) {
	if b == nil || len(pkt) == 0 {
		return
	}
	if ok, _ := IPv4TCPFinOrRst(pkt); ok {
		return
	}
	b.flowEgressBytes.Add(uint64(len(pkt)))
}
