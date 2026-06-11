package masque

import (
	"os"
	"strings"
	"sync"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/option"
)

// CONNECT-IP observability logs full JSON snapshots (CONNECT_IP_OBS) and is off on the packet
// plane by default — enable with MASQUE_CONNECT_IP_OBS=1 for VPS/debug interop.
func connectIPObsEventsEnabled() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_OBS")) == "1"
}

func trackConnectIPPacketRx(n int) {
	if n <= 0 || !connectIPObsEventsEnabled() {
		return
	}
	rxSeq := connectIPCounters.packetRxTotal.Add(1)
	connectIPCounters.bytesRxTotal.Add(uint64(n))
	if connectIPCounters.firstRxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_rx")
	}
	maybeEmitConnectIPActiveSnapshot(rxSeq)
}

func trackConnectIPPacketTx(ipLen int) {
	if ipLen <= 0 || !connectIPObsEventsEnabled() {
		return
	}
	txSeq := connectIPCounters.packetTxTotal.Add(1)
	connectIPCounters.bytesTxTotal.Add(uint64(ipLen))
	if connectIPCounters.firstTxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_tx")
	}
	maybeEmitConnectIPActiveSnapshot(txSeq)
}

func trackConnectIPReadExit(err error) {
	if err == nil || !connectIPObsEventsEnabled() {
		return
	}
	connectIPCounters.packetReadExitTotal.Add(1)
	incConnectIPReadDropReason(classifyConnectIPErrorReason(err))
	emitConnectIPObservabilityEvent("packet_read_exit")
}

func trackConnectIPWriteFail(err error, ceiling bool) {
	if err == nil || !connectIPObsEventsEnabled() {
		return
	}
	connectIPCounters.packetWriteFailTotal.Add(1)
	if ceiling {
		incConnectIPWriteFailReason("ceiling_reject")
		emitConnectIPObservabilityEvent("packet_write_fail_ceiling")
		return
	}
	incConnectIPWriteFailReason(classifyConnectIPErrorReason(err))
	emitConnectIPObservabilityEvent("packet_write_fail")
}

func trackConnectIPPTBRx() {
	if !connectIPObsEventsEnabled() {
		return
	}
	connectIPCounters.ptbRxTotal.Add(1)
	maybeEmitConnectIPPTBObs("packet_ptb_rx")
}

// connectIPUDPIngressSubCount tracks UDP bridge subscribers without locking the ingress loop.
func (s *coreSession) connectIPUDPIngressSubsEmpty() bool {
	return s.connectIPUDPIngressSubCount.Load() == 0
}

func connectIPIPv4TCPAckOnly(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	if len(pkt) > ihl+doff {
		return false
	}
	return pkt[ihl+13]&0x10 != 0
}

func (s *coreSession) connectIPTCPIngressFastPath(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	if !s.connectIPUDPIngressSubsEmpty() {
		return false
	}
	return s.ingressTCPNetstack.Load() != nil || s.connectIPTCPInstallInflight.Load() > 0
}

func connectIPIPv4TCPHasPayload(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	return len(pkt) > ihl+doff
}

// connectIPIPv4TCPIngressWakeCandidate is true for inbound TCP ACK-only (upload ACK-clock from server)
// and for segments carrying payload (download DATA → client must emit ACKs on QUIC egress).
func connectIPIPv4TCPIngressWakeCandidate(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	if len(pkt) > ihl+doff {
		return true
	}
	return pkt[ihl+13]&0x10 != 0
}

func (s *coreSession) noteConnectIPIngressAckForWake(pkt []byte) {
	if connectIPIPv4TCPIngressWakeCandidate(pkt) {
		s.connectIPIngressAckWake.Store(true)
	}
}

func (s *coreSession) flushConnectIPIngressAckWake() {
	if !s.connectIPIngressAckWake.CompareAndSwap(true, false) {
		return
	}
	if s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2 {
		return
	}
	if h3 := s.ipHTTPConn; h3 != nil {
		h3.MasqueWakeSend()
	}
}

// deliverConnectIPTCPIngress injects one proxied TCP datagram into the CONNECT-IP netstack and
// schedules QUIC send for upload ACK-clock / download DATA delivery.
func (s *coreSession) deliverConnectIPTCPIngress(pkt []byte) bool {
	deliver := func(ns *connectIPTCPNetstack) {
		ns.injectInboundClone(pkt)
		// Async drain after download DATA inject: gVisor queues egress TCP ACKs; a single
		// WriteNotify edge may not drain the link endpoint before the next ingress segment.
		if connectIPIPv4TCPHasPayload(pkt) {
			ns.scheduleOutboundDrain()
		}
		s.noteConnectIPIngressAckForWake(pkt)
		s.flushConnectIPIngressAckWake()
	}
	if ns := s.ingressTCPNetstack.Load(); ns != nil {
		deliver(ns)
		return true
	}
	if s.connectIPTCPInstallInflight.Load() > 0 {
		s.enqueuePreTCPNetstackIngress(pkt)
		return true
	}
	if ns := s.tcpNetstackForIngressInject(); ns != nil {
		deliver(ns)
		return true
	}
	return false
}

var connectIPForwarderPktPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1600)
		return &b
	},
}

func connectIPForwarderBorrow(n int) []byte {
	bp := connectIPForwarderPktPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		*bp = b[:0]
		connectIPForwarderPktPool.Put(bp)
		return make([]byte, n)
	}
	return b[:n]
}

func connectIPForwarderReturn(b []byte) {
	if cap(b) < 64 || cap(b) > 8<<10 {
		return
	}
	b = b[:0]
	connectIPForwarderPktPool.Put(&b)
}
