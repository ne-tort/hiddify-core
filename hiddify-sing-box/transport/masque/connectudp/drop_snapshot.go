package connectudp

import (
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	qmasque "github.com/quic-go/masque-go"
)

// DataplaneDropSnapshot captures process-wide drop counters relevant to CONNECT-UDP burst.
type DataplaneDropSnapshot struct {
	TransientUDPSend          uint64
	TransientUDPSendTail      uint64
	TransientUDPRead          uint64
	TransientHTTPDatagramSend uint64
	TransientHTTPDatagramRcv  uint64
	OversizedHTTPDatagramSend uint64
	UnknownContextHTTP        uint64
	MalformedHTTPDatagram     uint64
	StreamDatagramQueue       uint64
	QuicDatagramRcvQueue      uint64
	DatagramPackerOversize    uint64
	UnknownStreamDatagram     uint64
}

// SnapshotDataplaneDrops samples current drop totals (delta before/after a probe leg).
func SnapshotDataplaneDrops() DataplaneDropSnapshot {
	return DataplaneDropSnapshot{
		TransientUDPSend:          qmasque.TransientUDPSendDropTotal(),
		TransientUDPSendTail:      qmasque.TransientUDPSendTailDropTotal(),
		TransientUDPRead:          qmasque.TransientUDPReadDropTotal(),
		TransientHTTPDatagramSend: qmasque.TransientHTTPDatagramSendDropTotal(),
		TransientHTTPDatagramRcv:  qmasque.TransientHTTPDatagramReceiveDropTotal(),
		OversizedHTTPDatagramSend: qmasque.OversizedHTTPDatagramSendDropTotal(),
		UnknownContextHTTP:        qmasque.UnknownContextHTTPDatagramDropTotal(),
		MalformedHTTPDatagram:     qmasque.MalformedHTTPDatagramDropTotal(),
		StreamDatagramQueue:       http3.StreamDatagramQueueDropTotal(),
		QuicDatagramRcvQueue:      quic.DatagramReceiveQueueDropTotal(),
		DatagramPackerOversize:    quic.DatagramPackerOversizeDropTotal(),
		UnknownStreamDatagram:     http3.UnknownStreamDatagramDropTotal(),
	}
}

// Delta returns after-before drop counts.
func (after DataplaneDropSnapshot) Delta(before DataplaneDropSnapshot) DataplaneDropSnapshot {
	return DataplaneDropSnapshot{
		TransientUDPSend:          after.TransientUDPSend - before.TransientUDPSend,
		TransientUDPSendTail:      after.TransientUDPSendTail - before.TransientUDPSendTail,
		TransientUDPRead:          after.TransientUDPRead - before.TransientUDPRead,
		TransientHTTPDatagramSend: after.TransientHTTPDatagramSend - before.TransientHTTPDatagramSend,
		TransientHTTPDatagramRcv:  after.TransientHTTPDatagramRcv - before.TransientHTTPDatagramRcv,
		OversizedHTTPDatagramSend: after.OversizedHTTPDatagramSend - before.OversizedHTTPDatagramSend,
		UnknownContextHTTP:        after.UnknownContextHTTP - before.UnknownContextHTTP,
		MalformedHTTPDatagram:     after.MalformedHTTPDatagram - before.MalformedHTTPDatagram,
		StreamDatagramQueue:       after.StreamDatagramQueue - before.StreamDatagramQueue,
		QuicDatagramRcvQueue:      after.QuicDatagramRcvQueue - before.QuicDatagramRcvQueue,
		DatagramPackerOversize:    after.DatagramPackerOversize - before.DatagramPackerOversize,
		UnknownStreamDatagram:     after.UnknownStreamDatagram - before.UnknownStreamDatagram,
	}
}

// HasDrops reports whether any dataplane drop counter increased during a probe.
func (d DataplaneDropSnapshot) HasDrops() bool {
	return d.TransientUDPSend > 0 ||
		d.TransientUDPSendTail > 0 ||
		d.TransientUDPRead > 0 ||
		d.TransientHTTPDatagramSend > 0 ||
		d.TransientHTTPDatagramRcv > 0 ||
		d.OversizedHTTPDatagramSend > 0 ||
		d.UnknownContextHTTP > 0 ||
		d.MalformedHTTPDatagram > 0 ||
		d.StreamDatagramQueue > 0 ||
		d.QuicDatagramRcvQueue > 0 ||
		d.DatagramPackerOversize > 0 ||
		d.UnknownStreamDatagram > 0
}
