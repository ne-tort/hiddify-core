package quic

import (
	"sync"

	"github.com/quic-go/quic-go/internal/wire"
)

// http3DatagramBufferPool backs RFC 9297 HTTP/3 DATAGRAM capsules assembled as
// (quarter-stream-id varint + payload). (*Conn).EnqueuePooledHTTPDatagram transfers
// ownership until OutgoingPayloadRelease runs.
var http3DatagramBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1500)
		return &b
	},
}

// AcquireHTTP3DatagramBuffer returns *[]byte sized for capsule assembly in http3.sendDatagram.
// On enqueue failure callers must ReleaseHTTP3DatagramBuffer before discarding bp.
func AcquireHTTP3DatagramBuffer() *[]byte {
	return http3DatagramBufferPool.Get().(*[]byte)
}

// ReleaseHTTP3DatagramBuffer returns bp to the pool when an HTTP/3 datagram never reached Enqueue.
func ReleaseHTTP3DatagramBuffer(bp *[]byte) {
	if bp == nil {
		return
	}
	if cap(*bp) > 16*1024 {
		return
	}
	*bp = (*bp)[:0]
	http3DatagramBufferPool.Put(bp)
}

func releaseOutgoingDatagramPayload(f *wire.DatagramFrame) {
	if f == nil {
		return
	}
	cb := f.OutgoingPayloadRelease
	f.OutgoingPayloadRelease = nil
	if cb != nil {
		cb()
	}
}

func attachPooledOutgoingPayload(f *wire.DatagramFrame, bufPtr *[]byte) {
	capTooLarge := cap(f.Data) > 16*1024
	if capTooLarge {
		return
	}
	captured := bufPtr
	f.OutgoingPayloadRelease = func() {
		*captured = (*captured)[:0]
		http3DatagramBufferPool.Put(captured)
	}
}
