// Package h3quic holds tiny HTTP/3 datagram helpers shared by client and server relay (DRY).
package h3quic

// TransientPressureMaxSpins bounds Gosched retries on QUIC/UDP syscall pressure (zero-loss gates).
// masque-go upstream blocks on SendDatagram; our quic-go fork may return EAGAIN under burst.
const TransientPressureMaxSpins = 8192

// TryDrainHTTPDatagrams is quic-go HTTP/3 non-blocking datagram dequeue (masque-go shape).
type TryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}
