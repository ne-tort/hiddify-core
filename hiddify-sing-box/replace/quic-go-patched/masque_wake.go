package quic

// MasqueWakeStreamSend nudges the QUIC send stream scheduler after download-side reads on a
// bidirectional HTTP/3 CONNECT stream. Used when upload (request body) and download (response)
// share one stream and the peer stack does not schedule send work promptly (sing-box server ~15 Mbit/s).
func MasqueWakeStreamSend(s *Stream) {
	if s == nil || s.sendStr == nil {
		return
	}
	s.sendStr.signalWrite()
}

// MasqueWakeConnSend schedules QUIC send work after CONNECT-IP ingress reads (TCP ACK datagrams).
// Upload and download share one QUIC connection's DATAGRAM queue; without a wake, upload segments
// can wait a full RTT behind inbound ACK processing.
func MasqueWakeConnSend(c *Conn) {
	if c == nil {
		return
	}
	c.scheduleSending()
}
