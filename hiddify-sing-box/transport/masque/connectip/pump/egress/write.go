package egress

import "errors"

// FlushEgressBatch wakes QUIC send after batched WritePacketInPlaceNoWake calls.
func FlushEgressBatch(h ClientHost) {
	if h == nil {
		return
	}
	if conn := h.PacketConn(); conn != nil {
		conn.FlushOutgoingDatagramSend()
	}
	if wake := h.WakeAfterDatagram(); wake != nil {
		wake()
	}
}

func writePacketDirectNoWake(h ClientHost, buffer []byte) ([]byte, error) {
	conn := h.PacketConn()
	if conn == nil {
		return nil, joinTransport(errors.New("connect-ip conn is nil"))
	}
	if ceiling := h.DatagramCeiling(); ceiling > 0 && len(buffer) > ceiling {
		err := joinTransport(errors.New("connect-ip packet exceeds configured datagram ceiling"))
		trackWriteFail(err, true)
		return nil, err
	}
	icmp, err := conn.WritePacketNoWake(buffer)
	if err != nil {
		trackWriteFail(err, false)
		return icmp, err
	}
	trackPacketTx(len(buffer))
	if len(icmp) > 0 {
		trackPTBRx()
	}
	return icmp, err
}

// WritePacketNoWake enqueues one datagram without transport flush (usque LoopIn batch + OnLoopInEnd flush).
func WritePacketNoWake(h ClientHost, buffer []byte) ([]byte, error) {
	if ceiling := h.DatagramCeiling(); ceiling > 0 && len(buffer) > ceiling {
		err := joinTransport(errors.New("connect-ip packet exceeds configured datagram ceiling"))
		trackWriteFail(err, true)
		return nil, err
	}
	pkt := borrowOutboundBuf(len(buffer))
	copy(pkt, buffer)
	icmp, err := writePacketDirectNoWake(h, pkt)
	returnOutboundBuf(pkt)
	return icmp, err
}

// WritePacket sends one owned IP datagram and flushes the transport batch (RFC9484 hot path).
// LoopIn relies on this wake; NoWake-only callers must FlushEgressBatch explicitly.
func WritePacket(h ClientHost, buffer []byte) ([]byte, error) {
	if ceiling := h.DatagramCeiling(); ceiling > 0 && len(buffer) > ceiling {
		err := joinTransport(errors.New("connect-ip packet exceeds configured datagram ceiling"))
		trackWriteFail(err, true)
		return nil, err
	}
	pkt := borrowOutboundBuf(len(buffer))
	copy(pkt, buffer)
	icmp, err := writePacketDirectNoWake(h, pkt)
	returnOutboundBuf(pkt)
	if err != nil {
		return icmp, err
	}
	FlushEgressBatch(h)
	return icmp, nil
}

// WritePacketFromNetstack sends a netstack pool buffer in-place (NoWake); caller flushes the batch.
func WritePacketFromNetstack(h ClientHost, outbound []byte) (retained bool, icmp []byte, err error) {
	conn := h.PacketConn()
	if conn == nil {
		return false, nil, joinTransport(errors.New("connect-ip conn is nil"))
	}
	if ceiling := h.DatagramCeiling(); ceiling > 0 && len(outbound) > ceiling {
		err := joinTransport(errors.New("connect-ip packet exceeds configured datagram ceiling"))
		trackWriteFail(err, true)
		return false, nil, err
	}
	icmp, retained, err = conn.WritePacketInPlaceNoWake(outbound)
	if err != nil {
		trackWriteFail(err, false)
		return false, icmp, err
	}
	trackPacketTx(len(outbound))
	if len(icmp) > 0 {
		trackPTBRx()
	}
	return retained, icmp, nil
}

// WritePacketPrefixed sends a datagram buffer that already includes the RFC9297 context ID prefix.
func WritePacketPrefixed(h ClientHost, buffer []byte, prefixLen int) ([]byte, error) {
	conn := h.PacketConn()
	if conn == nil {
		return nil, joinTransport(errors.New("connect-ip conn is nil"))
	}
	if prefixLen <= 0 || len(buffer) <= prefixLen {
		return nil, joinTransport(errors.New("connect-ip prefixed datagram too short"))
	}
	ipLen := len(buffer) - prefixLen
	if ceiling := h.DatagramCeiling(); ceiling > 0 && ipLen > ceiling {
		err := joinTransport(errors.New("connect-ip packet exceeds configured datagram ceiling"))
		trackWriteFail(err, true)
		return nil, err
	}
	icmp, err := conn.WritePacketPrefixed(buffer)
	return accountWrite(h, ipLen, icmp, err)
}

func accountWrite(h ClientHost, ipLen int, icmp []byte, err error) ([]byte, error) {
	if err != nil {
		trackWriteFail(err, false)
		return icmp, err
	}
	trackPacketTx(ipLen)
	if len(icmp) > 0 {
		trackPTBRx()
	}
	if wake := h.WakeAfterDatagram(); wake != nil {
		wake()
	}
	return icmp, err
}
