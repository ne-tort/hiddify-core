package egress

import (
	"errors"

	connectip "github.com/quic-go/connect-ip-go"
)

// ptbForCeiling returns ICMP PTB when ip exceeds soft ceiling (RFC 9484 §7.2.1 contract).
// oversize=false means the packet is within limit and should proceed to the underlay.
func ptbForCeiling(ip []byte, ceiling int) (icmp []byte, oversize bool, err error) {
	if ceiling <= 0 || len(ip) <= ceiling {
		return nil, false, nil
	}
	icmp, err = connectip.ComposeICMPPacketTooBig(ip, ceiling)
	if err != nil {
		return nil, true, joinTransport(err)
	}
	return icmp, true, nil
}

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
	if icmp, over, err := ptbForCeiling(buffer, h.DatagramCeiling()); over {
		if err != nil {
			trackWriteFail(err, true)
			return nil, err
		}
		trackPTBRx()
		return icmp, nil
	}
	// Conn.WritePacketNoWake copies for QUIC retention.
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
	return writePacketDirectNoWake(h, buffer)
}

// WritePacket sends one owned IP datagram and flushes the transport batch (RFC9484 hot path).
// LoopIn relies on this wake; NoWake-only callers must FlushEgressBatch explicitly.
func WritePacket(h ClientHost, buffer []byte) ([]byte, error) {
	icmp, err := writePacketDirectNoWake(h, buffer)
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
	if icmp, over, err := ptbForCeiling(outbound, h.DatagramCeiling()); over {
		if err != nil {
			trackWriteFail(err, true)
			return false, nil, err
		}
		trackPTBRx()
		return false, icmp, nil
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
