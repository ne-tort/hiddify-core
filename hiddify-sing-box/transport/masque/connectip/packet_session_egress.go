package connectip

import "errors"

// FlushEgressBatch wakes QUIC/H2 send after batched WritePacketInPlaceNoWake calls.
func (s *ClientPacketSession) FlushEgressBatch() {
	if s.wakeAfterDatagram != nil {
		s.wakeAfterDatagram()
		return
	}
	if s.conn != nil {
		s.conn.FlushOutgoingDatagramSend()
	}
}

// ScheduleEgressFlush is a legacy alias for FlushEgressBatch (netstack OnEgressBatchComplete wiring).
func (s *ClientPacketSession) ScheduleEgressFlush() {
	s.FlushEgressBatch()
}

func (s *ClientPacketSession) writePacketDirectNoWake(buffer []byte) ([]byte, error) {
	if s.datagramCeiling > 0 && len(buffer) > s.datagramCeiling {
		TrackWriteFail(Errs.Transport, true)
		return nil, errors.Join(Errs.Transport, errors.New("connect-ip packet exceeds configured datagram ceiling"))
	}
	icmp, err := s.conn.WritePacketNoWake(buffer)
	if err != nil {
		TrackWriteFail(err, false)
		return icmp, err
	}
	TrackPacketTx(len(buffer))
	if len(icmp) > 0 {
		TrackPTBRx()
	}
	return icmp, err
}
