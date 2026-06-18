package connectip

const (
	clientPacketEgressQueueDepth = 8192
	clientPacketEgressBatchMax   = 64
)

func (s *ClientPacketSession) ensureEgressWriter() {
	s.egressOnce.Do(func() {
		s.egressCh = make(chan []byte, clientPacketEgressQueueDepth)
		s.egressStop = make(chan struct{})
		s.egressWG.Add(1)
		go s.runEgressWriter()
	})
}

func (s *ClientPacketSession) tryEnqueueEgress(buffer []byte) bool {
	s.ensureEgressWriter()
	if s.egressClosed.Load() {
		return false
	}
	pkt := make([]byte, len(buffer))
	copy(pkt, buffer)
	select {
	case <-s.egressStop:
		return false
	case s.egressCh <- pkt:
		return true
	default:
		return false
	}
}

func (s *ClientPacketSession) runEgressWriter() {
	defer s.egressWG.Done()
	for {
		select {
		case <-s.egressStop:
			s.drainEgressQueueOnStop()
			return
		case pkt := <-s.egressCh:
			s.flushEgressBatch(pkt)
		}
	}
}

func (s *ClientPacketSession) flushEgressBatch(first []byte) {
	batch := make([][]byte, 1, clientPacketEgressBatchMax)
	batch[0] = first
	for len(batch) < clientPacketEgressBatchMax {
		select {
		case p := <-s.egressCh:
			batch = append(batch, p)
		default:
			goto send
		}
	}
send:
	for _, p := range batch {
		_, _ = s.writePacketDirectNoWake(p)
	}
	if s.wakeAfterDatagram != nil {
		s.wakeAfterDatagram()
	}
}

func (s *ClientPacketSession) writePacketDirect(buffer []byte) ([]byte, error) {
	icmp, err := s.conn.WritePacket(buffer)
	return s.accountWrite(len(buffer), icmp, err)
}

func (s *ClientPacketSession) writePacketDirectNoWake(buffer []byte) ([]byte, error) {
	if s.datagramCeiling > 0 && len(buffer) > s.datagramCeiling {
		TrackWriteFail(Errs.Transport, true)
		return nil, Errs.Transport
	}
	icmp, err := s.conn.WritePacket(buffer)
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

func (s *ClientPacketSession) drainEgressQueueOnStop() {
	for {
		select {
		case pkt := <-s.egressCh:
			_, _ = s.writePacketDirectNoWake(pkt)
		default:
			return
		}
	}
}

func (s *ClientPacketSession) stopEgressWriter() {
	s.egressClose.Do(func() {
		if s.egressCh == nil {
			return
		}
		s.egressClosed.Store(true)
		close(s.egressStop)
		s.egressWG.Wait()
	})
}
