package connectip

import (
	"errors"

	connectipgo "github.com/quic-go/connect-ip-go"
	cipegress "github.com/sagernet/sing-box/transport/masque/connectip/pump/egress"
)

func init() {
	connectipgo.SetOutboundPayloadReleaseHook(returnOutboundBuf, IsOutboundPoolSlice)
	cipegress.SetHooks(cipegress.Hooks{
		JoinTransport: func(err error) error {
			return errors.Join(Errs.Transport, err)
		},
		TrackWriteFail:    TrackWriteFail,
		TrackPacketTx:     TrackPacketTx,
		TrackPTBRx:        TrackPTBRx,
		BorrowOutboundBuf: borrowOutboundBuf,
		ReturnOutboundBuf: returnOutboundBuf,
	})
}

type clientPacketEgressHost struct {
	s *ClientPacketSession
}

func (h clientPacketEgressHost) PacketConn() cipegress.PacketConn {
	if h.s == nil {
		return nil
	}
	return h.s.conn
}

func (h clientPacketEgressHost) DatagramCeiling() int {
	if h.s == nil {
		return 0
	}
	return h.s.datagramCeiling
}

func (h clientPacketEgressHost) WakeAfterDatagram() func() {
	if h.s == nil {
		return nil
	}
	return h.s.wakeAfterDatagram
}

func (s *ClientPacketSession) egressHost() cipegress.ClientHost {
	return clientPacketEgressHost{s: s}
}

// Root re-exports from connectip/pump/egress during W-IP-1 subdir migration (IP-1-PR4).

var (
	FlushClientEgressBatch    = cipegress.FlushEgressBatch
	ScheduleClientEgressFlush = cipegress.ScheduleEgressFlush
)
