package http3

import (
	"fmt"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	http3FrameTypeData     = 0x0
	http3FrameTypeHeaders  = 0x1
)

// EnableMasqueTunnelData marks CONNECT tunnel bulk phase on *http3.Stream.
func EnableMasqueTunnelData(s *Stream) {
	if s != nil {
		s.masqueTunnelData = true
	}
}

// DeactivateMasqueBidiDuplex clears concurrent bidi relay markers on hijacked CONNECT streams.
func DeactivateMasqueBidiDuplex(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	if qs := s.datagramStream.QUICStream(); qs != nil {
		quic.MasqueSetBidiDuplexUploadStarted(qs, false)
		quic.MasqueSetBidiDownloadReceiveActive(qs, false)
	}
}

// ActivateMasqueBidiDuplex marks saturated duplex on hijacked CONNECT streams (server relay parity with client WriteTo).
func ActivateMasqueBidiDuplex(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	if qs := s.datagramStream.QUICStream(); qs != nil {
		quic.MasqueSetBidiDownloadReceiveActive(qs, true)
	}
}

// EnableMasqueRelayDownloadSend marks server S2C tunnel send on hijacked CONNECT streams.
func EnableMasqueRelayDownloadSend(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	if qs := s.datagramStream.QUICStream(); qs != nil {
		quic.MasqueSetBidiDownloadActive(qs, true)
	}
}

// EnableMasqueConnectStream is the single prod CONNECT-stream profile: tunnel DATA parse + lazy receive FC.
// Does not mark download-active until WriteTo/relay drain starts (avoids upload mis-routing in quic wake).
func EnableMasqueConnectStream(s *Stream) {
	if s == nil {
		return
	}
	EnableMasqueTunnelData(s)
	if s.datagramStream != nil {
		if qs := s.datagramStream.QUICStream(); qs != nil {
			quic.MasqueSetPeerDuplexLazyFC(qs, true)
			quic.MasquePokeDownloadReceiveWindow(qs)
		}
	}
}

// WakeMasqueRelayDownloadPrime nudges QUIC after H3 relay iperf banner prime (H2 flush parity).
func WakeMasqueRelayDownloadPrime(s *Stream) {
	masqueWakeSendAfterDownloadWrite(s, 1)
}

// FlushMasqueCoalesce ships pending CONNECT DATA under the 256 KiB coalesce threshold.
func (s *Stream) FlushMasqueCoalesce() error {
	if s == nil {
		return nil
	}
	if err := s.flushMasqueWriteCoalesce(); err != nil {
		return err
	}
	masqueWakeSendAfterUploadWrite(s, 1)
	return nil
}

// FlushMasqueRelayDownloadPrime ships coalesced CONNECT DATA under 256 KiB (iperf banner prime).
func FlushMasqueRelayDownloadPrime(s *Stream) error {
	if s == nil {
		return nil
	}
	if err := s.flushMasqueWriteCoalesce(); err != nil {
		return err
	}
	WakeMasqueRelayDownloadPrime(s)
	return nil
}

func (p *frameParser) parseTunnelDataFrame(qlogger qlogwriter.Recorder) (frame, error) {
	r := &countingByteReader{Reader: quicvarint.NewReader(p.r)}
	t, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	l, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	switch t {
	case http3FrameTypeData:
		if qlogger != nil {
			qlogger.RecordEvent(qlog.FrameParsed{
				StreamID: p.streamID,
				Raw: qlog.RawInfo{
					Length:        int(l) + r.NumRead,
					PayloadLength: int(l),
				},
				Frame: qlog.Frame{Frame: qlog.DataFrame{}},
			})
		}
		return &dataFrame{Length: l}, nil
	case http3FrameTypeHeaders:
		return &headersFrame{
			Length:    l,
			headerLen: r.NumRead,
		}, nil
	default:
		p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
		return nil, fmt.Errorf("http3: unexpected frame in tunnel data phase: %d", t)
	}
}
