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

// MarkMasqueBidiDuplexUploadStarted marks concurrent C2S relay during download-active hijack.
func MarkMasqueBidiDuplexUploadStarted(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	if qs := s.datagramStream.QUICStream(); qs != nil {
		quic.MasqueSetBidiDuplexUploadStarted(qs, true)
	}
}

// IsMasqueBidiDuplexUploadStarted reports saturated duplex on a CONNECT stream.
func IsMasqueBidiDuplexUploadStarted(s *Stream) bool {
	if s == nil || s.datagramStream == nil {
		return false
	}
	qs := s.datagramStream.QUICStream()
	return qs != nil && quic.MasqueIsBidiDuplexUploadStarted(qs)
}

// WakeMasqueRelayAfterDownloadWrite nudges QUIC after server relay sends download (S2C).
func WakeMasqueRelayAfterDownloadWrite(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	qs := s.datagramStream.QUICStream()
	if qs == nil {
		return
	}
	if quic.MasqueIsBidiDuplexUploadStarted(qs) {
		if quic.MasquePeerUploadCreditDue(qs) {
			quic.MasqueRepromoteDuplexUploadSend(qs)
		}
		quic.MasqueWakeStreamSend(qs)
		return
	}
	if quic.MasqueIsBidiDownloadActive(qs) || quic.MasqueIsBidiDownloadReceiveOnly(qs) {
		quic.MasqueWakeStreamSend(qs)
	}
}

// WakeMasqueRelayAfterUploadRead nudges QUIC after server relay consumes client upload (grant C2S credit).
func WakeMasqueRelayAfterUploadRead(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	qs := s.datagramStream.QUICStream()
	if qs == nil {
		return
	}
	if quic.MasqueIsBidiDuplexUploadStarted(qs) {
		quic.MasquePokePeerUploadCreditAfterConsume(qs)
		quic.MasqueRepromoteDuplexUploadSend(qs)
		return
	}
	masqueWakeSendAfterReceiveRead(s, 1)
	if s.conn != nil && s.conn.conn != nil {
		quic.MasqueWakeConnSend(s.conn.conn)
	}
}

// ArmMasqueBidiDuplexParallel marks saturated duplex without fair-defer relay gate or credit wait (H2 relay parity).
func ArmMasqueBidiDuplexParallel(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	qs := s.datagramStream.QUICStream()
	if qs == nil {
		return
	}
	quic.MasqueClearPeerUploadCreditQueue(qs)
	quic.MasqueClearConnMaxDataQueue(qs)
	quic.MasqueBoostDuplexReceiveFC(qs)
	MarkMasqueBidiDuplexUploadStarted(s)
	ActivateMasqueBidiDuplex(s)
}

// ArmMasqueBidiDuplexFair marks saturated duplex on server hijack before bulk relay (both legs known).
func ArmMasqueBidiDuplexFair(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	qs := s.datagramStream.QUICStream()
	if qs == nil {
		return
	}
	// Drop hijack-era 64 KiB queue slot so the first post-arm MAX_STREAM_DATA uses boosted FC.
	quic.MasqueClearPeerUploadCreditQueue(qs)
	quic.MasqueClearConnMaxDataQueue(qs)
	// Boost + fair-defer before any stream markers poke FC — avoids a 64 KiB MAX_STREAM_DATA
	// queued at hijack (EnableMasqueConnectStream lazy FC) winning the first control slot.
	quic.MasqueBoostDuplexReceiveFC(qs)
	quic.MasqueSetBidiDuplexFairDeferRelay(qs, true)
	MarkMasqueBidiDuplexUploadStarted(s)
	ActivateMasqueBidiDuplex(s)
	quic.MasquePokePeerUploadCredit(qs)
	quic.MasquePokeConnPeerUploadCredit(qs)
	quic.MasqueRepromoteDuplexUploadSend(qs)
}

// PrepareMasqueRelayDownloadPrimary clears saturated duplex markers on download-only hijack relays.
func PrepareMasqueRelayDownloadPrimary(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	qs := s.datagramStream.QUICStream()
	if qs == nil {
		return
	}
	DeactivateMasqueBidiDuplex(s)
	quic.MasqueSetBidiDuplexFairDeferRelay(qs, false)
	// Drop hijack-era 64 KiB lazy FC slot so first post-probe S2C bulk uses boosted windows.
	quic.MasqueClearPeerUploadCreditQueue(qs)
	quic.MasqueClearConnMaxDataQueue(qs)
}

// WaitMasqueRelayPeerUploadCredit blocks until initial boosted C2S MAX_STREAM_DATA ships (duplex relay gate).
// Download-only CONNECT legs (iperf -R, no C2S bytes) disarm duplex fair after the wait budget.
func WaitMasqueRelayPeerUploadCredit(s *Stream) {
	if s == nil || s.datagramStream == nil {
		return
	}
	qs := s.datagramStream.QUICStream()
	if qs == nil {
		return
	}
	if !quic.MasqueWaitPeerUploadCreditShipped(qs) {
		DeactivateMasqueBidiDuplex(s)
		quic.MasqueSetBidiDuplexFairDeferRelay(qs, false)
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
// Initial MAX_STREAM_DATA is deferred: server relay arms via ArmMasqueBidiDuplexFair; client via dial prime.
func EnableMasqueConnectStream(s *Stream) {
	if s == nil {
		return
	}
	EnableMasqueTunnelData(s)
	if s.datagramStream != nil {
		if qs := s.datagramStream.QUICStream(); qs != nil {
			quic.MasqueSetPeerDuplexLazyFC(qs, true)
		}
	}
}

// WakeMasqueClientAfterDatagramReceive schedules QUIC send after CONNECT-UDP client S2C read (echo duplex interleave).
func WakeMasqueClientAfterDatagramReceive(s *Stream) {
	if s == nil || s.conn == nil || s.conn.conn == nil {
		return
	}
	quic.MasqueWakeConnSend(s.conn.conn)
}

// WakeMasqueClientAfterDatagramReceiveFrom works on Stream or RequestStream without exporting RequestStream.str.
func WakeMasqueClientAfterDatagramReceiveFrom(str interface{}) {
	switch s := str.(type) {
	case *Stream:
		WakeMasqueClientAfterDatagramReceive(s)
	case *RequestStream:
		if s != nil {
			WakeMasqueClientAfterDatagramReceive(s.str)
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
