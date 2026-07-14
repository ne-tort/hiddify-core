package http3

import (
	"fmt"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	http3FrameTypeData    = 0x0
	http3FrameTypeHeaders = 0x1
)

// EnableMasqueTunnelData marks CONNECT tunnel bulk phase on *http3.Stream.
func EnableMasqueTunnelData(s *Stream) {
	if s != nil {
		s.masqueTunnelData = true
	}
}

// EnableMasqueConnectStream enables fast CONNECT tunnel DATA frame parsing.
func EnableMasqueConnectStream(s *Stream) {
	EnableMasqueTunnelData(s)
}

// WakeMasqueClientAfterDatagramReceive schedules QUIC send after CONNECT-UDP client S2C read.
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
