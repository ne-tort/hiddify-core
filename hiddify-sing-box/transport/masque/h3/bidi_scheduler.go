package h3

import (
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// BidiWakeSink counts upload/download-side wake attempts during WriteTo duplex (test/inject).
type BidiWakeSink interface {
	NoteUploadWake()
	NoteDownloadWake()
}

// ConnectStreamSchedPolicy holds prod scheduling constants (MS3 — zero-env).
type ConnectStreamSchedPolicy struct {
	WriteToBufLen                  int
	UploadFlushChunkBytes          int
	DownloadDeliveryWakeBatchBytes int
	DuplexStarvedDownloadReadCap   int
}

// ProdConnectStreamSchedPolicy is the default CONNECT-stream H3 scheduler policy.
func ProdConnectStreamSchedPolicy() ConnectStreamSchedPolicy {
	return ConnectStreamSchedPolicy{
		WriteToBufLen:                  TunnelWriteToBufLen,
		UploadFlushChunkBytes:          H3UploadFlushChunkBytes,
		DownloadDeliveryWakeBatchBytes: TunnelWriteToBufLen,
		DuplexStarvedDownloadReadCap:   16 * 1024,
	}
}

// UploadChunkBytes returns upload write chunk size for the current duplex phase.
func (p ConnectStreamSchedPolicy) UploadChunkBytes(downloadActive bool) int {
	if downloadActive {
		return p.UploadFlushChunkBytes
	}
	return p.WriteToBufLen
}

// CapDownloadRead limits download read size when upload send is starved (WAN bidi fairness).
func (p ConnectStreamSchedPolicy) CapDownloadRead(uploadSendStarved bool, bufLen int) int {
	if uploadSendStarved && bufLen > p.DuplexStarvedDownloadReadCap {
		return p.DuplexStarvedDownloadReadCap
	}
	return bufLen
}

// bidiScheduler applies ConnectStreamSchedPolicy and QUIC wake hooks for one TunnelConn.
type bidiScheduler struct {
	conn   *TunnelConn
	policy ConnectStreamSchedPolicy
}

func newBidiScheduler(c *TunnelConn, policy ConnectStreamSchedPolicy) *bidiScheduler {
	if policy.WriteToBufLen <= 0 {
		policy = ProdConnectStreamSchedPolicy()
	}
	return &bidiScheduler{conn: c, policy: policy}
}

func (s *bidiScheduler) uploadChunkBytes() int {
	if s == nil || s.conn == nil {
		return TunnelWriteToBufLen
	}
	return s.policy.UploadChunkBytes(s.conn.DownloadActive())
}

func (s *bidiScheduler) capDownloadRead(p []byte, uploadSendStarved bool) []byte {
	if s == nil {
		return p
	}
	if cap := s.policy.CapDownloadRead(uploadSendStarved, len(p)); cap < len(p) {
		return p[:cap]
	}
	return p
}

func (s *bidiScheduler) noteDownloadDelivery(delivered int) {
	c := s.conn
	if s == nil || c == nil || delivered <= 0 || !c.downloadWakeEligible() {
		return
	}
	if qs := c.h3.QUICStream(); qs != nil &&
		quic.MasqueIsBidiDownloadReceiveOnly(qs) && !quic.MasqueIsBidiDuplexUploadStarted(qs) {
		s.wakeAfterDownloadDelivery()
		return
	}
	pending := atomic.AddInt32(&c.downloadDeliveryPending, int32(delivered))
	batch := int32(s.policy.DownloadDeliveryWakeBatchBytes)
	if pending >= batch {
		atomic.AddInt32(&c.downloadDeliveryPending, -batch)
		s.wakeAfterDownloadDelivery()
	}
}

func (s *bidiScheduler) wakeAfterUpload() {
	c := s.conn
	if c == nil || c.h3 == nil || !c.DownloadActive() {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteUploadWake()
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	quic.MasqueRepromoteDuplexUploadSend(qs)
	if quic.MasqueUploadSendStarved(qs) {
		quic.MasqueWakeBidiDuplex(qs)
	} else {
		quic.MasqueWakeStreamSend(qs)
	}
}

func (s *bidiScheduler) wakeAfterDownloadDelivery() {
	c := s.conn
	if s == nil || c == nil || !c.downloadWakeEligible() {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteDownloadWake()
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	if quic.MasqueIsBidiDownloadReceiveOnly(qs) && !quic.MasqueIsBidiDuplexUploadStarted(qs) {
		quic.MasquePokeDownloadReceiveWindow(qs)
		quic.MasquePokeConnPeerUploadCredit(qs)
		quic.MasqueWakeStreamSend(qs)
		return
	}
	if quic.MasqueUploadSendStarved(qs) {
		quic.MasqueRepromoteDuplexUploadSend(qs)
		quic.MasqueWakeBidiDuplex(qs)
		return
	}
	if quic.MasqueDuplexGrantPeerDownloadCredit(qs) {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueRepromoteDuplexUploadSend(qs)
	quic.MasqueWakeStreamSend(qs)
}

func (s *bidiScheduler) wakeUploadDuringDownload() {
	if s == nil || s.conn == nil || !s.conn.DownloadActive() {
		return
	}
	s.wakeAfterUpload()
}

func (c *TunnelConn) downloadWakeEligible() bool {
	if c == nil || c.h3 == nil {
		return false
	}
	if c.DownloadActive() {
		return true
	}
	qs := c.h3.QUICStream()
	return qs != nil && quic.MasqueIsBidiDownloadReceiveOnly(qs)
}
