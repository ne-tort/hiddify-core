package relay

import (
	"io"

	"github.com/quic-go/quic-go/http3"
)

// RelayBidiWaker hides *http3.Stream wake/flush hooks behind one relay-local assertion site (DIP-2).
type RelayBidiWaker interface {
	enableConnectStream()
	prepareDownloadPrimary()
	enableDownloadSend()
	flushDownloadPrime() error
	flushCoalesce() error
	isDuplexUploadStarted() bool
	wakeAfterDownloadWrite()
	wakeAfterUploadRead()
	armDuplexParallel()
}

type relayH3BidiWaker struct {
	*http3.Stream
}

func relayBidiWakerFromRW(leg io.ReadWriteCloser) RelayBidiWaker {
	if leg == nil {
		return nil
	}
	if str, ok := leg.(*http3.Stream); ok {
		return relayH3BidiWaker{str}
	}
	return nil
}

func relayBidiWakerFromWriter(w io.Writer) RelayBidiWaker {
	if w == nil {
		return nil
	}
	if str, ok := w.(*http3.Stream); ok {
		return relayH3BidiWaker{str}
	}
	return nil
}

func relayBidiWakerFromHTTPStream(str *http3.Stream) RelayBidiWaker {
	if str == nil {
		return nil
	}
	return relayH3BidiWaker{str}
}

func (w relayH3BidiWaker) enableConnectStream() {
	http3.EnableMasqueConnectStream(w.Stream)
}

func (w relayH3BidiWaker) prepareDownloadPrimary() {
	http3.PrepareMasqueRelayDownloadPrimary(w.Stream)
}

func (w relayH3BidiWaker) enableDownloadSend() {
	http3.EnableMasqueRelayDownloadSend(w.Stream)
}

func (w relayH3BidiWaker) flushDownloadPrime() error {
	return http3.FlushMasqueRelayDownloadPrime(w.Stream)
}

func (w relayH3BidiWaker) flushCoalesce() error {
	return w.Stream.FlushMasqueCoalesce()
}

func (w relayH3BidiWaker) isDuplexUploadStarted() bool {
	return http3.IsMasqueBidiDuplexUploadStarted(w.Stream)
}

func (w relayH3BidiWaker) wakeAfterDownloadWrite() {
	http3.WakeMasqueRelayAfterDownloadWrite(w.Stream)
}

func (w relayH3BidiWaker) wakeAfterUploadRead() {
	http3.WakeMasqueRelayAfterUploadRead(w.Stream)
}

func (w relayH3BidiWaker) armDuplexParallel() {
	http3.ArmMasqueBidiDuplexParallel(w.Stream)
}
