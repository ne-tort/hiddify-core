package masque

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

type streamDialAttemptFakeHost struct {
	snap            strm.AttemptSnapshot
	prepareErr      error
	dialCalls       int
	dialErr         error
	recordSuccess   int
	lastRecordedURL *url.URL
	tag             string
}

func (h *streamDialAttemptFakeHost) PrepareAttemptLocked() (strm.AttemptSnapshot, func(), error) {
	if h.prepareErr != nil {
		return strm.AttemptSnapshot{}, func() {}, h.prepareErr
	}
	return h.snap, func() {}, nil
}

func (h *streamDialAttemptFakeHost) DialOnce(_ context.Context, _ strm.AttemptSnapshot, _ M.Socksaddr, _ string, _ uint16) (net.Conn, *url.URL, error) {
	h.dialCalls++
	if h.dialErr != nil {
		return nil, nil, h.dialErr
	}
	u, _ := url.Parse("https://edge.example/.well-known/masque/tcp/192.0.2.1/443/")
	return &net.TCPConn{}, u, nil
}

func (h *streamDialAttemptFakeHost) RecordAttemptSuccess(_ strm.AttemptSnapshot, tcpURL *url.URL) {
	h.recordSuccess++
	h.lastRecordedURL = tcpURL
}

func (h *streamDialAttemptFakeHost) ConnectStreamTag() string {
	return h.tag
}

func TestStreamDialAttemptCanceledBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	host := &streamDialAttemptFakeHost{tag: "t1"}
	_, err := strm.DialAttempt(ctx, host, M.ParseSocksaddrHostPort("192.0.2.1", 443))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, session.ErrTCPConnectStreamFailed) {
		t.Fatalf("err=%v", err)
	}
	if host.dialCalls != 0 {
		t.Fatalf("dialCalls=%d want 0", host.dialCalls)
	}
}

func TestStreamDialAttemptSingleAttemptOnHTTP400(t *testing.T) {
	host := &streamDialAttemptFakeHost{
		tag:     "no-bracket",
		dialErr: errors.Join(session.ErrTCPConnectStreamFailed, errors.New("status=400 url=x")),
	}
	_, err := strm.DialAttempt(context.Background(), host, M.ParseSocksaddrHostPort("2001:db8::1", 443))
	if err == nil {
		t.Fatal("expected error")
	}
	if host.dialCalls != 1 {
		t.Fatalf("dialCalls=%d want 1", host.dialCalls)
	}
	if host.recordSuccess != 0 {
		t.Fatalf("recordSuccess=%d want 0", host.recordSuccess)
	}
}

func TestStreamDialAttemptSuccess(t *testing.T) {
	host := &streamDialAttemptFakeHost{tag: "ok"}
	conn, err := strm.DialAttempt(context.Background(), host, M.ParseSocksaddrHostPort("192.0.2.1", 443))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if host.dialCalls != 1 {
		t.Fatalf("dialCalls=%d want 1", host.dialCalls)
	}
	if host.recordSuccess != 1 {
		t.Fatalf("recordSuccess=%d want 1", host.recordSuccess)
	}
}

func TestStreamDialAttemptPrepareError(t *testing.T) {
	host := &streamDialAttemptFakeHost{
		prepareErr: errors.New("bad template"),
	}
	_, err := strm.DialAttempt(context.Background(), host, M.ParseSocksaddrHostPort("192.0.2.1", 443))
	if err == nil || err.Error() != "bad template" {
		t.Fatalf("err=%v", err)
	}
}

func TestStreamDialAttemptSnapshotH3Fields(t *testing.T) {
	host := &streamDialAttemptFakeHost{
		tag: "h3",
		snap: strm.AttemptSnapshot{
			HTTPLayer:   "h3",
			HTTPLayerH2: "h2",
			TCPHTTP:     &http3.Transport{},
		},
	}
	_, err := strm.DialAttempt(context.Background(), host, M.ParseSocksaddrHostPort("192.0.2.1", 443))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
