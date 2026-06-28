package masque

import (
	"net/http"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestTCPStreamDialH3HostRoundTripperBypassesSessionHookForEphemeralLeg(t *testing.T) {
	t.Parallel()
	shared := &http3.Transport{}
	ephemeral := &http3.Transport{}
	s := newTestCoreSession(session.CoreSession{
		TCPHTTP: shared,
		TCPRoundTripper: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, nil
		}),
	})
	host := s.streamH3Host()
	if rt := host.RoundTripper(ephemeral); rt != ephemeral {
		t.Fatalf("ephemeral P6 leg must bypass session hook, got %T", rt)
	}
	if rt := host.RoundTripper(shared); rt == shared {
		t.Fatal("shared CONNECT-stream leg must use session TCPRoundTripper hook")
	}
}
