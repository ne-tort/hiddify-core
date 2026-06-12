package httpx_test

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// dialTimeoutNetErr is synthetic net-compatible timeout text matching common Windows dial failures
// without the legacy "i/o timeout" / "connection timed out" substrings.
type dialTimeoutNetErr struct{}

func (dialTimeoutNetErr) Error() string   { return "dial tcp 203.0.113.1:443: connectex: A connection attempt failed" }
func (dialTimeoutNetErr) Timeout() bool   { return true }
func (dialTimeoutNetErr) Temporary() bool { return false }

var (
	errConnectIPTemplateNotConfigured = errors.New("masque: CONNECT-IP URI template is not configured")
	errTCPConnectStreamFailed         = errors.New("masque tcp connect-stream failed")
	errAuthFailed                     = errors.New("masque auth failed")
)

func TestMain(m *testing.M) {
	httpx.RegisterNonSwitchableSentinel(
		errConnectIPTemplateNotConfigured,
		errAuthFailed,
	)
	os.Exit(m.Run())
}

func TestHTTPLayerSwitchableFailure(t *testing.T) {
	switchable := httpx.IsLayerSwitchableFailure
	if !switchable(errors.New("Extended CONNECT xyz")) {
		t.Fatal("expected switchable")
	}
	if !switchable(errors.New(`http2: server sent GOAWAY and closed the connection`)) {
		t.Fatal("expected GOAWAY to be switchable for h2 fallback")
	}
	if !switchable(errors.New(`stream error: stream ID 3; RST_STREAM`)) {
		t.Fatal("expected RST_STREAM/stream error switchable")
	}
	if !switchable(errors.New("write tcp: broken pipe")) {
		t.Fatal("expected broken pipe switchable")
	}
	if !switchable(errors.New("read tcp 198.51.100.1:443->198.51.100.2:45678: read: connection timed out")) {
		t.Fatal("expected connection timed out switchable (Linux-style errno text)")
	}
	if !switchable(dialTimeoutNetErr{}) {
		t.Fatal("expected net.Error.Timeout() dial without legacy tokens to be switchable")
	}
	if switchable(&net.DNSError{Name: "slow.example.invalid", Server: "9.9.9.9:53", IsTimeout: true}) {
		t.Fatal("DNS timeout must not consume http_layer_fallback (same resolver for both overlays)")
	}
	if switchable(fmt.Errorf("wrap: %w", &net.DNSError{Name: "x", IsTimeout: true})) {
		t.Fatal("wrapped DNS timeout must not flip HTTP layer")
	}
	if !switchable(errors.New("wsarecv: An existing connection was forcibly closed by the remote host.")) {
		t.Fatal("expected forcibly-closed TCP switchable (Windows-style)")
	}
	if !switchable(errors.New("read tcp: use of closed network connection")) {
		t.Fatal("expected stdlib closed-conn switchable")
	}
	if switchable(errConnectIPTemplateNotConfigured) {
		t.Fatal("missing CONNECT-IP template sentinel must not flip HTTP layer")
	}
	if switchable(fmt.Errorf("parse: %w", h2c.ErrOversizedDeclared)) {
		t.Fatal("H2 CONNECT-UDP declared-length capsule rejection must not flip HTTP layer")
	}
	if switchable(fmt.Errorf("masque connect-ip h2: %w", errConnectIPTemplateNotConfigured)) {
		t.Fatal("wrapped template sentinel must not flip despite masque connect-ip h2 substring")
	}
	if switchable(net.ErrClosed) {
		t.Fatal("net.ErrClosed sentinel (incl. bare from CONNECT-IP H2 capsule path) must not flip HTTP layer")
	}
	if switchable(fmt.Errorf("recv: %w", net.ErrClosed)) {
		t.Fatal("wrapped net.ErrClosed must not flip HTTP layer")
	}
	if switchable(&connectip.CloseError{Remote: true}) {
		t.Fatal("CONNECT-IP CloseError must not flip HTTP layer despite net.ErrClosed-compatible Error() text")
	}
	if switchable(errors.Join(errors.New("read packet"), &connectip.CloseError{Remote: false})) {
		t.Fatal("wrapped CONNECT-IP CloseError must not flip HTTP layer")
	}
	if !switchable(errors.New("write tcp: The pipe is being closed.")) {
		t.Fatal("expected Windows pipe-closed switchable")
	}
	if !switchable(errors.New("masque connect-ip h2: roundtrip refused")) {
		t.Fatal("expected CONNECT-IP/H2 handshake prefix switchable")
	}
	if !switchable(errors.New("masque h2: tcp dialer is not configured")) {
		t.Fatal("expected H2-only setup error to be switchable so auto/fallback can try H3 overlay")
	}
	if !switchable(errors.New("masque h2: tcp connect-stream roundtrip: reset by peer")) {
		t.Fatal("expected H2 CONNECT-stream errors with canonical masque h2 prefix to be switchable")
	}
	if !switchable(fmt.Errorf("%w: status=%d url=%s",
		errTCPConnectStreamFailed, http.StatusBadGateway, "https://example.invalid/connect")) {
		t.Fatal("expected H3 CONNECT-stream non-2xx ErrTCPConnectStreamFailed shape to be switchable")
	}
	if !switchable(fmt.Errorf("masque h2: %w: status=%d url=%s",
		errTCPConnectStreamFailed, http.StatusBadGateway, "https://example.invalid/connect")) {
		t.Fatal("expected H2 CONNECT-stream non-2xx (aligned ErrTCP shape) to be switchable")
	}
	if !switchable(errors.New("masque: server responded with 502")) {
		t.Fatal("expected masque-go CONNECT-UDP non-2xx to be switchable for H3→H2 fallback")
	}
	if !switchable(errors.New("connect-ip: server responded with 502")) {
		t.Fatal("expected connect-ip-go H3 CONNECT-IP non-2xx to be switchable for H3→H2 fallback")
	}
	if switchable(errors.New("masque: server responded with 401")) {
		t.Fatal("CONNECT-UDP auth status must not flip layer")
	}
	if switchable(errors.New("connect-ip: server responded with 403")) {
		t.Fatal("CONNECT-IP auth status must not flip layer")
	}
	if switchable(errors.New("connect-ip: server responded with 407")) {
		t.Fatal("CONNECT-IP 407 must not flip layer")
	}
	if !switchable(errors.New("dial udp 198.51.100.1:1401: connection refused")) {
		t.Fatal("dial failures on port 1401 must not be confused with HTTP 401 substring match")
	}
	if switchable(errors.New("connect-ip: malformed datagram: too short")) {
		t.Fatal("library dataplane errors must not trigger HTTP layer flip")
	}
	if switchable(errors.New("masque h2 dataplane connect-udp capsule: corrupt framing")) {
		t.Fatal("post-handshake H2 CONNECT-UDP dataplane errors must not trigger HTTP layer flip")
	}
	if switchable(errors.New("masque h2 dataplane: extended connect capsule parse failed")) {
		t.Fatal("dataplane errors must not flip layer even if they mention extended connect")
	}
	if switchable(errors.New("masque connect-ip h2 dataplane: connect-ip: truncated capsule (extended connect noise in nested cause)")) {
		t.Fatal("CONNECT-IP H2 stream dataplane must not flip layer when nested text looks like handshake")
	}
	if switchable(errors.New("masque connect-ip h2 dataplane: write tcp: broken pipe")) {
		t.Fatal("CONNECT-IP H2 dataplane send/write must not consume http_layer_fallback")
	}
	if switchable(errors.New("masque connect-ip h2 dataplane: connect-ip: compose datagram: policy: extended connect noise")) {
		t.Fatal("H2 CONNECT-IP compose failures must not flip layer when nested text resembles handshake tokens")
	}
	if switchable(errors.New("masque connect-ip h3 dataplane: connect-ip: tls handshake while sending QUIC datagram")) {
		t.Fatal("CONNECT-IP H3 QUIC dataplane must not flip layer when nested text looks like handshake")
	}
	if switchable(errors.New("masque h2 dataplane connect-udp server capsule: unexpected EOF")) {
		t.Fatal("server-side H2 CONNECT-UDP relay dataplane must not flip HTTP layer")
	}
	if switchable(errors.New("masque h2 dataplane connect-udp server non-datagram capsule exceeds 65536 bytes")) {
		t.Fatal("oversized non-datagram capsules must stay dataplane classification")
	}
	if switchable(errors.New(`masque h2 dataplane connect-stream write: stream error`)) {
		t.Fatal("H2 CONNECT-stream dataplane faults must not flip HTTP layer")
	}
	if switchable(errors.New(`masque h3 dataplane connect-stream read: QUIC transport: pseudo handshake expired`)) {
		t.Fatal("H3 CONNECT-stream dataplane faults must not flip HTTP layer when nested text looks like handshake")
	}
	if switchable(errors.New("masque h3 dataplane connect-udp read: transport: QUIC extended connect noise")) {
		t.Fatal("H3 CONNECT-UDP dataplane faults must not flip HTTP layer when nested text looks like handshake")
	}
	if switchable(errors.New("masque h3 dataplane connect-udp write: tls handshake while sending datagram")) {
		t.Fatal("H3 CONNECT-UDP dataplane write must not flip HTTP layer on nested handshake-like text")
	}
	if switchable(errors.New("masque connect-udp h3 skip-capsules: type=7 capsule exceeds 65536 bytes")) {
		t.Fatal("H3 skip-capsules drain policy errors must not consume http_layer_fallback")
	}
	if switchable(errors.New("401 Unauthorized")) {
		t.Fatal("auth must not flip layer")
	}
	if switchable(nil) {
		t.Fatal("nil err")
	}
}
