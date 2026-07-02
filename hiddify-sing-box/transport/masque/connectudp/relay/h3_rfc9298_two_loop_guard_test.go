package relay

import (
	_ "embed"
	"strings"
	"testing"
)

// TestProdRelayRFC9298TwoLoopShape locks UDP-10 / G8: RFC-minimal duplex relay (C2S + S2C goroutines).
func TestProdRelayRFC9298TwoLoopShape(t *testing.T) {
	t.Parallel()
	idxFn := strings.Index(h3RelayProdSource, "func (s *Proxy) ProxyConnectedSocket")
	if idxFn < 0 {
		t.Fatal("missing ProxyConnectedSocket")
	}
	section := h3RelayProdSource[idxFn:]
	for _, needle := range []string{
		"wg.Add(3)",
		"relayCtx, cancelRelay := context.WithCancel(context.Background())",
		"s.proxyConnSend(relayCtx, conn, str)",
		"proxyConnReceive(relayCtx, conn, str)",
		"frame.SkipRequestStreamCapsules",
	} {
		if !strings.Contains(section, needle) {
			t.Fatalf("ProxyConnectedSocket must implement RFC 9298 two-loop relay (missing %q)", needle)
		}
	}
}

// TestProdRelayUsesSkipRequestStreamCapsules locks RFC 9297 §4.2 skip on request stream after relay drain.
func TestProdRelayUsesSkipRequestStreamCapsules(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3RelayProdSource, "frame.SkipRequestStreamCapsules") {
		t.Fatal("h3.go must drain request stream via frame.SkipRequestStreamCapsules")
	}
}

// TestProdRelayRFC9298WireParseAndValidate locks C2S/S2C wire helpers for proxied UDP framing and oversize abort.
func TestProdRelayRFC9298WireParseAndValidate(t *testing.T) {
	t.Parallel()
	c2sWire := h3RelayC2SSource
	if !strings.Contains(c2sWire, "relayHTTPDatagramUDPPayload") {
		t.Fatal("h3 C2S relay must use relayHTTPDatagramUDPPayload (masque-go context-0 fast path)")
	}
	if !strings.Contains(c2sWire, "ParseHTTPDatagramUDPFast") {
		t.Fatal("h3 C2S parse must use frame.ParseHTTPDatagramUDPFast for HTTP datagram framing")
	}
	if !strings.Contains(h3RelayC2SSource, "frame.ValidateProxiedUDPPayloadLen") {
		t.Fatal("h3_c2s.go must validate proxied UDP payload length")
	}
	if !strings.Contains(h3RelayS2CSource, "frame.ValidateProxiedUDPPayloadLen") {
		t.Fatal("h3_s2c.go must validate proxied UDP payload length")
	}
	if !strings.Contains(h3RelayS2CSource, "frame.ContextIDZeroWire") {
		t.Fatal("h3 S2C must prefix datagrams with context ID 0")
	}
}

// TestProdRelayRFC9298ICMPPortUnreachableEmptyPayload locks RFC 9298 §5 empty proxied UDP on ICMP port unreachable.
func TestProdRelayRFC9298ICMPPortUnreachableEmptyPayload(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3RelayS2CSource, "isICMPPortUnreachableUDPRead") {
		t.Fatal("h3_s2c.go must detect ICMP port unreachable on UDP read")
	}
	if !strings.Contains(h3RelayS2CSource, "SendDatagram(frame.ContextIDZeroWire)") {
		t.Fatal("h3_s2c.go must relay ICMP as zero-length proxied UDP (ctx0 only)")
	}
}
