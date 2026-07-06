package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	cstrm "github.com/sagernet/sing-box/protocol/masque/server/connectstream"
	"github.com/sagernet/sing-box/option"
	"github.com/yosida95/uritemplate/v3"
)

// TestGATEConnectStreamOnwardDialSerialIPv4Fallback (H2-SERIAL-FALLBACK) — unreachable v6 then v4 OK → 200.
func TestGATEConnectStreamOnwardDialSerialIPv4Fallback(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptOneEcho(ln)

	port := ln.Addr().(*net.TCPAddr).Port
	v4 := netip.MustParseAddr("127.0.0.1")
	unreachableV6 := netip.MustParseAddr("2001:db8:dead:beef::1")

	handler := cstrm.Handler{
		Hooks: cstrm.Hooks{
			ResolveTCPTargetAddrs: func(_ context.Context, _ string, _ bool) ([]netip.Addr, error) {
				return []netip.Addr{unreachableV6, v4}, nil
			},
			AllowTCPPort:      AllowTCPPort,
			OnwardTCPDialAddr: OnwardTCPDialAddr,
			DialTCPTargetSerial: DialTCPTargetSerial,
		},
	}
	host := cstrm.Host{
		Options:          option.MasqueEndpointOptions{},
		Dialer:           net.Dialer{Timeout: 500 * time.Millisecond},
		Authorize:        func(*http.Request) bool { return true },
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}
	req := httptest.NewRequest(http.MethodConnect, "/masque/tcp/example.test/"+strconv.Itoa(port), io.NopCloser(strings.NewReader("")))
	req.Host = "masque.local"
	req.RequestURI = "https://masque.local/masque/tcp/example.test/" + strconv.Itoa(port)
	rec := httptest.NewRecorder()

	handler.HandleConnectStream(host, rec, req, template, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (serial v4 fallback); body=%q", rec.Code, rec.Body.String())
	}
}

// TestGATEConnectStreamOnwardDialAAAAFirstUsesIPv4 (H1-AAAA-FIRST) — old first-addr v6-only path would 502.
func TestGATEConnectStreamOnwardDialAAAAFirstUsesIPv4(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptOneEcho(ln)

	port := ln.Addr().(*net.TCPAddr).Port
	aaaaFirst := []netip.Addr{
		netip.MustParseAddr("2001:db8:aaaa:1::1"),
		netip.MustParseAddr("127.0.0.1"),
	}
	ordered := OrderResolvedTCPAddrs(aaaaFirst)
	if !ordered[0].Is4() {
		t.Fatalf("OrderResolvedTCPAddrs must prefer v4 first: %v", ordered)
	}

	handler := cstrm.Handler{
		Hooks: cstrm.Hooks{
			ResolveTCPTargetAddrs: func(_ context.Context, _ string, _ bool) ([]netip.Addr, error) {
				return ordered, nil
			},
			AllowTCPPort:        AllowTCPPort,
			OnwardTCPDialAddr:   OnwardTCPDialAddr,
			DialTCPTargetSerial: DialTCPTargetSerial,
		},
	}
	host := cstrm.Host{
		Options:          option.MasqueEndpointOptions{},
		Dialer:           net.Dialer{Timeout: 500 * time.Millisecond},
		Authorize:        func(*http.Request) bool { return true },
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}
	req := httptest.NewRequest(http.MethodConnect, "/masque/tcp/yandex.ru/"+strconv.Itoa(port), io.NopCloser(strings.NewReader("")))
	req.Host = "masque.local"
	rec := httptest.NewRecorder()

	handler.HandleConnectStream(host, rec, req, template, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 when v4 reachable after AAAA-first resolve order", rec.Code)
	}
}

// TestGATEConnectStreamOnwardDialAllFail502 — all resolved addrs unreachable → 502.
func TestGATEConnectStreamOnwardDialAllFail502(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")
	handler := cstrm.Handler{
		Hooks: cstrm.Hooks{
			ResolveTCPTargetAddrs: func(_ context.Context, _ string, _ bool) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("2001:db8::dead:1")}, nil
			},
			AllowTCPPort:        AllowTCPPort,
			OnwardTCPDialAddr:   OnwardTCPDialAddr,
			DialTCPTargetSerial: DialTCPTargetSerial,
		},
	}
	host := cstrm.Host{
		Options:          option.MasqueEndpointOptions{},
		Dialer:           net.Dialer{Timeout: 200 * time.Millisecond},
		Authorize:        func(*http.Request) bool { return true },
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}
	req := httptest.NewRequest(http.MethodConnect, "/masque/tcp/unreachable.test/8443", io.NopCloser(strings.NewReader("")))
	req.Host = "masque.local"
	rec := httptest.NewRecorder()

	handler.HandleConnectStream(host, rec, req, template, true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502 when all onward dials fail", rec.Code)
	}
}

func acceptOneEcho(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("ok"))
}
