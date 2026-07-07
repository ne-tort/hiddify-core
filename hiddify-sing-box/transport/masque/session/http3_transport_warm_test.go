package session

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
)

func TestTCPConnectStreamHTTP3AuthorityAddsDefaultPort(t *testing.T) {
	got := TCPConnectStreamHTTP3Authority(ClientOptions{Server: "edge.example", ServerPort: 0})
	if got != "edge.example:443" {
		t.Fatalf("authority=%q want edge.example:443", got)
	}
}

func TestEnsureTCPHTTPQuicConnSkipsWhenAlreadyWarm(t *testing.T) {
	s := &CoreSession{
		Options: ClientOptions{Server: "edge.example", ServerPort: 443},
	}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	tr := &http3.Transport{}
	s.TCPHTTP = tr
	s.tcpHTTPWarm = tr
	if err := EnsureTCPHTTPQuicConn(s); err != nil {
		t.Fatalf("warm skip: %v", err)
	}
}

func TestResetTCPHTTPTransportClearsWarmMarker(t *testing.T) {
	s := &CoreSession{
		Options: ClientOptions{Server: "edge.example", ServerPort: 443},
	}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	s.TCPHTTP = NewTCPConnectStreamHTTP3Transport(s)
	s.tcpHTTPWarm = s.TCPHTTP
	ResetTCPHTTPTransport(s, tcpHTTPTransportHostStub{})
	if s.tcpHTTPWarm != nil {
		t.Fatal("tcpHTTPWarm must clear on transport reset")
	}
	if s.TCPHTTP == nil {
		t.Fatal("TCPHTTP must be rebuilt")
	}
}

type tcpHTTPTransportHostStub struct{}

func (tcpHTTPTransportHostStub) ResetH2ConnectStreamTransportLockedAssumeMu() {}
