package session

import (
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// CoreSession owns QUIC/H2/H3 overlay state for one MASQUE client.
// Methods remain in package masque during phase F; fields are exported for embedding.
type CoreSession struct {
	Mu                       sync.Mutex
	Options                  ClientOptions
	UDPClient                *qmasque.Client
	H2UDPTransport           *http2.Transport
	H2ConnectStreamTransport *http2.Transport
	H2UDPMu                  sync.Mutex
	H2ConnectStreamMu        sync.Mutex
	HTTPLayerAuto            bool
	HTTPFallbackConsumed     atomic.Bool
	UDPHTTPLayer             atomic.Value // "h3" | "h2"
	IPConn                   *connectip.Conn
	IPHTTPConn               *http3.ClientConn
	// IPHTTPH2Upload is the CONNECT-IP HTTP/2 Extended CONNECT upload half (ingress ACK wake poke).
	IPHTTPH2Upload           io.Writer
	IPHTTP                   *http3.Transport
	TCPHTTP                  *http3.Transport
	p6UploadWarm             p6UploadWarmPool
	TemplateUDP              *uritemplate.Template
	TemplateIP               *uritemplate.Template
	TemplateTCP              *uritemplate.Template
	Caps                     CapabilitySet
	HopOrder                 []HopOptions
	HopIndex                 int
	ConnectIPDatagramCeiling   int
	ConnectIPUDPPayloadHardCap int
	ConnectIPTCPDatagramSlack  int
	MasqueUDPWriteMax          int
	ConnectIPPMTUState         *mcip.UDPPMTUState
	TCPRoundTripper            http.RoundTripper
	TCPNetstack                mcip.TCPNetstack
	ConnectIPIngressOnce       sync.Once
	ConnectIPIngress           *mcip.Ingress
	ConnectIPIngressAckWake    mcip.IngressAckWake
	IngressTCPNetstack         atomic.Pointer[mcip.Netstack]
	ConnectIPTCPInstallInflight atomic.Int32
}

// ConnectIPPMTUState tracks the effective UDP payload ceiling for the CONNECT-IP UDP bridge.
type ConnectIPPMTUState = mcip.UDPPMTUState

// NewConnectIPPMTUState constructs PMTU state with the given payload bounds.
func NewConnectIPPMTUState(currentPayload, minPayload, maxPayload int) *ConnectIPPMTUState {
	return mcip.NewUDPPMTUState(currentPayload, minPayload, maxPayload)
}
