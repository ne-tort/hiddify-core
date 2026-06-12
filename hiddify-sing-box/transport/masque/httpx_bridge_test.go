package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func TestCoreSessionDialUsesFakeHTTPLayer(t *testing.T) {
	t.Parallel()

	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("udp template: %v", err)
	}
	_, _, templateTCP, err := buildTemplates(ClientOptions{
		Server:     "example.com",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}

	var tcpHits, udpHits, ipHits atomic.Uint32
	layer := httpx.NewHookLayer(option.MasqueHTTPLayerH3, httpx.HookFuncs{
		TCPRoundTrip: func(*http.Request) (*http.Response, error) {
			tcpHits.Add(1)
			return nil, errors.New("fake httpx layer tcp")
		},
		UDPDial: func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
			udpHits.Add(1)
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
		ConnectIP: func(context.Context, bool) (*connectip.Conn, error) {
			ipHits.Add(1)
			return nil, errors.New("fake httpx layer ip")
		},
	})

	session := newTestCoreSession(session.CoreSession{
		Options: ClientOptions{
			Server:                   "example.com",
			ServerPort:               443,
			TransportMode:            option.MasqueTransportModeConnectUDP,
			TCPTransport:             option.MasqueTCPTransportConnectStream,
			TCPMode:                  option.MasqueTCPModeStrictMasque,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
		TemplateUDP: templateUDP,
		TemplateTCP: templateTCP,
		Caps:        CapabilitySet{ConnectTCP: true, ConnectUDP: true, ConnectIP: true},
		UDPClient:   &qmasque.Client{},
	})
	BindHookLayer(session, layer)

	if got := session.currentUDPHTTPLayer(); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("overlay want h3 got %q", got)
	}

	dest := M.ParseSocksaddrHostPort("example.com", 443)
	_, dialErr := session.DialContext(context.Background(), "tcp", dest)
	if dialErr == nil || !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("DialContext: want ErrTCPConnectStreamFailed, got %v", dialErr)
	}
	if tcpHits.Load() != 1 {
		t.Fatalf("tcpRoundTripper via HookLayer: want 1 call, got %d", tcpHits.Load())
	}

	pc, listenErr := session.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if listenErr != nil {
		t.Fatalf("ListenPacket via HookLayer: %v", listenErr)
	}
	_ = pc.Close()
	if udpHits.Load() != 1 {
		t.Fatalf("udpDial via HookLayer: want 1 call, got %d", udpHits.Load())
	}

	_, openErr := session.OpenIPSession(context.Background())
	if openErr == nil {
		t.Fatal("OpenIPSession: expected error from fake connect-ip hook")
	}
	if n := ipHits.Load(); n < 1 {
		t.Fatalf("dialConnectIPAttemptHook via HookLayer: want >=1 call (H3 churn may retry), got %d", n)
	}
}

func TestBindHookLayerTCPRoundTripSuccessPath(t *testing.T) {
	t.Parallel()

	_, _, templateTCP, err := buildTemplates(ClientOptions{
		Server:     "example.com",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}

	session := newTestCoreSession(session.CoreSession{
		Options: ClientOptions{
			Server:                   "example.com",
			ServerPort:               443,
			TCPTransport:             option.MasqueTCPTransportConnectStream,
			TCPMode:                  option.MasqueTCPModeStrictMasque,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
		TemplateTCP: templateTCP,
		Caps:        CapabilitySet{ConnectTCP: true},
	})
	BindHookLayer(session, httpx.NewHookLayer(option.MasqueHTTPLayerH3, httpx.HookFuncs{
		TCPRoundTrip: func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, dialErr := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if dialErr == nil {
		t.Fatal("expected error building tunnel from stub 200 response")
	}
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("want ErrTCPConnectStreamFailed, got %v", dialErr)
	}
}
