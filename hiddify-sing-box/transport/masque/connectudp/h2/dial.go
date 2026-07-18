package h2

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// H2OverlayDialConfig wires production H2 CONNECT-UDP dial from package masque.
type H2OverlayDialConfig struct {
	Hook func(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error)

	EnsureTransport func(ctx context.Context) (*http2.Transport, error)
	// NewTransport is optional lab/isolation mode: builds one dedicated TCP per UDPFlow.
	// Prod leaves this nil and uses EnsureTransport → shared H2UDPTransport (H2-TUN-3).
	// When set, DialH2Overlay uses one dedicated TCP for the single RFC bidi stream.
	NewTransport  func() (*http2.Transport, error)
	SetAuthHeader func(h http.Header)

	Tag                   string
	WarpConnectIPProtocol string
	QUICDialCandidateHost string
	ResolveDialAddr       func() string
	// PathObfuscationKey is the baked-in key when path_obfuscation=true (nil = plaintext host/port).
	PathObfuscationKey []byte

	ErrTemplateNotConfigured error
}

// DialH2Overlay performs Extended CONNECT over HTTP/2 with DATAGRAM capsules (RFC 9298).
// One CONNECT → one H2 stream: C2S = request body, S2C = response body (approach A).
func DialH2Overlay(ctx context.Context, cfg H2OverlayDialConfig, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if cfg.Hook != nil {
		return cfg.Hook(ctx, template, target)
	}
	return dialH2OverlayBidi(ctx, cfg, template, target)
}

func dialH2OverlayBidi(ctx context.Context, cfg H2OverlayDialConfig, template *uritemplate.Template, target string) (net.PacketConn, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	var transportOnClose func()
	cfg, transportOnClose = dedicatedOverlayTransport(cfg)
	if template == nil {
		return nil, cfg.ErrTemplateNotConfigured
	}
	expanded, err := pathbuild.ExpandHostPortAddr(template, pathbuild.ObfuscationKey(cfg.PathObfuscationKey), target)
	if err != nil {
		return nil, fmt.Errorf("masque h2: expand template: %w", err)
	}
	u, err := url.Parse(expanded)
	if err != nil {
		return nil, fmt.Errorf("masque h2: parse url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("masque h2: template must use https scheme")
	}

	tr, err := cfg.EnsureTransport(ctx)
	if err != nil {
		if transportOnClose != nil {
			transportOnClose()
		}
		return nil, err
	}

	// Shallow uploadPipe decouples C2S from writeRequestBody; END_STREAM deferred until writer half-close.
	pipeR, pipeW := h2c.NewConnectUploadShallowPipe()
	pipeR = wrapConnectUDPNoXNetBulkPipe(pipeR)
	uploadBody := &h2c.ExtendedConnectUploadBody{Pipe: pipeR, Writer: pipeW}
	uploadBody.BeginUploadWriterLive()
	reqBody := pipeW

	// Match CONNECT-stream dial_h2.go: do NOT defer stop(false) after stop(true).
	streamCtx, stopReqCtxRelay := httpx.NewH2ExtendedConnectRequestContext(ctx)
	handshakeOK := false
	defer func() {
		if !handshakeOK {
			stopReqCtxRelay(false)
		}
	}()
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, expanded, uploadBody)
	if err != nil {
		_ = pipeW.Close()
		if transportOnClose != nil {
			transportOnClose()
		}
		return nil, fmt.Errorf("masque h2: new connect-udp request: %w", err)
	}
	req.Header = make(http.Header)
	req.Header.Set(":protocol", ConnectProto)
	req.Header.Set(http3.CapsuleProtocolHeader, h2c.CapsuleProtocolHeaderValue())
	if cfg.SetAuthHeader != nil {
		cfg.SetAuthHeader(req.Header)
	}
	if u.Host != "" {
		req.Host = u.Host
	}
	req.ContentLength = -1

	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = pipeW.Close()
		if transportOnClose != nil {
			transportOnClose()
		}
		proto := strings.TrimSpace(cfg.WarpConnectIPProtocol)
		primaryHost := strings.TrimSpace(cfg.QUICDialCandidateHost)
		altHost := ""
		if strings.EqualFold(proto, "cf-connect-ip") {
			altHost = WarpH2AlternateDialHost(primaryHost)
		}
		if altHost != "" && IsH2ExtendedConnectUnsupportedByPeer(err) {
			diag.Logf("masque h2 cf-connect-ip: connect-udp tcp uses sibling %s of quic dataplane %s; peer omits RFC8441 SETTINGS_ENABLE_CONNECT_PROTOCOL tag=%s",
				altHost, primaryHost, strings.TrimSpace(cfg.Tag))
		}
		return nil, fmt.Errorf("masque h2: roundtrip: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pipeW.Close()
		_ = resp.Body.Close()
		if transportOnClose != nil {
			transportOnClose()
		}
		return nil, fmt.Errorf("masque h2: CONNECT-UDP status %d", resp.StatusCode)
	}
	if ctxErr := context.Cause(ctx); ctxErr != nil {
		_ = pipeW.Close()
		_ = resp.Body.Close()
		if transportOnClose != nil {
			transportOnClose()
		}
		return nil, ctxErr
	}
	stopReqCtxRelay(true)
	handshakeOK = true

	dialAddr := cfg.ResolveDialAddr()

	raddr := NewUDPAddr(target)
	if nh := frame.ProxyStatusNextHopUDP(resp); nh != nil {
		raddr = NewUDPAddr(net.JoinHostPort(nh.IP.String(), strconv.Itoa(nh.Port)))
	}

	onClose := func() {
		stopReqCtxRelay(false)
		if transportOnClose != nil {
			transportOnClose()
		}
	}
	pc := NewPacketConn(PacketConnConfig{
		ReqPipeR:      pipeR,
		ReqBody:       reqBody,
		Resp:          resp,
		LocalAddr:     NewUDPAddr(dialAddr),
		RemoteAddr:    raddr,
		UploadWireAck: uploadBody,
		OnClose:       onClose,
	})
	if err := pc.Prime(); err != nil {
		_ = pc.Close()
		return nil, err
	}
	return pc, nil
}

// H2DialHostCandidates returns TCP dial host order for H2 MASQUE (WARP sibling parity).
func H2DialHostCandidates(connectProto string, dialOverrideHost string, alternateDialHost string) []string {
	dialOverrideHost = strings.TrimSpace(dialOverrideHost)
	alternateDialHost = strings.TrimSpace(alternateDialHost)
	if dialOverrideHost == "" {
		return []string{""}
	}
	if alternateDialHost == "" || strings.EqualFold(alternateDialHost, dialOverrideHost) {
		return []string{dialOverrideHost}
	}
	if strings.EqualFold(strings.TrimSpace(connectProto), "cf-connect-ip") {
		return []string{alternateDialHost}
	}
	return []string{dialOverrideHost, alternateDialHost}
}

// IsH2ExtendedConnectUnsupportedByPeer matches golang.org/x/net/http2 errors when the peer did not
// advertise RFC 8441 (SETTINGS_ENABLE_CONNECT_PROTOCOL).
func IsH2ExtendedConnectUnsupportedByPeer(err error) bool {
	if err == nil {
		return false
	}
	es := strings.ToLower(err.Error())
	return strings.Contains(es, "extended connect not supported") ||
		strings.Contains(es, "enable_connect_protocol") ||
		strings.Contains(es, "enable connect protocol")
}

// WarpH2AlternateDialHost swaps WARP sibling IPv4 (.1 <-> .2) for H2 dial fallback.
func WarpH2AlternateDialHost(host string) string {
	host = strings.TrimSpace(host)
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return ""
	}
	v4 := addr.As4()
	switch v4[3] {
	case 1:
		v4[3] = 2
	case 2:
		v4[3] = 1
	default:
		return ""
	}
	return netip.AddrFrom4(v4).String()
}
