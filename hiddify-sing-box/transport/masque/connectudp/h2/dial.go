package h2

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// connectUDPNoXNetBulkPipe reports ≤64KiB cap so x/net masque_upload_bulk_flush stays off CONNECT-UDP (REF-H2-02).
type connectUDPNoXNetBulkPipe struct {
	io.ReadCloser
}

func (connectUDPNoXNetBulkPipe) UploadPipeCap() int { return 64 << 10 }

// H2OverlayDialConfig wires production H2 CONNECT-UDP dial from package masque.
type H2OverlayDialConfig struct {
	Hook func(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error)

	EnsureTransport func(ctx context.Context) (*http2.Transport, error)
	// NewTransport builds a dedicated HTTP/2 client pool (separate TCP) per upload stream.
	NewTransport  func() (*http2.Transport, error)
	SetAuthHeader func(h http.Header)

	Tag                   string
	WarpConnectIPProtocol string
	QUICDialCandidateHost string
	ResolveDialAddr       func() string

	ErrTemplateNotConfigured error
}

// DialH2Overlay performs Extended CONNECT over HTTP/2 with DATAGRAM capsules (RFC 9298).
func DialH2Overlay(ctx context.Context, cfg H2OverlayDialConfig, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if cfg.Hook != nil {
		return cfg.Hook(ctx, template, target)
	}
	return dialH2OverlayAsymmetric(ctx, cfg, template, target)
}

func dialH2OverlayAsymmetric(ctx context.Context, cfg H2OverlayDialConfig, template *uritemplate.Template, target string) (net.PacketConn, error) {
	muxKey, err := NewUDPMuxSessionKey()
	if err != nil {
		return nil, fmt.Errorf("masque h2: asymmetric mux key: %w", err)
	}
	// Separate TCP/H2 client per leg (UDP-6MIG-11). Sharing one conn leaves a single
	// upload body pump @ unlimited hammer — upload pipe fills with no server reader.
	download, err := dialH2OverlaySingle(ctx, cfg, template, target, streamRoleDownload, muxKey)
	if err != nil {
		return nil, err
	}
	localAddr := download.LocalAddr()
	var remoteAddr net.Addr
	if ra, ok := download.(interface{ RemoteAddr() net.Addr }); ok {
		remoteAddr = ra.RemoteAddr()
	}

	upload, err := dialH2OverlaySingle(ctx, cfg, template, target, streamRoleUpload, muxKey)
	if err != nil {
		_ = download.Close()
		return nil, err
	}
	return NewAsymmetricPacketConn(download, []net.PacketConn{upload}, localAddr, remoteAddr, nil), nil
}

func dialH2OverlaySingle(ctx context.Context, cfg H2OverlayDialConfig, template *uritemplate.Template, target string, role streamRole, muxKey string) (net.PacketConn, error) {
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
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("masque h2: bad target: %w", err)
	}
	expanded, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(port),
	})
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
		return nil, err
	}

	uploadOnly := role == streamRoleUpload
	var pipeR io.ReadCloser
	var pipeW h2c.ConnectUploadPipeWriter
	var uploadBody *h2c.ExtendedConnectUploadBody
	var reqBody io.WriteCloser
	if uploadOnly {
		// Shallow uploadPipe decouples C2S from writeRequestBody; END_STREAM deferred until writer half-close.
		pipeR, pipeW = h2c.NewConnectUploadShallowPipe()
		pipeR = connectUDPNoXNetBulkPipe{ReadCloser: pipeR}
		uploadBody = &h2c.ExtendedConnectUploadBody{Pipe: pipeR, Writer: pipeW}
		uploadBody.BeginUploadWriterLive()
		reqBody = pipeW
	}
	streamCtx, stopReqCtxRelay := httpx.NewH2ExtendedConnectRequestContext(ctx)
	defer stopReqCtxRelay(false)
	var reqBodyReader io.Reader
	if uploadBody != nil {
		reqBodyReader = uploadBody
	}
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, expanded, reqBodyReader)
	if err != nil {
		if pipeW != nil {
			_ = pipeW.Close()
		}
		return nil, fmt.Errorf("masque h2: new connect-udp request: %w", err)
	}
	req.Header = make(http.Header)
	req.Header.Set(":protocol", ConnectProto)
	req.Header.Set(http3.CapsuleProtocolHeader, h2c.CapsuleProtocolHeaderValue())
	if cfg.SetAuthHeader != nil {
		cfg.SetAuthHeader(req.Header)
	}
	if hdr := streamRoleHeader(role); hdr != "" {
		req.Header.Set(MasqueUDPStreamRoleHeader, hdr)
	}
	if muxKey != "" {
		req.Header.Set(MasqueUDPMuxKeyHeader, muxKey)
	}
	if u.Host != "" {
		req.Host = u.Host
	}
	if uploadOnly {
		req.ContentLength = -1
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		if pipeW != nil {
			_ = pipeW.Close()
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
		if pipeW != nil {
			_ = pipeW.Close()
		}
		_ = resp.Body.Close()
		return nil, fmt.Errorf("masque h2: CONNECT-UDP status %d", resp.StatusCode)
	}
	if ctxErr := context.Cause(ctx); ctxErr != nil {
		if pipeW != nil {
			_ = pipeW.Close()
		}
		_ = resp.Body.Close()
		return nil, ctxErr
	}
	stopReqCtxRelay(true)

	dialAddr := cfg.ResolveDialAddr()

	raddr := NewUDPAddr(target)
	if nh := ProxyStatusNextHopUDP(resp); nh != nil {
		raddr = NewUDPAddr(net.JoinHostPort(nh.IP.String(), strconv.Itoa(nh.Port)))
	}

	profile := legProfileForStreamRole(role)
	pc := NewPacketConn(PacketConnConfig{
		ReqPipeR:      pipeR,
		ReqBody:       reqBody,
		Resp:          resp,
		LocalAddr:     NewUDPAddr(dialAddr),
		RemoteAddr:    raddr,
		UploadOnly:    uploadOnly,
		LegProfile:    profile,
		UploadWireAck: uploadBody,
		OnClose:       transportOnClose,
	})
	if uploadOnly {
		if err := pc.Prime(); err != nil {
			_ = pc.Close()
			return nil, err
		}
		pc.startUploadOnlyDrain()
	}
	return pc, nil
}

// ProxyStatusNextHopUDP parses Proxy-Status next-hop from a CONNECT-UDP response.
func ProxyStatusNextHopUDP(rsp *http.Response) *net.UDPAddr {
	if rsp == nil {
		return nil
	}
	vals := rsp.Header.Values("Proxy-Status")
	if len(vals) == 0 {
		return nil
	}
	proxyStatus, err := httpsfv.UnmarshalItem(vals)
	if err != nil {
		return nil
	}
	nextHop, ok := proxyStatus.Params.Get("next-hop")
	if !ok {
		return nil
	}
	nextHopStr, ok := nextHop.(string)
	if !ok || nextHopStr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(nextHopStr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: portNum}
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
