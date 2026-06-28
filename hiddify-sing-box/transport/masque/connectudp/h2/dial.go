package h2

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

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
	policy := ConnectUDPDialPolicyFromEnv()
	if policy.AsymmetricDuplex {
		uploads := policy.UploadStreams
		if uploads < 1 {
			uploads = 1
		}
		return dialH2OverlayAsymmetric(ctx, cfg, template, target, uploads)
	}
	streams := policy.UploadStreams
	if streams <= 1 {
		return dialH2OverlaySingle(ctx, cfg, template, target, streamRoleBidi, "")
	}
	return dialH2OverlaySharded(ctx, cfg, template, target, streams)
}

func dialH2OverlayAsymmetric(ctx context.Context, cfg H2OverlayDialConfig, template *uritemplate.Template, target string, uploadCount int) (net.PacketConn, error) {
	muxKey, err := NewUDPMuxSessionKey()
	if err != nil {
		return nil, fmt.Errorf("masque h2: asymmetric mux key: %w", err)
	}
	var sharedTr *http2.Transport
	var sharedErr error
	var sharedOnce sync.Once
	sharedEnsure := func(ctx context.Context) (*http2.Transport, error) {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		default:
		}
		if cfg.NewTransport != nil {
			sharedOnce.Do(func() {
				sharedTr, sharedErr = cfg.NewTransport()
			})
			if sharedErr != nil {
				return nil, sharedErr
			}
			return sharedTr, nil
		}
		return cfg.EnsureTransport(ctx)
	}
	// One TCP pool per UDPFlow; download + upload legs are separate H2 streams on it.
	flowCfg := cfg
	flowCfg.NewTransport = nil
	flowCfg.EnsureTransport = sharedEnsure

	download, err := dialH2OverlaySingle(ctx, flowCfg, template, target, streamRoleDownload, muxKey)
	if err != nil {
		return nil, err
	}
	localAddr := download.LocalAddr()
	var remoteAddr net.Addr
	if ra, ok := download.(interface{ RemoteAddr() net.Addr }); ok {
		remoteAddr = ra.RemoteAddr()
	}

	uploads := make([]net.PacketConn, 0, uploadCount)
	for i := 0; i < uploadCount; i++ {
		pc, err := dialH2OverlaySingle(ctx, flowCfg, template, target, streamRoleUpload, muxKey)
		if err != nil {
			_ = download.Close()
			for _, u := range uploads {
				_ = u.Close()
			}
			if sharedTr != nil {
				CloseClientTransport(sharedTr)
			}
			return nil, err
		}
		uploads = append(uploads, pc)
	}
	onClose := func() {
		if sharedTr != nil {
			CloseClientTransport(sharedTr)
			sharedTr = nil
		}
	}
	return NewAsymmetricPacketConn(download, uploads, localAddr, remoteAddr, onClose), nil
}

func dialH2OverlaySharded(ctx context.Context, cfg H2OverlayDialConfig, template *uritemplate.Template, target string, streams int) (net.PacketConn, error) {
	if cfg.NewTransport == nil {
		return dialH2OverlaySingle(ctx, cfg, template, target, streamRoleBidi, "")
	}
	conns := make([]net.PacketConn, 0, streams)
	var localAddr, remoteAddr net.Addr
	var transports []*http2.Transport
	for i := 0; i < streams; i++ {
		streamCfg := cfg
		streamCfg.EnsureTransport = func(ctx context.Context) (*http2.Transport, error) {
			select {
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			default:
			}
			tr, err := cfg.NewTransport()
			if err != nil {
				return nil, err
			}
			transports = append(transports, tr)
			return tr, nil
		}
		pc, err := dialH2OverlaySingle(ctx, streamCfg, template, target, streamRoleBidi, "")
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			for _, tr := range transports {
				CloseClientTransport(tr)
			}
			return nil, err
		}
		if i == 0 {
			localAddr = pc.LocalAddr()
			if ra, ok := pc.(interface{ RemoteAddr() net.Addr }); ok {
				remoteAddr = ra.RemoteAddr()
			}
		}
		conns = append(conns, pc)
	}
	onClose := func() {
		for _, tr := range transports {
			CloseClientTransport(tr)
		}
	}
	return NewShardedPacketConn(conns, localAddr, remoteAddr, onClose), nil
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

	pipeR, pipeW := h2c.NewConnectUploadPipe()
	uploadBody := &h2c.ExtendedConnectUploadBody{Pipe: pipeR}
	streamCtx, stopReqCtxRelay := httpx.NewH2ExtendedConnectRequestContext(ctx)
	defer stopReqCtxRelay(false)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, expanded, uploadBody)
	if err != nil {
		_ = pipeW.Close()
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
	req.ContentLength = -1

	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = pipeW.Close()
		proto := strings.TrimSpace(cfg.WarpConnectIPProtocol)
		primaryHost := strings.TrimSpace(cfg.QUICDialCandidateHost)
		altHost := ""
		if strings.EqualFold(proto, "cf-connect-ip") {
			altHost = WarpH2AlternateDialHost(primaryHost)
		}
		if altHost != "" && IsH2ExtendedConnectUnsupportedByPeer(err) {
			log.Printf("masque h2 cf-connect-ip: connect-udp tcp uses sibling %s of quic dataplane %s; peer omits RFC8441 SETTINGS_ENABLE_CONNECT_PROTOCOL tag=%s",
				altHost, primaryHost, strings.TrimSpace(cfg.Tag))
		}
		return nil, fmt.Errorf("masque h2: roundtrip: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pipeW.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("masque h2: CONNECT-UDP status %d", resp.StatusCode)
	}
	if ctxErr := context.Cause(ctx); ctxErr != nil {
		_ = pipeW.Close()
		_ = resp.Body.Close()
		return nil, ctxErr
	}
	stopReqCtxRelay(true)

	dialAddr := cfg.ResolveDialAddr()

	raddr := NewUDPAddr(target)
	if nh := ProxyStatusNextHopUDP(resp); nh != nil {
		raddr = NewUDPAddr(net.JoinHostPort(nh.IP.String(), strconv.Itoa(nh.Port)))
	}

	uploadOnly := role == streamRoleUpload
	profile := legProfileForStreamRole(role)
	asyncDownlink := !uploadOnly
	pc := NewPacketConn(PacketConnConfig{
		ReqPipeR:      pipeR,
		ReqBody:       NewRequestBodyWriter(pipeW),
		Resp:          resp,
		LocalAddr:     NewUDPAddr(dialAddr),
		RemoteAddr:    raddr,
		AsyncDownlink: asyncDownlink,
		UploadOnly:    uploadOnly,
		LegProfile:    profile,
		UploadWireAck: uploadBody,
		OnClose:       transportOnClose,
	})
	if err := pc.Prime(); err != nil {
		_ = pc.Close()
		return nil, err
	}
	if uploadOnly {
		pc.startUploadOnlyDrain()
	} else {
		pc.ensureDownlinkPump()
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
