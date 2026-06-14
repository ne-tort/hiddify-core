package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

var streamDialOnceHooks = strm.DialOnceHooks{
	PathHostForTemplate: MasqueTCPPathHostForTemplate,
	FixExpandedURL:      FixMasqueExpandedTCPConnectStreamURL,
	RewritePercentIPv6:  RewriteMasqueTCPURLIfPercentEncodedIPv6,
}

type tcpStreamDialH3Host struct {
	s *coreSession
}

func (h tcpStreamDialH3Host) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	return h.s.getTCPRoundTripper(defaultTransport)
}

func (h tcpStreamDialH3Host) ResetHTTP3Transport() *http3.Transport {
	h.s.resetTCPHTTPTransport()
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	return h.s.TCPHTTP
}

func streamDialH3Hooks(options ClientOptions) strm.DialH3Hooks {
	return strm.DialH3Hooks{
		NewRequestContext: httpx.NewH2ExtendedConnectRequestContext,
		BuildRequest: func(ctx context.Context, url, serverHost string, usePipe bool) (*http.Request, *io.PipeReader, io.WriteCloser, error) {
			return h3.ConnectRequest(ctx, url, serverHost, usePipe, func(h http.Header) {
				setMasqueAuthorizationHeader(h, options)
			})
		},
		TunnelFromResponse: func(ctx context.Context, resp *http.Response, upload io.WriteCloser, targetHost string, targetPort uint16) (net.Conn, error) {
			allowPipe := h3.ConnectUsePipeUpload()
			return strm.H3TunnelFromResponse(ctx, resp, upload, targetHost, targetPort, allowPipe, h3.ConnectTunnelFromResponse)
		},
		UsePipeUpload: h3.ConnectUsePipeUpload,
		RequestURL:    MasqueTCPConnectStreamRequestURL,
		ClassifyError: func(err error) string { return string(session.ClassifyError(err)) },
		AuthFailed:    session.ErrAuthFailed,
	}
}

func (s *coreSession) dialTCPStreamHTTP3(ctx context.Context, tcpURL *url.URL, options ClientOptions, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error) {
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	hooks := streamDialH3Hooks(options)
	logIn := strm.DialH3LogInput{
		Tag:        options.Tag,
		TCPURLHost: tcpURL.Host,
		Server:     options.Server,
		ServerPort: options.ServerPort,
		ResolveDialAddr: func(port int) string {
			return masqueDialTarget(masqueQuicDialCandidateHost(options), port)
		},
	}
	host := tcpStreamDialH3Host{s: s}
	if h3.ConnectStreamUseDualConnect() {
		// P2: download leg now; upload leg lazy (or parallel-prep on WriteTo) — no second CONNECT on single-leg flows.
		download, err := strm.DialHTTP3ConnectStreamLeg(ctx, hooks, host, tcpURL, logIn, targetHost, targetPort, tcpHTTP, false, "download")
		if err != nil {
			return nil, err
		}
		dialCtx := ctx
		var local, remote net.Addr
		if download != nil {
			local = download.LocalAddr()
			remote = download.RemoteAddr()
		}
		dc := h3.NewDualTunnelConn(h3.DualTunnelConnParams{
			Download: download,
			Ctx:      ctx,
			Local:    local,
			Remote:   remote,
		})
		dc.SetUploadDial(func() (net.Conn, io.Closer, error) {
			uploadHTTP := tcpHTTP
			var uploadCloser io.Closer
			if dc.UploadLegParallelQUIC() {
				tr, acquireErr := session.AcquireP6UploadTransport(dialCtx, &s.CoreSession)
				if acquireErr != nil {
					return nil, nil, acquireErr
				}
				uploadHTTP = tr
				sess := &s.CoreSession
				warmCtx := dialCtx
				uploadCloser = p6UploadLegCloser{
					closer: tr,
					release: func() {
						session.KickP6UploadWarmPoolIdle(warmCtx, sess)
					},
				}
			}
			upload, dialErr := strm.DialHTTP3ConnectStreamLeg(dialCtx, hooks, host, tcpURL, logIn, targetHost, targetPort, uploadHTTP, false, "upload")
			if dialErr != nil {
				if uploadCloser != nil {
					_ = uploadCloser.Close()
				}
				return nil, nil, dialErr
			}
			wireH3PeerDuplexWake(dc, download, upload)
			return upload, uploadCloser, nil
		})
		return strm.NewTunnelConn(dc), nil
	}
	return strm.DialHTTP3ConnectStream(ctx, hooks, host, tcpURL, logIn, targetHost, targetPort, tcpHTTP)
}

func wireH3PeerDuplexWake(dc *h3.DualTunnelConn, download, upload net.Conn) {
	ulTC := findH3TunnelConn(upload)
	if ulTC != nil {
		ulTC.SetPeerDuplexDownloadActive(dc.CompositeDownloadActive)
	}
	dlTC := findH3TunnelConn(download)
	if dlTC != nil && ulTC != nil {
		dlTC.SetPeerDuplexUploadWake(ulTC.WakePeerDuplexUpload)
	}
}

func findH3TunnelConn(conn net.Conn) *h3.TunnelConn {
	for conn != nil {
		if tc, ok := h3.AsTunnelConn(conn); ok {
			return tc
		}
		if w, ok := conn.(*strm.TunnelConn); ok && w.Inner != nil {
			conn = w.Inner
			continue
		}
		break
	}
	return nil
}

func (s *coreSession) dialTCPStreamOnce(ctx context.Context, templateTCP *uritemplate.Template, options ClientOptions, destination M.Socksaddr, httpLayer string, tcpHTTP *http3.Transport, targetHost string, targetPort uint16, pathBracket bool) (net.Conn, *url.URL, error) {
	hooks := streamDialOnceHooks
	hooks.DialH2 = func(ctx context.Context, tcpURL *url.URL, targetHost string, destination M.Socksaddr) (net.Conn, error) {
		return s.dialTCPStreamH2(ctx, tcpURL, options, targetHost, destination)
	}
	hooks.DialH3 = func(ctx context.Context, tcpURL *url.URL, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error) {
		return s.dialTCPStreamHTTP3(ctx, tcpURL, options, targetHost, targetPort, tcpHTTP)
	}
	return strm.DialOnce(ctx, hooks, templateTCP, destination, httpLayer, option.MasqueHTTPLayerH2, tcpHTTP, targetHost, targetPort, pathBracket)
}
