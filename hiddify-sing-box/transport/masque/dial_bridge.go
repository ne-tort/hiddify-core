package masque

import (
	"context"
	"errors"
	"net/url"

	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func masqueTemplateHooks() session.TemplateURIHooks {
	return session.TemplateURIHooks{
		ExpandHTTPSURI:            ExpandMasqueHTTPSURI,
		NormalizeTCPUDPTargetHost: NormalizeMasqueTCPUDPTemplateTargetHost,
	}
}

func joinTemplateCapability(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, session.ErrTemplateCapability) {
		return errors.Join(session.ErrCapability, err)
	}
	return err
}

func buildTemplates(options ClientOptions) (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
	udp, ip, tcp, err := session.BuildTemplates(options, masqueTemplateHooks())
	return udp, ip, tcp, joinTemplateCapability(err)
}

func resolveHopOrder(hops []HopOptions) []HopOptions {
	return session.ResolveHopOrder(hops)
}

func resolveEntryHop(hops []HopOptions) (string, uint16, error) {
	return session.ResolveEntryHop(hops)
}

func applyConnectIPFlowScope(ipTemplateRaw string, scopeTarget string, scopeIPProto uint8) (string, error) {
	expanded, err := session.ApplyConnectIPFlowScope(ipTemplateRaw, scopeTarget, scopeIPProto)
	return expanded, joinTemplateCapability(err)
}

func masqueDialTarget(host string, port int) string {
	return session.MasqueDialTarget(host, port)
}

func resolveTLSServerName(options ClientOptions) string {
	return session.ResolveTLSServerName(options)
}

func masqueQuicDialCandidateHost(options ClientOptions) string {
	return session.QuicDialCandidateHost(options)
}

func resolveDestinationHost(destination M.Socksaddr) (string, error) {
	return strm.ResolveDestinationHost(destination)
}

func normalizeTCPTransport(mode string) string {
	return session.NormalizeTCPTransport(mode)
}

func isTCPMasqueDirectFallbackEligible(err error, ctx context.Context) bool {
	return session.TCPMasqueDirectFallbackEligible(err, ctx)
}

func tcpMasqueConnectStreamChosenLogFields(tcpURL *url.URL, options ClientOptions) (target, dial string) {
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	return strm.ConnectStreamChosenLogFields(strm.ConnectStreamLogInput{
		TCPURLHost: tcpURL.Host,
		Server:     options.Server,
		ServerPort: options.ServerPort,
		ResolveDialAddr: func() string {
			return masqueDialTarget(masqueQuicDialCandidateHost(options), portNum)
		},
	})
}

func tcpTracef(format string, args ...any) {
	strm.TraceTCPf(format, args...)
}

func isRetryableTCPStreamError(err error) bool {
	return strm.IsRetryableTCPStreamError(err)
}
