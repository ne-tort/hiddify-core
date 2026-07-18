package session

import (
	"log"
	"strings"
	"sync/atomic"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/yosida95/uritemplate/v3"
)

// CurrentUDPHTTPLayer returns the effective CONNECT-UDP/control overlay ("h2" or "h3").
func CurrentUDPHTTPLayer(s *CoreSession) string {
	v, _ := s.UDPHTTPLayer.Load().(string)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case option.MasqueHTTPLayerH2:
		return option.MasqueHTTPLayerH2
	default:
		return option.MasqueHTTPLayerH3
	}
}

// HTTPLayerCacheDialIdentityForSession returns the live MASQUE TLS edge identity for TTL cache keys.
func HTTPLayerCacheDialIdentityForSession(s *CoreSession) HTTPLayerCacheDialIdentity {
	var hopTag string
	if len(s.HopOrder) > 0 && s.HopIndex >= 0 && s.HopIndex < len(s.HopOrder) {
		hopTag = strings.TrimSpace(s.HopOrder[s.HopIndex].Tag)
	}
	return HTTPLayerCacheDialIdentity{
		HopTag: hopTag,
		Server: strings.TrimSpace(s.Options.Server),
		Port:   s.Options.ServerPort,
	}
}

// MaybeRecordHTTPLayerCacheSuccess forwards a working h2/h3 choice to protocol/masque.RecordMasqueHTTPLayerSuccess.
// EffectiveMasqueClientHTTPLayer only consults the chain entry hop (empty Via), not inner hops after advanceHop.
func MaybeRecordHTTPLayerCacheSuccess(s *CoreSession, layer string) {
	if s.Options.HTTPLayerSuccess == nil {
		return
	}
	if len(s.HopOrder) > 0 && s.HopIndex > 0 {
		return
	}
	s.Options.HTTPLayerSuccess(layer, HTTPLayerCacheDialIdentityForSession(s))
}

// TeardownOverlayHTTPLockedAssumeMu closes shared H3 transports after overlay pivot. Caller holds s.Mu.
func TeardownOverlayHTTPLockedAssumeMu(s *CoreSession) {
	if s.IPHTTP != nil {
		s.IPHTTP.Close()
		if s.TCPHTTP == s.IPHTTP {
			s.TCPHTTP = nil
		}
		s.IPHTTP = nil
		s.IPHTTPConn = nil
		s.IPHTTPH2Upload = nil
	}
	if s.TCPHTTP != nil {
		s.TCPHTTP.Close()
		s.TCPHTTP = nil
	}
}

// CloseUDPClientLockedAssumeMu closes the QUIC CONNECT-UDP client during overlay pivot. Caller holds s.Mu.
func CloseUDPClientLockedAssumeMu(s *CoreSession) {
	if s.UDPClient != nil {
		_ = s.UDPClient.Close()
		s.UDPClient = nil
	}
}

// TryHTTPFallbackSwitch attempts H3↔H2 overlay pivot after a switchable handshake failure.
func TryHTTPFallbackSwitch(s *CoreSession, host LifecycleHost, err error) bool {
	s.Mu.Lock()
	ok := TryHTTPFallbackSwitchLockedAssumeMu(s, host, err)
	s.Mu.Unlock()
	return ok
}

// TryHTTPFallbackSwitchLockedAssumeMu pivots overlay when http_layer is auto. Caller holds s.Mu.
//
// Tears down on successful pivot (AUDIT B16): CONNECT-IP dataplane + native L3, shared H3
// IP/TCP transports, UDPClient, and **all** H2 client transports (UDP + CONNECT-stream).
// Refuses pivot when CONNECT-IP is already open (IPConn != nil). Live CONNECT-UDP PacketConns
// are gated in package masque (coreSession.tryHTTPFallbackSwitch*) via flow tracking (B14/B15).
func TryHTTPFallbackSwitchLockedAssumeMu(s *CoreSession, host LifecycleHost, err error) bool {
	if !s.HTTPLayerAuto || err == nil || !httpx.IsLayerSwitchableFailure(err) {
		return false
	}
	if s.IPConn != nil {
		return false
	}
	if !s.HTTPFallbackConsumed.CompareAndSwap(false, true) {
		return false
	}
	cur := CurrentUDPHTTPLayer(s)
	var next string
	switch cur {
	case option.MasqueHTTPLayerH3:
		next = option.MasqueHTTPLayerH2
	case option.MasqueHTTPLayerH2:
		next = option.MasqueHTTPLayerH3
	default:
		s.HTTPFallbackConsumed.Store(false)
		return false
	}
	log.Printf("masque_http_layer_fallback tag=%s from=%s to=%s", strings.TrimSpace(s.Options.Tag), cur, next)
	host.StopConnectIPNativeL3Plane()
	host.CancelConnectIPIngress()
	CloseConnectIPDataplaneLockedAssumeMu(s, host)
	TeardownOverlayHTTPLockedAssumeMu(s)
	CloseUDPClientLockedAssumeMu(s)
	host.CloseAllH2ClientTransports()
	s.UDPHTTPLayer.Store(next)
	return true
}

// ResetHTTPFallbackBudgetAfterSuccess clears the one-shot auto overlay pivot latch after a successful handshake.
func ResetHTTPFallbackBudgetAfterSuccess(s *CoreSession) {
	s.HTTPFallbackConsumed.Store(false)
}

// ClearHTTPFallbackConsumedAfterGivingUp resets the latch when returning an error so the next dial gets a fresh pivot budget.
func ClearHTTPFallbackConsumedAfterGivingUp(s *CoreSession) {
	s.HTTPFallbackConsumed.Store(false)
}

// WireMasqueUDPClientForOverlayLocked rebuilds QUIC CONNECT-UDP client or clears it when overlay is H2.
// Caller must hold s.Mu (udpHTTPLayer was updated by TryHTTPFallbackSwitch).
func WireMasqueUDPClientForOverlayLocked(s *CoreSession, newUDPClient func() *qmasque.Client) (*qmasque.Client, *uritemplate.Template) {
	if CurrentUDPHTTPLayer(s) != option.MasqueHTTPLayerH2 {
		if s.UDPClient == nil && newUDPClient != nil {
			s.UDPClient = newUDPClient()
		}
	} else if s.UDPClient != nil {
		_ = s.UDPClient.Close()
		s.UDPClient = nil
	}
	return s.UDPClient, s.TemplateUDP
}

// OverlayDatagramsEnabled reports whether CONNECT-IP should advertise QUIC datagrams for the current overlay.
func OverlayDatagramsEnabled(s *CoreSession) bool {
	return CurrentUDPHTTPLayer(s) != option.MasqueHTTPLayerH2
}

// StoreUDPHTTPLayer sets the overlay layer (tests).
func StoreUDPHTTPLayer(s *CoreSession, layer string) {
	s.UDPHTTPLayer.Store(layer)
}

// HTTPFallbackConsumedLatch exposes the fallback latch for tests.
func HTTPFallbackConsumedLatch(s *CoreSession) *atomic.Bool {
	return &s.HTTPFallbackConsumed
}
