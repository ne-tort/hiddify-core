package masque

import (
	"log"
	"strings"
)

type overlaySwitchHost struct {
	lifecycleHost
}

func (s *coreSession) overlaySwitchHost() overlaySwitchHost {
	return overlaySwitchHost{lifecycleHost: s.lifecycleHost()}
}

func (h overlaySwitchHost) TeardownOverlayHTTPLockedAssumeMu() {
	s := h.s
	if s.IPHTTP != nil {
		s.IPHTTP.Close()
		if s.TCPHTTP == s.IPHTTP {
			s.TCPHTTP = nil
		}
		s.IPHTTP = nil
		s.IPHTTPConn = nil
	}
	if s.TCPHTTP != nil {
		s.TCPHTTP.Close()
		s.TCPHTTP = nil
	}
}

func (h overlaySwitchHost) CloseUDPClientLockedAssumeMu() {
	if h.s.UDPClient != nil {
		_ = h.s.UDPClient.Close()
		h.s.UDPClient = nil
	}
}

func (h overlaySwitchHost) OverlaySwitchLog(tag, from, to string) {
	log.Printf("masque_http_layer_fallback tag=%s from=%s to=%s", strings.TrimSpace(tag), from, to)
}
