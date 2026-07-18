package frame

import (
	"net"
	"net/http"
	"strings"
	"unicode"

	"github.com/dunglas/httpsfv"
)

// DNSErrorToProxyStatus fills Proxy-Status params for CONNECT-UDP dial failures (RFC 9209).
func DNSErrorToProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
		return
	}
	proxyStatus.Params.Add("error", "dns_error")
	if dnsError.IsNotFound {
		proxyStatus.Params.Add("rcode", "Negative response")
	} else {
		proxyStatus.Params.Add("rcode", "SERVFAIL")
	}
}

// NewProxyStatusItem builds a Proxy-Status item for CONNECT-UDP server responses (RFC 9209).
func NewProxyStatusItem(authority string) httpsfv.Item {
	return httpsfv.NewItem(authority)
}

// sanitizeProxyStatusDetails keeps Proxy-Status details marshalable as an sf-string
// (RFC 8941: ASCII 0x20–0x7E only; joined/OS DNS errors often include newlines or non-ASCII).
func sanitizeProxyStatusDetails(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r <= unicode.MaxASCII && r >= 0x20 && r != 0x7f:
			return r
		default:
			return -1
		}
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// WriteProxyStatusHeader marshals Proxy-Status on the HTTP response (RFC 9209).
func WriteProxyStatusHeader(w http.ResponseWriter, proxyStatus *httpsfv.Item, err error) error {
	if err != nil {
		if d := sanitizeProxyStatusDetails(err.Error()); d != "" {
			proxyStatus.Params.Add("details", d)
		}
	}
	val, marshalErr := httpsfv.Marshal(proxyStatus)
	if marshalErr != nil {
		// Last resort: emit authority-only item so clients still see Proxy-Status.
		fallback := httpsfv.NewItem(proxyStatus.Value)
		if v, err2 := httpsfv.Marshal(fallback); err2 == nil {
			w.Header().Add("Proxy-Status", v)
		}
		return marshalErr
	}
	w.Header().Add("Proxy-Status", val)
	return err
}

// AddProxyStatusNextHopHeader sets Proxy-Status next-hop on a successful CONNECT-UDP response (RFC 9209).
func AddProxyStatusNextHopHeader(w http.ResponseWriter, authorityHost, target string) error {
	item := httpsfv.NewItem(authorityHost)
	item.Params.Add("next-hop", target)
	val, err := httpsfv.Marshal(item)
	if err != nil {
		return err
	}
	w.Header().Add("Proxy-Status", val)
	return nil
}

// ProxyStatusNextHopUDP parses Proxy-Status next-hop from a CONNECT-UDP response (RFC 9209).
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
