package connectip

import (
	"errors"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type Proxy struct{}

// Proxy attaches the CONNECT-IP session to writer w. parsed was produced by ParseRequest(r, ...)
// against the configured URI template; r is needed to detect HTTP/2 vs HTTP/3 transport framing.
func (s *Proxy) Proxy(w http.ResponseWriter, r *http.Request, _ *Request) (*Conn, error) {
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	if hs, ok := w.(http3.HTTPStreamer); ok {
		str := hs.HTTPStream()
		return newProxiedConn(str, false), nil
	}
	// HTTP/3 path is taken above; remaining CONNECT-IP handlers are HTTP/2 Extended CONNECT
	// (RFC 8441). Do not require ProtoMajor==2 — some net/http versions surface CONNECT :protocol
	// with unexpected ProtoMajor while still using the H2 capsule dataplane.
	if r != nil && strings.EqualFold(extendedConnectProtocol(r), requestProtocol) {
		str := &h2ServerCapsuleStream{reqBody: r.Body, w: w}
		return newProxiedConn(str, true), nil
	}
	return nil, errors.New("connect-ip: proxy requires HTTP/3 HTTPStreamer or HTTP/2 CONNECT-IP")
}
