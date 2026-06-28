package relay

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type proxyEntry struct {
	str  *http3.Stream
	conn *net.UDPConn
}

func (e proxyEntry) Close() error {
	e.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	return errors.Join(e.str.Close(), e.conn.Close())
}

// Proxy is an RFC 9298 CONNECT-UDP proxy over HTTP/3.
type Proxy struct {
	mx       sync.Mutex
	closed   bool
	refCount sync.WaitGroup
	closers  map[io.Closer]struct{}
}

func errToStatus(err error) int {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func dnsErrorToProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
	} else {
		proxyStatus.Params.Add("error", "dns_error")
		if dnsError.IsNotFound {
			proxyStatus.Params.Add("rcode", "Negative response")
		} else {
			proxyStatus.Params.Add("rcode", "SERVFAIL")
		}
	}
}

// Proxy dials a connected UDP socket and proxies the CONNECT-UDP request.
func (s *Proxy) Proxy(w http.ResponseWriter, r *frame.Request) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.mx.Unlock()

	proxyStatus := httpsfv.NewItem(r.Host)
	writeProxyStatus := func(err error) error {
		if err != nil {
			proxyStatus.Params.Add("details", err.Error())
		}
		proxyStatusVal, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", proxyStatusVal)
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToProxyStatus(&proxyStatus, dnsError)
		}
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}

	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}

	tuneMasqueUDPSocketBuffers(conn)

	if err = writeProxyStatus(nil); err != nil {
		conn.Close()
		w.WriteHeader(errToStatus(err))
		return err
	}

	return s.ProxyConnectedSocket(w, r, conn)
}

// ProxyConnectedSocket proxies on an existing connected UDP socket.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *frame.Request, conn *net.UDPConn) error {
	tuneMasqueUDPSocketBuffers(conn)

	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusInternalServerError)
		return errors.New("connectudp/relay: response writer is not http3.HTTPStreamer")
	}
	str := streamer.HTTPStream()
	entry := proxyEntry{str: str, conn: conn}
	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[entry] = struct{}{}
	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, frame.CapsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	var wg sync.WaitGroup
	var closeStream sync.Once
	var closeUDP sync.Once

	shutdownStream := func() {
		closeStream.Do(func() {
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
			_ = str.Close()
		})
	}

	shutdownUDP := func() {
		closeUDP.Do(func() { _ = conn.Close() })
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		defer shutdownStream()
		if err := s.proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
	}()

	go func() {
		defer wg.Done()
		defer shutdownStream()
		defer shutdownUDP()
		if err := proxyConnReceive(conn, str); err != nil {
			s.mx.Lock()
			closed := s.closed
			s.mx.Unlock()
			if !closed {
				log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
			}
		}
	}()

	if err := frame.SkipRequestStreamCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) {
		s.mx.Lock()
		closed := s.closed
		s.mx.Unlock()
		if !closed {
			log.Printf("reading from request stream failed: %v", err)
		}
	}

	shutdownStream()
	shutdownUDP()
	wg.Wait()
	shutdownStream()
	shutdownUDP()

	s.mx.Lock()
	if s.closers != nil {
		delete(s.closers, entry)
	}
	s.mx.Unlock()

	return nil
}

// Close closes the proxy and all proxied flows.
func (s *Proxy) Close() error {
	s.mx.Lock()
	s.closed = true
	var errs []error
	for closer := range s.closers {
		errs = append(errs, closer.Close())
	}
	s.mx.Unlock()

	s.refCount.Wait()

	s.mx.Lock()
	s.closers = nil
	s.mx.Unlock()

	return errors.Join(errs...)
}
