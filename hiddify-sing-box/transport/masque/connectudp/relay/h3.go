package relay

import (
	"errors"

	"io"

	"log"

	"net"

	"net/http"

	"sync"

	"sync/atomic"

	"github.com/dunglas/httpsfv"

	"github.com/quic-go/quic-go"

	"github.com/quic-go/quic-go/http3"

	"github.com/quic-go/quic-go/quicvarint"

	qmasque "github.com/quic-go/masque-go"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type proxyEntry struct {
	str *http3.Stream

	conn *net.UDPConn
}

func (e proxyEntry) Close() error {

	e.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))

	return errors.Join(e.str.Close(), e.conn.Close())

}

type h3DatagramSender interface {
	SendDatagram([]byte) error

	SendDatagramNoWake([]byte) error

	FlushProxiedIPDatagramSend()
}

const h3S2CDatagramBatchSize = 8

// Proxy is an RFC 9298 CONNECT-UDP proxy over HTTP/3.

type Proxy struct {
	mx sync.Mutex

	closed bool

	refCount sync.WaitGroup

	closers map[io.Closer]struct{}
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

	defer conn.Close()

	tuneMasqueUDPSocketBuffers(conn)

	if err = writeProxyStatus(nil); err != nil {

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

	str := w.(http3.HTTPStreamer).HTTPStream()

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

	http3.PrepareMasqueRelayDownloadPrimary(str)

	var s2cBatchAllowed atomic.Bool

	s2cBatchAllowed.Store(true)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {

		defer wg.Done()

		if err := s.proxyConnSend(conn, str, &s2cBatchAllowed); err != nil {

			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)

		}

		str.Close()

	}()

	go func() {

		defer wg.Done()

		if err := proxyConnReceive(conn, str, &s2cBatchAllowed); err != nil {

			s.mx.Lock()

			closed := s.closed

			s.mx.Unlock()

			if !closed {

				log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)

			}

		}

		str.Close()

	}()

	if err := skipCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) {

		s.mx.Lock()

		closed := s.closed

		s.mx.Unlock()

		if !closed {

			log.Printf("reading from request stream failed: %v", err)

		}

	}

	str.Close()

	conn.Close()

	wg.Wait()

	s.mx.Lock()

	delete(s.closers, entry)

	s.mx.Unlock()

	return nil

}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str *http3.Stream, _ *atomic.Bool) error {
	return qmasque.RelayH3ClientToUDP(conn, str)
}

// proxyConnReceive: fountain uses NoWake batch; echo-duplex uses per-packet wake after 2nd C2S.

func proxyConnReceive(conn *net.UDPConn, str h3DatagramSender, s2cBatchAllowed *atomic.Bool) error {

	b := make([]byte, len(contextIDZero)+maxUDPPayloadSize+1)

	copy(b, contextIDZero)

	pending := 0

	flush := func() {

		if pending > 0 {

			str.FlushProxiedIPDatagramSend()

			pending = 0

		}

	}

	defer flush()

	sendS2C := func(payload []byte) error {

		if s2cBatchAllowed != nil && s2cBatchAllowed.Load() {

			if err := str.SendDatagramNoWake(payload); err != nil {

				return err

			}

			pending++

			if pending >= h3S2CDatagramBatchSize {

				flush()

			}

			return nil

		}

		flush()

		return str.SendDatagram(payload)

	}

	for {

		n, err := conn.Read(b[len(contextIDZero):])

		if err != nil {

			if errors.Is(err, io.EOF) {

				return nil

			}

			if isICMPPortUnreachableUDPRead(n, err) {

				if sendErr := sendS2C(b[:len(contextIDZero)]); sendErr != nil {

					return sendErr

				}

				continue

			}

			return err

		}

		if n > maxUDPPayloadSize {

			log.Printf("dropping UDP packet larger than MTU")

			continue

		}

		if err := sendS2C(b[:len(contextIDZero)+n]); err != nil {

			return err

		}

	}

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

	s.closers = nil

	return errors.Join(errs...)

}
