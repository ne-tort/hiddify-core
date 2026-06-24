package relay

import (
	"context"
	"errors"

	"io"

	"log"

	"net"

	"net/http"

	"sync"

	"time"

	"github.com/dunglas/httpsfv"

	"github.com/quic-go/quic-go"

	"github.com/quic-go/quic-go/http3"

	"github.com/quic-go/quic-go/quicvarint"

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
}

// h3C2SStream is the HTTP/3 client→UDP relay ingress (ReceiveDatagram + optional try-drain).
type h3C2SStream interface {
	ReceiveDatagram(context.Context) ([]byte, error)
}

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

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {

		defer wg.Done()

		if err := s.proxyConnSend(conn, str); err != nil {

			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)

		}

		str.Close()

	}()

	go func() {

		defer wg.Done()

		if err := proxyConnReceive(conn, str); err != nil {

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

	if s.closers != nil {

		delete(s.closers, entry)

	}

	s.mx.Unlock()

	return nil

}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str h3C2SStream) error {
	var drainer tryDrainHTTPDatagrams
	if dr, ok := any(str).(tryDrainHTTPDatagrams); ok {
		drainer = dr
	}
	var icmpRelay func() error
	if sender, ok := any(str).(h3DatagramSender); ok {
		icmpRelay = func() error { return sender.SendDatagram(contextIDZero) }
	}
	var recvBackoff transientPressureBackoff
	forwardC2SDatagram := func(data []byte) error {
		defer quic.ReleaseMasqueDatagramReceiveBuffer(data)
		udpPayload, ok, perr := frame.ParseHTTPDatagramUDP(data)
		if perr != nil {
			if errors.Is(perr, io.EOF) {
				return nil
			}
			log.Printf("dropping malformed HTTP datagram on C2S relay: %v", perr)
			return nil
		}
		if !ok || len(udpPayload) == 0 {
			return nil
		}
		if len(udpPayload) > maxUDPPayloadSize {
			log.Printf("dropping UDP packet larger than MTU")
			return nil
		}
		return c2sRelayUDPWrite(conn, udpPayload, icmpRelay)
	}
	drainQueued := func() (int, error) {
		if drainer == nil {
			return 0, nil
		}
		forwarded := 0
		for i := 0; i < proxyConnTryDrainMax; i++ {
			data, ok := drainer.TryReceiveDatagram()
			if !ok {
				break
			}
			if err := forwardC2SDatagram(data); err != nil {
				return forwarded, err
			}
			forwarded++
		}
		return forwarded, nil
	}
	for {
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if isTransientHTTPDatagramReceiveError(err) {
				forwarded, drainErr := drainQueued()
				if drainErr != nil {
					return drainErr
				}
				if forwarded > 0 {
					recvBackoff.onProgress()
					continue
				}
				if backoff := recvBackoff.onTransientError(); backoff > 0 {
					time.Sleep(backoff)
				}
				continue
			}
			return err
		}
		if err := forwardC2SDatagram(data); err != nil {
			return err
		}
		recvBackoff.onProgress()
		if forwarded, err := drainQueued(); err != nil {
			return err
		} else if forwarded > 0 {
			recvBackoff.onProgress()
		}
	}
}

func proxyConnReceive(conn *net.UDPConn, str h3DatagramSender) error {
	b := make([]byte, len(contextIDZero)+maxUDPPayloadSize+1)
	copy(b, contextIDZero)
	var sendBackoff transientPressureBackoff
	for {
		n, err := conn.Read(b[len(contextIDZero):])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if isICMPPortUnreachableUDPRead(n, err) {
				if sendErr := str.SendDatagram(b[:len(contextIDZero)]); sendErr != nil && !isTransientHTTPDatagramSendError(sendErr) {
					return sendErr
				}
				sendBackoff.onProgress()
				continue
			}
			return err
		}
		if n > maxUDPPayloadSize {
			log.Printf("dropping UDP packet larger than MTU")
			continue
		}
		if err := str.SendDatagram(b[:len(contextIDZero)+n]); err != nil {
			if isTransientHTTPDatagramSendError(err) {
				if backoff := sendBackoff.onTransientError(); backoff > 0 {
					time.Sleep(backoff)
				}
				continue
			}
			if isHTTPDatagramTooLargeError(err) {
				log.Printf("dropping UDP packet on S2C relay: datagram too large")
				continue
			}
			return err
		}
		sendBackoff.onProgress()
	}
}

func isHTTPDatagramTooLargeError(err error) bool {
	if err == nil {
		return false
	}
	var errDTL *quic.DatagramTooLargeError
	return errors.As(err, &errDTL)
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
