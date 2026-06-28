package relay

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

// h3C2SStream is the HTTP/3 client→UDP relay ingress (ReceiveDatagram + optional try-drain).
type h3C2SStream interface {
	ReceiveDatagram(context.Context) ([]byte, error)
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
		if err := frame.ValidateProxiedUDPPayloadLen(len(udpPayload)); err != nil {
			return err
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
