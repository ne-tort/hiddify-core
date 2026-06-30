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

func (s *Proxy) proxyConnSend(ctx context.Context, conn *net.UDPConn, str h3C2SStream) error {
	if ctx == nil {
		ctx = context.Background()
	}
	onward := NewOnwardUDPWriter(conn)
	var drainer tryDrainHTTPDatagrams
	if dr, ok := any(str).(tryDrainHTTPDatagrams); ok {
		drainer = dr
	}
	var icmpRelay func() error
	if sender, ok := any(str).(h3DatagramSender); ok {
		icmpRelay = func() error { return sender.SendDatagram(contextIDZero) }
	}
	relayICMP := func(icmp bool) error {
		if !icmp || icmpRelay == nil {
			return nil
		}
		relayErr := icmpRelay()
		if relayErr == nil || isTransientHTTPDatagramSendError(relayErr) {
			return nil
		}
		return relayErr
	}
	flushOnward := func() error {
		icmp, err := onward.Flush()
		if err != nil {
			return err
		}
		return relayICMP(icmp)
	}
	defer func() { _ = flushOnward() }()

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
		icmp, err := onward.Queue(udpPayload)
		if err != nil {
			return err
		}
		return relayICMP(icmp)
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
		if forwarded > 0 {
			if err := flushOnward(); err != nil {
				return forwarded, err
			}
		}
		return forwarded, nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		forwarded, drainErr := drainQueued()
		if drainErr != nil {
			return drainErr
		}
		if forwarded > 0 {
			recvBackoff.onProgress()
			continue
		}
		data, err := str.ReceiveDatagram(ctx)
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
		if _, err := drainQueued(); err != nil {
			return err
		}
		if err := flushOnward(); err != nil {
			return err
		}
	}
}
