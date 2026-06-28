package relay

import (
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type h3DatagramSender interface {
	SendDatagram([]byte) error
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
		if err := frame.ValidateProxiedUDPPayloadLen(n); err != nil {
			return err
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
