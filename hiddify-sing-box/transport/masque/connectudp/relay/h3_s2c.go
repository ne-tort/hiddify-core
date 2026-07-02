package relay

import (
	"context"
	"errors"
	"net"
	"runtime"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type h3DatagramSender interface {
	SendDatagram([]byte) error
}

const h3DownlinkUDPBatchWire = 32 * 1024

// proxyConnReceive relays onward UDP to HTTP/3 DATAGRAMs (upstream masque-go/proxy.go proxyConnReceive + RFC validate).
// UDP socket drain batches reads (h2o/h2 readOnwardUDPBatch parity); each payload still gets sync SendDatagram.
func proxyConnReceive(ctx context.Context, conn *net.UDPConn, str h3DatagramSender) error {
	if ctx == nil {
		ctx = context.Background()
	}
	buf := make([]byte, RelayMaxUDPPayloadBytes()+1)
	ctx0Len := len(frame.ContextIDZeroWire)
	wire := make([]byte, ctx0Len+cap(buf))
	copy(wire, frame.ContextIDZeroWire)
	statsOn := relayStatsEnabled()
	for {
		payloads, err := readOnwardUDPBatch(ctx, conn, buf, h3DownlinkUDPBatchWire, onwardUDPWireLenRaw)
		if err != nil {
			if isICMPPortUnreachableUDPRead(0, err) {
				if sendErr := str.SendDatagram(frame.ContextIDZeroWire); sendErr != nil {
					return sendErr
				}
				continue
			}
			if isTransientUDPReadError(err) {
				continue
			}
			if isServeTerminalUDPConnErr(err) {
				return nil
			}
			if len(payloads) == 0 {
				return err
			}
		}
		for _, payload := range payloads {
			if err := relayH3S2CPayload(str, wire, ctx0Len, payload, statsOn); err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
}

func relayH3S2CPayload(str h3DatagramSender, wire []byte, ctx0Len int, payload []byte, statsOn bool) error {
	n := len(payload)
	if n == 0 {
		return nil
	}
	if relayExceedsMTUCap(n) {
		if statsOn {
			globalUDPRelayStats.s2cDropOversize.Add(1)
		}
		diag.Logf("dropping UDP packet larger than MTU")
		return nil
	}
	if err := frame.ValidateProxiedUDPPayloadLen(n); err != nil {
		return err
	}
	if statsOn {
		globalUDPRelayStats.s2cUDPIn.Add(1)
	}
	copy(wire[ctx0Len:], payload)
	return sendH3S2CDatagram(str, wire[:ctx0Len+n], statsOn)
}

func sendH3S2CDatagram(str h3DatagramSender, data []byte, statsOn bool) error {
	for spin := 0; spin < h3TransientRetryMaxSpins; spin++ {
		err := str.SendDatagram(data)
		if err == nil {
			if statsOn {
				globalUDPRelayStats.s2cDatagramOut.Add(1)
			}
			return nil
		}
		if isHTTPDatagramTooLargeError(err) {
			if statsOn {
				globalUDPRelayStats.s2cDropOversize.Add(1)
			}
			diag.Logf("dropping UDP packet on S2C relay: datagram too large")
			return nil
		}
		if isTransientHTTPDatagramSendError(err) {
			wakeH3RelayAfterS2CSendPressure(str)
			runtime.Gosched()
			continue
		}
		if statsOn {
			globalUDPRelayStats.s2cDropSendFail.Add(1)
		}
		return err
	}
	return errors.New("masque h3: S2C SendDatagram transient retry exhausted")
}

func isHTTPDatagramTooLargeError(err error) bool {
	if err == nil {
		return false
	}
	var errDTL *quic.DatagramTooLargeError
	return errors.As(err, &errDTL)
}
