package relay

import (
	"context"
	"errors"
	"net"
	"runtime"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/transport/masque/connectudp/h3quic"
)

type h3DatagramSender interface {
	SendDatagram([]byte) error
}

// h3DatagramBatchSender is the http3 Stream/RequestStream S2C path:
// enqueue without per-packet QUIC wake, then one FlushProxiedIPDatagramSend per RX batch
// (H2 Fountain FlushPending parity — cuts wake/PPS ceiling on WAN).
type h3DatagramBatchSender interface {
	h3DatagramSender
	SendDatagramNoWake([]byte) error
	FlushProxiedIPDatagramSend()
}

const h3DownlinkUDPBatchWire = 32 * 1024

// h3S2CSendBacklogSoftLimit matches client C2S soft backlog.
// Without it, server S2C enqueues fountain UDP into the unreliable QUIC DATAGRAM
// send queue faster than the path can carry → s2c_dgram_out≈s2c_udp_in but client rx≪sent.
const h3S2CSendBacklogSoftLimit = 256

func h3S2CSoftLimit() int {
	return h3S2CSendBacklogSoftLimit
}

type h3DatagramSendBacklog interface {
	DatagramSendBacklog() int
}

func awaitH3S2CSendDrain(str h3DatagramSender) {
	b, ok := str.(h3DatagramSendBacklog)
	if !ok || b == nil {
		return
	}
	batcher, _ := str.(h3DatagramBatchSender)
	limit := h3S2CSoftLimit()
	for spin := 0; b.DatagramSendBacklog() >= limit; spin++ {
		if batcher != nil {
			batcher.FlushProxiedIPDatagramSend()
		} else {
			wakeH3RelayAfterS2CSendPressure(str)
		}
		if spin&63 == 63 {
			time.Sleep(time.Microsecond)
		} else {
			runtime.Gosched()
		}
		if spin >= h3quic.TransientPressureMaxSpins*64 {
			return
		}
	}
}

// proxyConnReceive relays onward UDP to HTTP/3 DATAGRAMs (upstream masque-go/proxy.go proxyConnReceive + RFC validate).
// UDP socket drain batches reads; when str supports NoWake, one QUIC send wake per RX batch (not per packet).
func proxyConnReceive(ctx context.Context, conn *net.UDPConn, str h3DatagramSender) error {
	if ctx == nil {
		ctx = context.Background()
	}
	buf := make([]byte, RelayMaxUDPPayloadBytes()+1)
	ctx0Len := len(frame.ContextIDZeroWire)
	wire := make([]byte, ctx0Len+cap(buf))
	copy(wire, frame.ContextIDZeroWire)
	statsOn := relayStatsEnabled()
	batcher, _ := str.(h3DatagramBatchSender)
	for {
		payloads, err := readOnwardUDPBatch(ctx, conn, buf, h3DownlinkUDPBatchWire, onwardUDPWireLenRaw)
		if err != nil {
			if isRelayBatchContextDone(err) {
				return nil
			}
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
		batchWire := 0
		batchPkts := 0
		for _, payload := range payloads {
			n, sendErr := 0, error(nil)
			if batcher != nil {
				n, sendErr = relayH3S2CPayloadNoWake(batcher, wire, ctx0Len, payload, statsOn)
			} else {
				n, sendErr = relayH3S2CPayload(str, wire, ctx0Len, payload, statsOn)
			}
			if sendErr != nil {
				if batcher != nil && batchPkts > 0 {
					flushH3S2CBatch(batcher, batchWire, statsOn)
				}
				return sendErr
			}
			if n > 0 {
				batchPkts++
				batchWire += n
			}
		}
		if batcher != nil && batchPkts > 0 {
			flushH3S2CBatch(batcher, batchWire, statsOn)
		}
		if err != nil {
			if isRelayBatchContextDone(err) {
				return nil
			}
			return err
		}
	}
}

func flushH3S2CBatch(batcher h3DatagramBatchSender, wireBytes int, statsOn bool) {
	batcher.FlushProxiedIPDatagramSend()
	if statsOn {
		RecordS2CFlush(wireBytes)
	}
}

func relayH3S2CPayload(str h3DatagramSender, wire []byte, ctx0Len int, payload []byte, statsOn bool) (int, error) {
	n := len(payload)
	if n == 0 {
		return 0, nil
	}
	if relayExceedsMTUCap(n) {
		if statsOn {
			globalUDPRelayStats.s2cDropOversize.Add(1)
		}
		diag.Logf("dropping UDP packet larger than MTU")
		return 0, nil
	}
	if err := frame.ValidateProxiedUDPPayloadLen(n); err != nil {
		return 0, err
	}
	if statsOn {
		globalUDPRelayStats.s2cUDPIn.Add(1)
	}
	copy(wire[ctx0Len:], payload)
	wireLen := ctx0Len + n
	if err := sendH3S2CDatagram(str, wire[:wireLen], statsOn); err != nil {
		return 0, err
	}
	return wireLen, nil
}

func relayH3S2CPayloadNoWake(str h3DatagramBatchSender, wire []byte, ctx0Len int, payload []byte, statsOn bool) (int, error) {
	n := len(payload)
	if n == 0 {
		return 0, nil
	}
	if relayExceedsMTUCap(n) {
		if statsOn {
			globalUDPRelayStats.s2cDropOversize.Add(1)
		}
		diag.Logf("dropping UDP packet larger than MTU")
		return 0, nil
	}
	if err := frame.ValidateProxiedUDPPayloadLen(n); err != nil {
		return 0, err
	}
	if statsOn {
		globalUDPRelayStats.s2cUDPIn.Add(1)
	}
	copy(wire[ctx0Len:], payload)
	wireLen := ctx0Len + n
	if err := sendH3S2CDatagramNoWake(str, wire[:wireLen], statsOn); err != nil {
		return 0, err
	}
	return wireLen, nil
}

func sendH3S2CDatagram(str h3DatagramSender, data []byte, statsOn bool) error {
	for spin := 0; spin < h3quic.TransientPressureMaxSpins; spin++ {
		awaitH3S2CSendDrain(str)
		err := str.SendDatagram(data)
		if err == nil {
			if statsOn {
				globalUDPRelayStats.s2cDatagramOut.Add(1)
			}
			recordRelayS2CSendSpins(spin)
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

func sendH3S2CDatagramNoWake(str h3DatagramBatchSender, data []byte, statsOn bool) error {
	for spin := 0; spin < h3quic.TransientPressureMaxSpins; spin++ {
		awaitH3S2CSendDrain(str)
		err := str.SendDatagramNoWake(data)
		if err == nil {
			if statsOn {
				globalUDPRelayStats.s2cDatagramOut.Add(1)
			}
			recordRelayS2CSendSpins(spin)
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
			// Mid-batch pressure: wake queued datagrams so credit can advance, then retry enqueue.
			str.FlushProxiedIPDatagramSend()
			wakeH3RelayAfterS2CSendPressure(str)
			runtime.Gosched()
			continue
		}
		if statsOn {
			globalUDPRelayStats.s2cDropSendFail.Add(1)
		}
		return err
	}
	return errors.New("masque h3: S2C SendDatagramNoWake transient retry exhausted")
}

func isHTTPDatagramTooLargeError(err error) bool {
	if err == nil {
		return false
	}
	var errDTL *quic.DatagramTooLargeError
	return errors.As(err, &errDTL)
}
