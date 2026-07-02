package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/transport/masque/connectudp/h3quic"
)

func h3C2SUDPFlushMinBatch() int {
	if runtime.GOOS == "linux" {
		return h3C2SUDPFlushMinBatchLinux
	}
	return 1
}

// h3C2SStream is the HTTP/3 client→UDP relay ingress (ReceiveDatagram).
type h3C2SStream interface {
	ReceiveDatagram(context.Context) ([]byte, error)
}

// proxyConnSend relays HTTP/3 DATAGRAMs to onward UDP (upstream masque-go/proxy.go sync shape).
func (s *Proxy) proxyConnSend(ctx context.Context, conn *net.UDPConn, str h3C2SStream) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var icmpRelay func() error
	if sender, ok := any(str).(h3DatagramSender); ok {
		icmpRelay = func() error { return sender.SendDatagram(frame.ContextIDZeroWire) }
	}
	writer := newH3C2SUDPWriter(conn, icmpRelay)
	drainer, _ := str.(h3quic.TryDrainHTTPDatagrams)

	statsOn := relayStatsEnabled()

	var payloadBatch [h3C2SUDPSendBatchMax][]byte
	batchCount := 0

	var drainAll func() error
	var flushC2SBatch func() error

	relayEnqueue := func(raw []byte) error {
		udpPayload, ok, perr := relayHTTPDatagramUDPPayload(raw)
		if perr != nil {
			quic.ReleaseMasqueDatagramReceiveBuffer(raw)
			if errors.Is(perr, io.EOF) {
				return io.EOF
			}
			if statsOn {
				globalUDPRelayStats.c2sDropMalformed.Add(1)
			}
			diag.Logf("dropping malformed HTTP datagram on C2S relay: %v", perr)
			return nil
		}
		if !ok {
			quic.ReleaseMasqueDatagramReceiveBuffer(raw)
			return nil
		}
		if len(udpPayload) == 0 {
			quic.ReleaseMasqueDatagramReceiveBuffer(raw)
			return nil
		}
		if err := frame.ValidateProxiedUDPPayloadLen(len(udpPayload)); err != nil {
			quic.ReleaseMasqueDatagramReceiveBuffer(raw)
			return err
		}
		if relayExceedsMTUCap(len(udpPayload)) {
			quic.ReleaseMasqueDatagramReceiveBuffer(raw)
			if statsOn {
				globalUDPRelayStats.c2sDropOversize.Add(1)
			}
			diag.Logf("dropping UDP packet larger than MTU")
			return nil
		}
		if statsOn {
			globalUDPRelayStats.c2sDatagramIn.Add(1)
			globalUDPRelayStats.c2sUDPPayloadOut.Add(1)
		}
		// Copy before Release: QUIC receive lease must not outlive subsliced udpPayload in batch queue.
		payloadBatch[batchCount] = append([]byte(nil), udpPayload...)
		quic.ReleaseMasqueDatagramReceiveBuffer(raw)
		batchCount++
		if batchCount >= h3C2SUDPSendBatchMax {
			return flushC2SBatch()
		}
		return nil
	}

	drainAll = func() error {
		if drainer == nil {
			return nil
		}
		for {
			raw, ok := drainer.TryReceiveDatagram()
			if !ok {
				break
			}
			if err := relayEnqueue(raw); err != nil {
				return err
			}
		}
		return nil
	}

	flushC2SBatch = func() error {
		for batchCount > 0 {
			n := batchCount
			if n > h3C2SOnwardFlushChunk {
				n = h3C2SOnwardFlushChunk
			}
			if err := writer.writePayloadBatch(payloadBatch[:n]); err != nil {
				return err
			}
			if tail := batchCount - n; tail > 0 {
				copy(payloadBatch[:tail], payloadBatch[n:batchCount])
			}
			batchCount -= n
			if err := drainAll(); err != nil {
				return err
			}
		}
		return nil
	}

	flushC2SBatchIfReady := func(force bool) error {
		if batchCount == 0 {
			return nil
		}
		if !force && batchCount < h3C2SUDPFlushMinBatch() {
			return nil
		}
		return flushC2SBatch()
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := str.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return flushC2SBatch()
			}
			if isTransientHTTPDatagramReceiveError(err) {
				if err := drainAll(); err != nil {
					return err
				}
				if err := flushC2SBatchIfReady(true); err != nil {
					return err
				}
				runtime.Gosched()
				continue
			}
			return err
		}
		if err := relayEnqueue(data); err != nil {
			return err
		}
		if err := drainAll(); err != nil {
			return err
		}
		if err := flushC2SBatchIfReady(false); err != nil {
			return err
		}
		wakeH3RelayAfterC2SConsume(str)
	}
}

// relayHTTPDatagramUDPPayload extracts proxied UDP payload from an HTTP datagram (RFC 9297 / MASQUE).
func relayHTTPDatagramUDPPayload(raw []byte) (payload []byte, ok bool, err error) {
	return frame.ParseHTTPDatagramUDPFast(raw)
}
