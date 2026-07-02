package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

// h3C2SStream is the HTTP/3 client→UDP relay ingress (ReceiveDatagram).
type h3C2SStream interface {
	ReceiveDatagram(context.Context) ([]byte, error)
}

// tryDrainHTTPDatagrams is quic-go HTTP/3 non-blocking datagram dequeue (masque-go/proxy.go).
type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

const h3C2STryDrainMax = 32 // legacy cap for guards; hot path drains until empty

const h3C2SOnwardQueueDepth = 4096

type h3C2SOnwardItem struct {
	payload []byte
	raw     []byte
}

type h3C2SOnwardFlushReq struct {
	done chan error
}

// proxyConnSend relays HTTP/3 DATAGRAMs to onward UDP.
// Receive loop stays sync (masque-go shape); onward UDP runs in one worker to decouple QUIC ingress from Write pressure.
func (s *Proxy) proxyConnSend(ctx context.Context, conn *net.UDPConn, str h3C2SStream) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var icmpRelay func() error
	if sender, ok := any(str).(h3DatagramSender); ok {
		icmpRelay = func() error { return sender.SendDatagram(frame.ContextIDZeroWire) }
	}
	writer := newH3C2SUDPWriter(conn, icmpRelay)
	drainer, _ := str.(tryDrainHTTPDatagrams)

	statsOn := relayStatsEnabled()

	onwardCh := make(chan h3C2SOnwardItem, h3C2SOnwardQueueDepth)
	onwardFlush := make(chan h3C2SOnwardFlushReq, 1)
	flushDone := make(chan error, 1)
	var onwardWG sync.WaitGroup
	onwardErr := make(chan error, 1)
	onwardWG.Add(1)
	go func() {
		defer onwardWG.Done()
		var payloadBatch [h3C2SUDPSendBatchMax][]byte
		var releaseBatch [h3C2SUDPSendBatchMax][]byte
		batchCount := 0
		flushC2SBatch := func() error {
			if batchCount == 0 {
				return nil
			}
			n := batchCount
			if err := writer.writePayloadBatch(payloadBatch[:n]); err != nil {
				for i := 0; i < n; i++ {
					quic.ReleaseMasqueDatagramReceiveBuffer(releaseBatch[i])
				}
				return err
			}
			for i := 0; i < n; i++ {
				quic.ReleaseMasqueDatagramReceiveBuffer(releaseBatch[i])
			}
			batchCount = 0
			return nil
		}
		for {
			select {
			case req := <-onwardFlush:
				err := flushC2SBatch()
				req.done <- err
				if err != nil {
					onwardErr <- err
					return
				}
			case item, ok := <-onwardCh:
				if !ok {
					if err := flushC2SBatch(); err != nil {
						onwardErr <- err
					}
					return
				}
				payloadBatch[batchCount] = item.payload
				releaseBatch[batchCount] = item.raw
				batchCount++
				if batchCount >= h3C2SUDPSendBatchMax {
					if err := flushC2SBatch(); err != nil {
						onwardErr <- err
						return
					}
				}
			}
		}
	}()
	defer func() {
		close(onwardCh)
		onwardWG.Wait()
	}()

	flushOnwardBatch := func() error {
		req := h3C2SOnwardFlushReq{done: flushDone}
		select {
		case onwardFlush <- req:
		case err := <-onwardErr:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case err := <-req.done:
			return err
		case err := <-onwardErr:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

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
		select {
		case onwardCh <- h3C2SOnwardItem{payload: udpPayload, raw: raw}:
			return nil
		case err := <-onwardErr:
			quic.ReleaseMasqueDatagramReceiveBuffer(raw)
			return err
		case <-ctx.Done():
			quic.ReleaseMasqueDatagramReceiveBuffer(raw)
			return ctx.Err()
		}
	}
	drainAll := func() error {
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
	for {
		select {
		case err := <-onwardErr:
			return err
		default:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return flushOnwardBatch()
			}
			if isTransientHTTPDatagramReceiveError(err) {
				if err := drainAll(); err != nil {
					return err
				}
				if err := flushOnwardBatch(); err != nil {
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
		if err := flushOnwardBatch(); err != nil {
			return err
		}
		wakeH3RelayAfterC2SConsume(str)
	}
}

// relayHTTPDatagramUDPPayload extracts proxied UDP payload from an HTTP datagram (RFC 9297 / MASQUE).
func relayHTTPDatagramUDPPayload(raw []byte) (payload []byte, ok bool, err error) {
	return frame.ParseHTTPDatagramUDPFast(raw)
}
