package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// H2UplinkOnward batches onward UDP sends for H2 CONNECT-UDP server uplink relay.
type H2UplinkOnward interface {
	Queue(payload []byte) (icmp bool, err error)
	Flush() (icmp bool, err error)
	SendBurstViews(wire []byte, count, wireLen, payloadOff int) (icmp bool, err error)
}

// H2DownlinkCapsules writes RFC 9297 DATAGRAM capsules on the HTTP/2 response body.
type H2DownlinkCapsules interface {
	WriteUDPPayloadAsCapsules(udpPayload []byte) error
}

// H2DownlinkBatchWriter appends capsules and flushes once per relay UDP drain batch.
type H2DownlinkBatchWriter interface {
	H2DownlinkCapsules
	AppendUDPPayloadAsCapsules(udpPayload []byte) error
	FlushPending() error
}

// DirectH2OnwardWriter wraps a single-leg OnwardUDPWriter (no session mutex).
type DirectH2OnwardWriter struct {
	W *OnwardUDPWriter
}

func (o *DirectH2OnwardWriter) Queue(payload []byte) (bool, error) {
	if o == nil || o.W == nil {
		return false, errors.New("masque h2: onward writer unavailable")
	}
	return o.W.Queue(payload)
}

func (o *DirectH2OnwardWriter) Flush() (bool, error) {
	if o == nil || o.W == nil {
		return false, errors.New("masque h2: onward writer unavailable")
	}
	return o.W.Flush()
}

func (o *DirectH2OnwardWriter) SendBurstViews(wire []byte, count, wireLen, payloadOff int) (bool, error) {
	if o == nil || o.W == nil {
		return false, errors.New("masque h2: onward writer unavailable")
	}
	return o.W.SendBurstViews(wire, count, wireLen, payloadOff)
}

// DirectH2Onward is the thin single-write onward path (c2sRelayUDPWriteReliable guard anchor).
type DirectH2Onward struct {
	Conn *net.UDPConn
}

func (o *DirectH2Onward) RelayUDP(payload []byte) error {
	if o == nil || o.Conn == nil {
		return errors.New("masque h2: onward UDP unavailable")
	}
	if len(payload) == 0 {
		return nil
	}
	return c2sRelayUDPWriteReliable(o.Conn, payload, nil)
}

// RelayH2ConnectUplink scans HTTP/2 request-body DATAGRAM capsules and relays payloads onward.
func RelayH2ConnectUplink(r *http.Request, onward H2UplinkOnward, bodyBufSize int, signalReady func(), onICMP func() error) error {
	br := bufio.NewReaderSize(r.Body, bodyBufSize)
	readBuf := make([]byte, bodyBufSize)
	var pending []byte
	relayOnward := func(payload []byte) error {
		icmp, err := onward.Queue(payload)
		if icmp {
			if onICMP != nil {
				if werr := onICMP(); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after write: %w", werr)
				}
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server udp write: %w", err)
		}
		if signalReady != nil {
			signalReady()
		}
		return nil
	}
	for {
		select {
		case <-r.Context().Done():
			return nil
		default:
		}
		for len(pending) > 0 {
			if n512 := h2c.CountLeadingDatagramCapsule512Wire(pending); n512 > 0 {
				wireLen := h2c.DatagramCapsule512WireLen
				icmp, err := onward.SendBurstViews(pending, n512, wireLen, wireLen-512)
				pending = pending[n512*wireLen:]
				if icmp {
					if onICMP != nil {
						if werr := onICMP(); werr != nil {
							return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after burst: %w", werr)
						}
					}
				} else if err != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server udp burst: %w", err)
				}
				if signalReady != nil {
					signalReady()
				}
				continue
			}
			if udpPayload, consumed, ok := h2c.TryConsumeDatagramCapsule512Wire(pending); ok {
				pending = pending[consumed:]
				if err := relayOnward(udpPayload); err != nil {
					return err
				}
				continue
			}
			inner, consumed, perr := h2c.ParseNextDatagramCapsuleWire(pending)
			if perr != nil {
				return fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", perr)
			}
			if consumed == 0 {
				break
			}
			pending = pending[consumed:]
			if inner == nil {
				continue
			}
			udpPayload, ok, uperr := frame.ParseHTTPDatagramUDP(inner)
			if uperr != nil || !ok {
				continue
			}
			if len(udpPayload) == 0 {
				if signalReady != nil {
					signalReady()
				}
				continue
			}
			if err := relayOnward(udpPayload); err != nil {
				return err
			}
		}
		if icmp, err := onward.Flush(); err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server udp flush: %w", err)
		} else if icmp {
			if onICMP != nil {
				if werr := onICMP(); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after flush: %w", werr)
				}
			}
		}
		if len(pending) == 0 && cap(pending) > bodyBufSize*2 {
			pending = nil
		}
		nr, err := br.Read(readBuf)
		if nr > 0 {
			pending = append(pending, readBuf[:nr]...)
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(pending) > 0 {
					return fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", io.ErrUnexpectedEOF)
				}
				return nil
			}
			return fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", err)
		}
	}
}

// RelayH2ConnectDownlink reads onward UDP, batches available datagrams, then writes capsules (h2o udp_on_read drain).
// tailFlush controls sub-threshold flush after a drain batch (echo: true on lone reply after uplink).
func RelayH2ConnectDownlink(ctx context.Context, conn *net.UDPConn, readBufSize int, downlink H2DownlinkCapsules, maxBatchWire int, tailFlush func(payloads [][]byte) bool) error {
	if maxBatchWire <= 0 {
		maxBatchWire = 32 * 1024
	}
	batchW, batchOK := downlink.(H2DownlinkBatchWriter)
	buf := make([]byte, readBufSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		payloads, err := readOnwardUDPBatch(ctx, conn, buf, maxBatchWire, onwardUDPWireLenH2Capsule)
		if err != nil {
			if isICMPPortUnreachableUDPRead(0, err) {
				if werr := downlink.WriteUDPPayloadAsCapsules(nil); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram: %w", werr)
				}
				continue
			}
			if isTransientUDPReadError(err) {
				continue
			}
			if isServeTerminalUDPConnErr(err) {
				return nil
			}
			return fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
		}
		if len(payloads) == 0 {
			continue
		}
		if batchOK {
			batchWire := 0
			for _, payload := range payloads {
				if len(payload) > 0 {
					if err := frame.ValidateProxiedUDPPayloadLen(len(payload)); err != nil {
						return err
					}
					batchWire += onwardUDPWireLenH2Capsule(payload)
				}
				if err := batchW.AppendUDPPayloadAsCapsules(payload); err != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
				}
			}
			shouldFlush := shouldFlushH2DownlinkBatch(batchWire, maxBatchWire, payloads, tailFlush)
			if shouldFlush {
				if err := batchW.FlushPending(); err != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server down flush: %w", err)
				}
			}
			continue
		}
		for _, payload := range payloads {
			if len(payload) > 0 {
				if err := frame.ValidateProxiedUDPPayloadLen(len(payload)); err != nil {
					return err
				}
			}
			if err := downlink.WriteUDPPayloadAsCapsules(payload); err != nil {
				return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
			}
		}
	}
}

func shouldFlushH2DownlinkBatch(batchWire, maxBatchWire int, payloads [][]byte, tailFlush func([][]byte) bool) bool {
	if batchWire >= maxBatchWire {
		return true
	}
	if tailFlush != nil {
		return tailFlush(payloads)
	}
	return false
}

// RelayH2ConnectDownlinkImmediate writes one RFC9297 capsule per onward UDP read (h2o 1:1 S2C).
// Asymmetric download legs use this instead of batch Append — echo-duplex needs immediate flush.
func RelayH2ConnectDownlinkImmediate(ctx context.Context, conn *net.UDPConn, readBufSize int, downlink H2DownlinkCapsules) error {
	buf := make([]byte, readBufSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			if isICMPPortUnreachableUDPRead(n, err) {
				if werr := downlink.WriteUDPPayloadAsCapsules(nil); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram: %w", werr)
				}
				continue
			}
			if isTransientUDPReadError(err) {
				continue
			}
			if isServeTerminalUDPConnErr(err) {
				return nil
			}
			return fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
		}
		if len(buf[:n]) > 0 {
			if err := frame.ValidateProxiedUDPPayloadLen(n); err != nil {
				return err
			}
		}
		if err := downlink.WriteUDPPayloadAsCapsules(buf[:n]); err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
		}
	}
}
