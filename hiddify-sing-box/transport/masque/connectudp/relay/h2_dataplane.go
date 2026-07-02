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

// H2UplinkOnward queues onward UDP sends for H2 CONNECT-UDP server uplink relay.
type H2UplinkOnward interface {
	Queue(payload []byte) (icmp bool, err error)
	Flush() (icmp bool, err error)
}

// H2DownlinkCapsules writes RFC 9297 DATAGRAM capsules on the HTTP/2 response body.
type H2DownlinkCapsules interface {
	WriteUDPPayloadAsCapsules(udpPayload []byte) error
}

// H2DownlinkAppender batches S2C capsules before HTTP/2 flush (asymmetric download fountain; not bidi echo).
type H2DownlinkAppender interface {
	H2DownlinkCapsules
	AppendUDPPayloadAsCapsules(udpPayload []byte) error
	FlushPending() error
}

const h2DownlinkBatchWire = 64 * 1024

func relayH2DownlinkICMP(downlink H2DownlinkCapsules) error {
	if err := downlink.WriteUDPPayloadAsCapsules(nil); err != nil {
		return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram: %w", err)
	}
	return nil
}

func validateH2DownlinkPayloadLen(n int) error {
	if n <= 0 {
		return nil
	}
	return frame.ValidateProxiedUDPPayloadLen(n)
}

// DirectH2OnwardUplink implements H2UplinkOnward with h2o udp_write_core immediate send (no Linux WriteBatch).
type DirectH2OnwardUplink struct {
	Conn *net.UDPConn
}

func (o *DirectH2OnwardUplink) Queue(payload []byte) (bool, error) {
	return queueH2OnwardUDP(o.Conn, payload)
}

func (o *DirectH2OnwardUplink) Flush() (bool, error) {
	return false, nil
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

// RelayH2ConnectDownlinkImmediate writes one RFC9297 capsule per onward UDP read (h2o 1:1 S2C).
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
				if werr := relayH2DownlinkICMP(downlink); werr != nil {
					return werr
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
		if err := validateH2DownlinkPayloadLen(n); err != nil {
			return err
		}
		if err := downlink.WriteUDPPayloadAsCapsules(buf[:n]); err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
		}
	}
}

// RelayH2ConnectDownlinkFountain appends RFC9297 wire with byte-threshold flush (asymmetric S2C-only leg).
// It keeps low-latency single-packet echo, but uses append batching for multi-packet bursts.
func RelayH2ConnectDownlinkFountain(ctx context.Context, conn *net.UDPConn, readBufSize int, downlink H2DownlinkAppender) error {
	if downlink == nil {
		return errors.New("masque h2 dataplane connect-udp server downlink: nil appender")
	}
	defer func() { _ = downlink.FlushPending() }()
	buf := make([]byte, readBufSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		payloads, err := readOnwardUDPBatch(ctx, conn, buf, h2DownlinkBatchWire, onwardUDPWireLenH2Capsule)
		if err != nil {
			if isRelayBatchContextDone(err) {
				return nil
			}
			if isICMPPortUnreachableUDPRead(0, err) {
				if werr := relayH2DownlinkICMP(downlink); werr != nil {
					return werr
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
				return fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
			}
		}
		for _, payload := range payloads {
			if vErr := validateH2DownlinkPayloadLen(len(payload)); vErr != nil {
				return vErr
			}
			if aErr := downlink.AppendUDPPayloadAsCapsules(payload); aErr != nil {
				return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", aErr)
			}
		}
		// Single-packet batch: low-latency flush for echo on asym download leg.
		if len(payloads) == 1 {
			if fErr := downlink.FlushPending(); fErr != nil {
				return fmt.Errorf("masque h2 dataplane connect-udp server down flush: %w", fErr)
			}
		}
		if err != nil {
			if isRelayBatchContextDone(err) {
				return nil
			}
			return err
		}
	}
}
