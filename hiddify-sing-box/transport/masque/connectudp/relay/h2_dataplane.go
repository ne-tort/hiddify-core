package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

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
	return frame.CheckConnectUDPUDPPayload(n, 0)
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
		if err := frame.CheckConnectUDPUDPPayload(len(payload), 0); err != nil {
			return err
		}
		if relayStatsEnabled() {
			globalUDPRelayStats.c2sDatagramIn.Add(1)
		}
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
		if relayStatsEnabled() {
			globalUDPRelayStats.c2sUDPPayloadOut.Add(1)
		}
		if signalReady != nil {
			signalReady()
		}
		return nil
	}
	for {
		select {
		case <-r.Context().Done():
			// Client Cancel/Close often races END_STREAM: TCP already delivered DATA but
			// stream context dies before we peel. Drain what is already buffered / readable.
			return drainH2UplinkAfterCancel(br, readBuf, pending, onward, signalReady, onICMP, relayOnward)
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
				if relayStatsEnabled() && uperr != nil {
					globalUDPRelayStats.c2sDropMalformed.Add(1)
				}
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

// drainH2UplinkAfterCancel peels capsules already buffered / still readable after stream cancel.
// Client PacketConn.Close often cancels r.Context while TCP already delivered DATA; returning
// immediately here dropped those capsules (docker paced write_ok≫c2s_in at 300+ Mbit).
func drainH2UplinkAfterCancel(
	br *bufio.Reader,
	readBuf []byte,
	pending []byte,
	onward H2UplinkOnward,
	signalReady func(),
	onICMP func() error,
	relayOnward func([]byte) error,
) error {
	// Fallback when client cancels before peer peel finishes; primary barrier is
	// client uploadPeerPeelGrace before Body.Close / stream cancel.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		progress := false
		for len(pending) > 0 {
			if udpPayload, consumed, ok := h2c.TryConsumeDatagramCapsule512Wire(pending); ok {
				pending = pending[consumed:]
				progress = true
				if err := relayOnward(udpPayload); err != nil {
					return err
				}
				continue
			}
			inner, consumed, perr := h2c.ParseNextDatagramCapsuleWire(pending)
			if perr != nil || consumed == 0 {
				break
			}
			pending = pending[consumed:]
			progress = true
			if inner == nil {
				continue
			}
			udpPayload, ok, uperr := frame.ParseHTTPDatagramUDP(inner)
			if uperr != nil || !ok || len(udpPayload) == 0 {
				if len(udpPayload) == 0 && signalReady != nil {
					signalReady()
				}
				continue
			}
			if err := relayOnward(udpPayload); err != nil {
				return err
			}
		}
		if _, err := onward.Flush(); err != nil {
			return err
		}
		nr, err := br.Read(readBuf)
		if nr > 0 {
			pending = append(pending, readBuf[:nr]...)
			progress = true
			continue
		}
		if err != nil || !progress {
			return nil
		}
	}
	return nil
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
		if relayStatsEnabled() {
			globalUDPRelayStats.s2cUDPIn.Add(1)
		}
		if err := validateH2DownlinkPayloadLen(n); err != nil {
			if relayStatsEnabled() {
				globalUDPRelayStats.s2cDropOversize.Add(1)
			}
			return err
		}
		if err := downlink.WriteUDPPayloadAsCapsules(buf[:n]); err != nil {
			if relayStatsEnabled() {
				globalUDPRelayStats.s2cDropSendFail.Add(1)
			}
			return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
		}
		if relayStatsEnabled() {
			globalUDPRelayStats.s2cDatagramOut.Add(1)
		}
	}
}

// RelayH2ConnectDownlinkFountain appends RFC9297 wire and flushes once per onward UDP
// RX batch (AUDIT B7 / F2.5). Append itself does not byte-threshold flush.
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
		appended := 0
		for _, payload := range payloads {
			if relayStatsEnabled() {
				globalUDPRelayStats.s2cUDPIn.Add(1)
			}
			if vErr := validateH2DownlinkPayloadLen(len(payload)); vErr != nil {
				if relayStatsEnabled() {
					globalUDPRelayStats.s2cDropOversize.Add(1)
				}
				return vErr
			}
			if aErr := downlink.AppendUDPPayloadAsCapsules(payload); aErr != nil {
				if relayStatsEnabled() {
					globalUDPRelayStats.s2cDropSendFail.Add(1)
				}
				return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", aErr)
			}
			appended++
		}
		// AUDIT A6 / TASKS F0.3: count s2c_out only after successful wire flush (not after Append).
		if appended > 0 {
			if fErr := downlink.FlushPending(); fErr != nil {
				if relayStatsEnabled() {
					globalUDPRelayStats.s2cDropSendFail.Add(uint64(appended))
				}
				return fmt.Errorf("masque h2 dataplane connect-udp server down flush: %w", fErr)
			}
			if relayStatsEnabled() {
				globalUDPRelayStats.s2cDatagramOut.Add(uint64(appended))
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
