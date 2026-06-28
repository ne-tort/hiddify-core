package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"

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

// RelayH2ConnectDownlink reads onward UDP and writes DATAGRAM capsules on the HTTP/2 response body.
func RelayH2ConnectDownlink(ctx context.Context, conn *net.UDPConn, readBufSize int, downlink H2DownlinkCapsules) error {
	buf := make([]byte, readBufSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			if isH2ServeICMPUnreachableRead(n, err) {
				if werr := downlink.WriteUDPPayloadAsCapsules(nil); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram: %w", werr)
				}
				continue
			}
			if isH2ServeTransientReadErr(err) {
				continue
			}
			if isH2ServeTerminalConnErr(err) {
				return nil
			}
			return fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
		}
		if err := downlink.WriteUDPPayloadAsCapsules(buf[:n]); err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
		}
	}
}

func isH2ServeTransientReadErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET)
}

func isH2ServeICMPUnreachableRead(n int, err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func isH2ServeTerminalConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "pipe is being closed")
}
