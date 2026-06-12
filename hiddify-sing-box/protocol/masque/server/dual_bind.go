package server

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

const masqueDynPortBindAttempts = 512

// DualBindConfig drives UDP+TCP collocated listen for the MASQUE server (HTTP/3 + HTTP/2).
type DualBindConfig struct {
	ListenHost        string
	ListenPort        uint16
	AuthorityH3Only   bool
	SkipUDPValidation bool
	ValidateUDP       func(net.PacketConn) error
	ListenUDP         func(network, address string) (net.PacketConn, error)
	ListenTCP         func(network, address string) (net.Listener, error)
}

// DualBindResult holds listeners from a successful dual-bind attempt.
type DualBindResult struct {
	PacketConn net.PacketConn
	TCPRaw     net.Listener
}

// DualBindMasqueListeners binds UDP for HTTP/3 and, unless AuthorityH3Only, TCP on the same port for HTTP/2.
// When ListenPort is 0, retries up to masqueDynPortBindAttempts on ephemeral TCP EADDRINUSE (Windows parallel tests).
func DualBindMasqueListeners(cfg DualBindConfig) (DualBindResult, error) {
	listenUDP := cfg.ListenUDP
	if listenUDP == nil {
		listenUDP = net.ListenPacket
	}
	listenTCP := cfg.ListenTCP
	if listenTCP == nil {
		listenTCP = net.Listen
	}
	addr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(int(cfg.ListenPort)))
	ephemeralPorts := cfg.ListenPort == 0
	maxAttempts := 1
	if ephemeralPorts {
		maxAttempts = masqueDynPortBindAttempts
	}
	var (
		result         DualBindResult
		lastTCPListenErr error
	)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		pc, udpErr := listenUDP("udp", addr)
		if udpErr != nil {
			return DualBindResult{}, fmt.Errorf("listen udp for masque server: %w", udpErr)
		}
		if !cfg.SkipUDPValidation && cfg.ValidateUDP != nil {
			if err := cfg.ValidateUDP(pc); err != nil {
				_ = pc.Close()
				return DualBindResult{}, fmt.Errorf("validate quic transport packetconn: %w", err)
			}
		}
		if cfg.AuthorityH3Only {
			result.PacketConn = pc
			return result, nil
		}
		us := pc.LocalAddr()
		uaddr, uok := us.(*net.UDPAddr)
		if !uok || uaddr == nil {
			_ = pc.Close()
			return DualBindResult{}, fmt.Errorf("masque server: UDP listener has unexpected address type %v", us)
		}
		tcpBind := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(uaddr.Port))
		tr, tcpErr := listenTCP("tcp", tcpBind)
		if tcpErr == nil {
			result.PacketConn = pc
			result.TCPRaw = tr
			return result, nil
		}
		_ = pc.Close()
		lastTCPListenErr = tcpErr
		if ephemeralPorts && EphemeralDualBindTCPRetryable(tcpErr) {
			continue
		}
		return DualBindResult{}, fmt.Errorf("listen tcp for masque server (http2 extended connect): %w", tcpErr)
	}
	err := lastTCPListenErr
	if err == nil {
		err = errors.New("masque server: UDP listen failed")
	}
	return DualBindResult{}, fmt.Errorf("listen udp for masque server: %w", err)
}
