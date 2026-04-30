package masque

import (
	"errors"

	"github.com/sagernet/sing-box/option"
)

type TCPPath string

const (
	TCPPathConnectStream TCPPath = "connect_stream"
	TCPPathConnectIP     TCPPath = "connect_ip"
	TCPPathAuto          TCPPath = "auto"
)

func selectTCPPath(options ClientOptions) TCPPath {
	switch normalizeTCPTransport(options.TCPTransport) {
	case option.MasqueTCPTransportConnectStream:
		return TCPPathConnectStream
	case option.MasqueTCPTransportConnectIP:
		return TCPPathConnectIP
	default:
		return TCPPathAuto
	}
}

func fallbackAllowedForError(options ClientOptions, network string, err error) bool {
	if options.FallbackPolicy != option.MasqueFallbackPolicyDirectExplicit {
		return false
	}
	if options.TCPMode == option.MasqueTCPModeStrictMasque {
		return false
	}
	if !isTCPNetwork(network) {
		return false
	}
	class := ClassifyError(err)
	return class == ErrorClassCapability || class == ErrorClassDial || class == ErrorClassTCPStackInit || class == ErrorClassTransport
}

func classifyTCPNotImplemented(path TCPPath) error {
	switch path {
	case TCPPathConnectIP:
		return ErrTCPOverConnectIP
	case TCPPathConnectStream:
		return ErrTCPConnectStreamFailed
	default:
		return ErrTCPPathNotImplemented
	}
}

func wrapPolicyDenied(err error) error {
	if err == nil {
		return ErrPolicyFallbackDenied
	}
	if errors.Is(err, ErrPolicyFallbackDenied) {
		return err
	}
	return errors.Join(ErrPolicyFallbackDenied, err)
}
