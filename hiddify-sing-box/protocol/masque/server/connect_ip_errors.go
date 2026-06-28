package server

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
)

const defaultConnectIPRouteSetupTimeout = 2 * time.Second

// ConnectIPRouteSetupTimeout bounds AssignAddresses + AdvertiseRoute during CONNECT-IP bootstrap.
// Override via MASQUE_CONNECT_IP_ROUTE_SETUP_TIMEOUT (e.g. "5s") for slow links or docker restart.
func ConnectIPRouteSetupTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_ROUTE_SETUP_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultConnectIPRouteSetupTimeout
}

// ConnectIPRequestErrorHTTPStatus maps connect-ip-go parse errors to HTTP status codes.
func ConnectIPRequestErrorHTTPStatus(err error) int {
	var perr *connectip.RequestParseError
	if errors.As(err, &perr) {
		return perr.HTTPStatus
	}
	return 400
}

// ConnectIPRequestErrorClass maps HTTP status to transport error class.
func ConnectIPRequestErrorClass(status int) session.ErrorClass {
	switch status {
	case 400, 501:
		return session.ErrorClassCapability
	default:
		return session.ErrorClassUnknown
	}
}

// ConnectIPServerWriteErrorClass maps packet-plane WritePacket failures to lifecycle vs fatal classes.
// Reason keys from connectip.ClassifyWriteError correlate with CONNECT_IP_OBS write_fail_reason totals.
func ConnectIPServerWriteErrorClass(err error) session.ErrorClass {
	if err == nil {
		return session.ErrorClassUnknown
	}
	var closeErr *connectip.CloseError
	if errors.As(err, &closeErr) && closeErr.Remote {
		return session.ErrorClassLifecycle
	}
	switch cip.ClassifyWriteError(err) {
	case "closed", "canceled":
		return session.ErrorClassLifecycle
	case "capability_flow_forwarding_unsupported":
		return session.ErrorClassCapability
	case "deadline_exceeded", "timeout", "mtu":
		return session.ErrorClassTransport
	default:
		return session.ErrorClassUnknown
	}
}

// ConnectIPRouteAdvertiseErrorClass maps route advertise failures to error class.
func ConnectIPRouteAdvertiseErrorClass(err error) session.ErrorClass {
	if err == nil {
		return session.ErrorClassUnknown
	}
	if errors.Is(err, net.ErrClosed) {
		return session.ErrorClassLifecycle
	}
	if errors.Is(err, connectip.ErrInvalidRouteAdvertisement) {
		return session.ErrorClassCapability
	}
	return session.ErrorClassTransport
}
