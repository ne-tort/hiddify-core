package connectip

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const connectIPTCPDialDefaultTimeout = 20 * time.Second

// DialTCPHost wires production CONNECT-IP TCP netstack dial from package masque (phase 17 bridge).
type DialTCPHost interface {
	ClearHTTPFallbackAfterGiveUp()
	LockSession()
	UnlockSession()
	OpenIPSessionLocked(ctx context.Context) (PacketSession, error)
	TCPNetstack() TCPNetstack
	AttachTCPNetstack(ns TCPNetstack)
	FlushTCPNetstackIngress(ns TCPNetstack)
	BumpTCPInstallInflight(delta int)
	MaybeStartConnectIPIngressLocked()
	NewTCPNetstack(ctx context.Context, session PacketSession) (TCPNetstack, error)
	OnTCPNetstackFactoryError()
	RecordTCPNetstackReady(ready bool)
	ReleaseAbandonedIPSession()
	// ResetStaleConnectIPPlaneLocked drops cached IPConn/overlay after dial timeout (remote restart).
	ResetStaleConnectIPPlaneLocked()
}

// DialTCP dials TCP over the CONNECT-IP userspace netstack (tcp_transport=connect_ip).
func DialTCP(ctx context.Context, host DialTCPHost, destination M.Socksaddr) (net.Conn, error) {
	return dialTCP(ctx, host, destination, true)
}

func dialTCP(ctx context.Context, host DialTCPHost, destination M.Socksaddr, allowRetry bool) (net.Conn, error) {
	select {
	case <-ctx.Done():
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, errors.Join(Errs.Dial, context.Cause(ctx))
	default:
	}
	dest, err := NormalizeTCPDestination(ctx, destination)
	if err != nil {
		if ctx.Err() != nil {
			host.ClearHTTPFallbackAfterGiveUp()
		}
		return nil, err
	}
	host.LockSession()
	if host.TCPNetstack() == nil {
		host.BumpTCPInstallInflight(1)
	}
	ipSess, err := host.OpenIPSessionLocked(ctx)
	if err != nil {
		if host.TCPNetstack() == nil {
			host.BumpTCPInstallInflight(-1)
		}
		host.UnlockSession()
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, err
	}
	var ns TCPNetstack
	if host.TCPNetstack() == nil {
		host.MaybeStartConnectIPIngressLocked()
		host.UnlockSession()
		newStack, nerr := host.NewTCPNetstack(ctx, ipSess)
		host.LockSession()
		if nerr != nil {
			host.RecordTCPNetstackReady(false)
			host.OnTCPNetstackFactoryError()
			host.BumpTCPInstallInflight(-1)
			host.UnlockSession()
			host.ReleaseAbandonedIPSession()
			host.ClearHTTPFallbackAfterGiveUp()
			return nil, nerr
		}
		if host.TCPNetstack() == nil {
			host.RecordTCPNetstackReady(true)
			host.AttachTCPNetstack(newStack)
			host.MaybeStartConnectIPIngressLocked()
			ns = host.TCPNetstack()
		} else {
			_ = newStack.Close()
			ns = host.TCPNetstack()
			host.FlushTCPNetstackIngress(ns)
		}
		host.BumpTCPInstallInflight(-1)
	} else {
		ns = host.TCPNetstack()
		if allowRetry {
			if err := tcpNetstackTerminalError(ns); err != nil {
				old := ns
				host.AttachTCPNetstack(nil)
				host.RecordTCPNetstackReady(false)
				host.ResetStaleConnectIPPlaneLocked()
				host.UnlockSession()
				_ = old.Close()
				return dialTCP(ctx, host, destination, false)
			}
		}
		host.MaybeStartConnectIPIngressLocked()
		host.FlushTCPNetstackIngress(ns)
	}
	host.UnlockSession()
	select {
	case <-ctx.Done():
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, errors.Join(Errs.Dial, context.Cause(ctx))
	default:
	}
	dialCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, connectIPTCPDialDefaultTimeout)
		defer cancel()
	}
	conn, dialErr := ns.DialContext(dialCtx, dest)
	if dialErr != nil {
		if allowRetry && shouldRetryDialAfterNetstackReset(dialErr) {
			host.LockSession()
			if host.TCPNetstack() == ns {
				host.AttachTCPNetstack(nil)
				host.RecordTCPNetstackReady(false)
			}
			host.ResetStaleConnectIPPlaneLocked()
			host.UnlockSession()
			_ = ns.Close()
			return dialTCP(ctx, host, destination, false)
		}
		host.ClearHTTPFallbackAfterGiveUp()
	}
	return conn, dialErr
}

func shouldRetryDialAfterNetstackReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "endpoint not connected") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "tcp dial failed") {
		return true
	}
	if errors.Is(err, Errs.Dial) || errors.Is(err, Errs.Closed) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func tcpNetstackTerminalError(ns TCPNetstack) error {
	if ns == nil {
		return nil
	}
	te, ok := ns.(interface{ TerminalError() error })
	if !ok {
		return nil
	}
	return te.TerminalError()
}
