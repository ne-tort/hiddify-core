package connectip

import (
	"context"
	"errors"
	"log"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

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
}

// DialTCP dials TCP over the CONNECT-IP userspace netstack (tcp_transport=connect_ip).
func DialTCP(ctx context.Context, host DialTCPHost, destination M.Socksaddr) (net.Conn, error) {
	if NetstackDebugEnabled() {
		log.Printf("masque connect_ip tcp: dial request destination=%s", destination.String())
	}
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
	}
	host.UnlockSession()
	select {
	case <-ctx.Done():
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, errors.Join(Errs.Dial, context.Cause(ctx))
	default:
	}
	conn, dialErr := ns.DialContext(ctx, dest)
	if NetstackDebugEnabled() {
		log.Printf("masque connect_ip tcp: dial result destination=%s err=%v", dest.String(), dialErr)
	}
	return conn, dialErr
}
