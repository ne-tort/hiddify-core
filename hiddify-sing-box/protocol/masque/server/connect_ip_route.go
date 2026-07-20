package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
)

// connectIPRouteActive counts live RouteConnectIPBlocked handlers for graceful shutdown drain.
var connectIPRouteActive atomic.Int32

// ConnectIPRouteActiveCount reports in-flight RouteConnectIPBlocked handlers (for shutdown drain).
func ConnectIPRouteActiveCount() int32 {
	return connectIPRouteActive.Load()
}

func waitConnectIPRoutesDrained(timeout time.Duration) bool {
	if timeout <= 0 {
		return connectIPRouteActive.Load() == 0
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if connectIPRouteActive.Load() == 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return connectIPRouteActive.Load() == 0
}

// DataplaneContext returns a context for CONNECT-IP packet-plane work that does not
// propagate cancellation from the inbound HTTP request. sing-box Router forwards the same ctx into
// matchRule and outbound packet handlers; req.Context may cancel independently of relay lifetime.
func DataplaneContext(reqCtx context.Context) context.Context {
	return context.WithoutCancel(reqCtx)
}

// RouteConnectIPBlocked keeps the HTTP handler alive until the CONNECT-IP packet-plane
// relay ends. On HTTP/3 the stream is hijacked via http3.HTTPStreamer inside connect-ip Proxy,
// so ending the handler does not close the QUIC stream. On HTTP/2 Extended CONNECT there is no
// hijack; if the handler returned immediately, net/http would finalize the response and tear down
// the CONNECT stream while RoutePacketConnectionEx goroutines were still running.
func RouteConnectIPBlocked(router adapter.Router, reqCtx context.Context, packetConn *ConnectIPNetPacketConn, metadata adapter.InboundContext, logger log.ContextLogger, opts option.MasqueEndpointOptions, onwardDialer net.Dialer) {
	connectIPRouteActive.Add(1)
	defer connectIPRouteActive.Add(-1)

	done := make(chan struct{})
	var once sync.Once
	notify := func() { once.Do(func() { close(done) }) }
	onClose := func(err error) {
		if err != nil && !errors.Is(err, context.Canceled) && logger != nil {
			logger.DebugContext(reqCtx, fmt.Sprintf("masque connect-ip route closed err=%v error_class=%s parse_drop_total=%d", err, ConnectIPServerWriteErrorClass(err), ConnectIPServerParseDropTotal()))
		}
		_ = packetConn.Close()
		notify()
	}
	// P1-5 LOCK: prod CONNECT-IP server dataplane = S2 terminate (TCP+UDP) via
	// forwarder.RunConnectIPTCPPacketPlaneForwarder — not transparent L3 IP forward.
	// RoutePacketConnectionEx is unused here: it models extracted UDP payloads and drops
	// TCP SYNs (would tear down the session). Transparent L3 onward = optional future mode
	// (FOCUS-04 IP-SRV-L3), not the default product path.
	_ = router
	_ = metadata
	fwdCtx := DataplaneContext(reqCtx)
	fwdOpts := fwd.ConnectIPTCPForwarderOptions{
		AllowPrivateTargets: opts.AllowPrivateTargets,
		AllowedTargetPorts:  opts.AllowedTargetPorts,
		BlockedTargetPorts:  opts.BlockedTargetPorts,
		Dialer:              onwardDialer,
	}
	go func() {
		err := fwd.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, packetConn.Conn, fwdOpts)
		onClose(err)
	}()
	// P4-5: DataplaneContext is WithoutCancel (Router lifetime ≠ HTTP cancel), but when the
	// inbound CONNECT-IP request itself ends (client kill / QUIC stream teardown) we must
	// Close the packet conn so S2 does not sit half-dead under MaxIdleTimeout=24h.
	go func() {
		select {
		case <-reqCtx.Done():
			_ = packetConn.Close()
		case <-done:
		}
	}()
	<-done
}
