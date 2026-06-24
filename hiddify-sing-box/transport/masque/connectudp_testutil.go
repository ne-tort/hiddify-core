package masque

import (
	"context"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"
)

// trackConnectUDPGoroutines fails the test if goroutines remain after cleanup (selector/outbound close contract).
func trackConnectUDPGoroutines(t *testing.T) {
	t.Helper()
	runtime.GC()
	start := goroutineCount()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			runtime.GC()
			if goroutineCount() <= start {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		end := goroutineCount()
		if end > start {
			t.Fatalf("connect-udp goroutine leak: start=%d end=%d\n%s", start, end, goroutineStacks())
		}
	})
}

func goroutineCount() int {
	return pprof.Lookup("goroutine").Count()
}

func goroutineStacks() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}


// ConnectUDPTestFactory is the exported session factory for connectudp integration tests.
type ConnectUDPTestFactory = CoreClientFactory

// NewConnectUDPTestSession builds a core MASQUE client session for CONNECT-UDP gate/localize tests.
func NewConnectUDPTestSession(ctx context.Context, opts ClientOptions) (ClientSession, error) {
	return (CoreClientFactory{}).NewSession(ctx, opts)
}

// ResetConnectUDPH2TransportForTest closes the cached CONNECT-UDP H2 http2.Transport on a session.
// Synth tests reuse CoreClientFactory sessions in-process; reset avoids stale pooled conns between cases.
func ResetConnectUDPH2TransportForTest(sess ClientSession) {
	s, ok := sess.(*coreSession)
	if !ok || s == nil {
		return
	}
	s.Mu.Lock()
	s.resetH2UDPTransportLockedAssumeMu()
	s.Mu.Unlock()
}

// closeConnectUDPTestSession closes a synth session and resets H2 transport cache when applicable.
func closeConnectUDPTestSession(sess ClientSession) {
	if sess == nil {
		return
	}
	_ = sess.Close()
	ResetConnectUDPH2TransportForTest(sess)
}
