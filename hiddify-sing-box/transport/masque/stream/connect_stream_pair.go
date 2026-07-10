package stream

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectStreamPairHeader correlates P2 download+upload CONNECT legs to one onward TCP.
const ConnectStreamPairHeader = "Masque-Connect-Stream-Pair"

// ErrDualLegPairNotReady is returned when the upload leg arrives before download registered the pair.
var ErrDualLegPairNotReady = errors.New("stream: dual connect leg pair not ready")

type connectStreamPairKey struct{}

// NewConnectStreamPairID returns a random pair id for one P2 dual CONNECT dial.
func NewConnectStreamPairID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ContextWithConnectStreamPair tags a CONNECT-stream dial with a P2 pair id.
func ContextWithConnectStreamPair(ctx context.Context, pairID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, connectStreamPairKey{}, pairID)
}

// ConnectStreamPairFromContext returns the P2 pair id, or "" for single bidi dial.
func ConnectStreamPairFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	pairID, _ := ctx.Value(connectStreamPairKey{}).(string)
	return pairID
}

// ConnectStreamPairFromRequest returns the P2 pair id from a CONNECT request, or "".
func ConnectStreamPairFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(ConnectStreamPairHeader))
}

// ConnectStreamAutoPairKey builds a server-side pair key when the pair header is absent.
// Safe for sequential P2 dials on one QUIC session to the same target; not for parallel
// dual connects to the same target (use ConnectStreamPairHeader then).
func ConnectStreamAutoPairKey(remoteAddr, targetHost, targetPort string) string {
	return strings.TrimSpace(remoteAddr) + "|" + strings.TrimSpace(targetHost) + "|" + strings.TrimSpace(targetPort)
}

// ConnectStreamPairKeyFromRequest returns explicit pair id or auto key for split legs.
func ConnectStreamPairKeyFromRequest(r *http.Request, targetHost, targetPort string) string {
	if r == nil {
		return ""
	}
	if pairID := ConnectStreamPairFromRequest(r); pairID != "" {
		return pairID
	}
	if leg := ConnectStreamLegFromRequest(r); leg != "" {
		return ConnectStreamAutoPairKey(r.RemoteAddr, targetHost, targetPort)
	}
	return ""
}

type dualLegOnwardEntry struct {
	conn net.Conn
	refs int32
}

type dualLegOnwardTable struct {
	mu      sync.Mutex
	entries map[string]*dualLegOnwardEntry
}

var dualLegOnwardRegistry dualLegOnwardTable

// AcquireDualLegOnward dials or reuses onward TCP for P2 dual CONNECT legs sharing one target flow.
// pairKey is ConnectStreamPairFromRequest or ConnectStreamAutoPairKey from the server handler.
func AcquireDualLegOnward(
	ctx context.Context,
	leg, pairKey string,
	dial func(context.Context) (net.Conn, error),
) (net.Conn, func(), error) {
	if leg == "" || pairKey == "" {
		conn, err := dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() { _ = conn.Close() }, nil
	}
	switch leg {
	case ConnectStreamLegDownload:
		conn, err := dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		entry := &dualLegOnwardEntry{conn: conn}
		atomic.StoreInt32(&entry.refs, 1)
		dualLegOnwardRegistry.mu.Lock()
		if dualLegOnwardRegistry.entries == nil {
			dualLegOnwardRegistry.entries = make(map[string]*dualLegOnwardEntry)
		}
		dualLegOnwardRegistry.entries[pairKey] = entry
		dualLegOnwardRegistry.mu.Unlock()
		return conn, func() { dualLegOnwardRegistry.release(pairKey, entry) }, nil
	case ConnectStreamLegUpload:
		entry, err := dualLegOnwardRegistry.waitDownload(ctx, pairKey)
		if err != nil {
			return nil, nil, err
		}
		atomic.AddInt32(&entry.refs, 1)
		return entry.conn, func() { dualLegOnwardRegistry.release(pairKey, entry) }, nil
	default:
		conn, err := dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() { _ = conn.Close() }, nil
	}
}

func (t *dualLegOnwardTable) waitDownload(ctx context.Context, pairKey string) (*dualLegOnwardEntry, error) {
	const tick = 2 * time.Millisecond
	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		t.mu.Lock()
		entry, ok := t.entries[pairKey]
		t.mu.Unlock()
		if ok {
			return entry, nil
		}
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if time.Now().After(deadline) {
			return nil, ErrDualLegPairNotReady
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(tick):
		}
	}
}

func (t *dualLegOnwardTable) release(pairKey string, entry *dualLegOnwardEntry) {
	if atomic.AddInt32(&entry.refs, -1) == 0 {
		_ = entry.conn.Close()
		t.mu.Lock()
		delete(t.entries, pairKey)
		t.mu.Unlock()
	}
}
