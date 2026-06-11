package masque

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	defaultConnectStreamDuplexWindowBytes = 64 * 1024
	defaultConnectStreamDuplexUploadChunk = 4 * 1024
	connectStreamDuplexRingMultiplier     = 3
	connectStreamDownloadSinkMaxBulk      = 512 * 1024
	connectStreamDownloadFeederRingCapLegacy = 4 << 20
)

// connectStreamDuplexGate couples HTTP/3 CONNECT-stream response intake with request-body
// upload (TCP ACK path under iperf -R). inflight = responseAhead - uploadReleased; capped at W
// (~64 KiB/RTT bench anchor). uploadReleased advances on request-body flush (ACK proxy), not on
// TUN delivery — ReleaseToStack is intentionally not used (v1 cleared inflight too early).
type connectStreamDuplexGate struct {
	enabled     bool
	windowBytes int
	uploadChunk int
	ringCap     int

	active atomic.Int32

	mu             sync.Mutex
	cond           sync.Cond
	responseAhead  int64
	uploadReleased int64
}

func newConnectStreamDuplexGate() *connectStreamDuplexGate {
	g := &connectStreamDuplexGate{
		enabled:     connectStreamDuplexEnabled(),
		windowBytes: connectStreamDuplexWindowBytes(),
		uploadChunk: defaultConnectStreamDuplexUploadChunk,
	}
	if g.enabled {
		g.ringCap = g.windowBytes * connectStreamDuplexRingMultiplier
	} else {
		g.ringCap = connectStreamDownloadFeederRingCapLegacy
	}
	g.cond.L = &g.mu
	return g
}

func connectStreamDuplexEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_STREAM_DUPLEX"))
	if raw == "" {
		return true
	}
	switch strings.ToLower(raw) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func connectStreamDuplexWindowBytes() int {
	raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_STREAM_DUPLEX_WINDOW_KB"))
	if raw == "" {
		return defaultConnectStreamDuplexWindowBytes
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return defaultConnectStreamDuplexWindowBytes
	}
	return kb * 1024
}

func (g *connectStreamDuplexGate) Enabled() bool {
	return g != nil && g.enabled
}

func (g *connectStreamDuplexGate) Active() bool {
	return g != nil && g.enabled && g.active.Load() > 0
}

func (g *connectStreamDuplexGate) EnterDuplex() {
	if g == nil || !g.enabled {
		return
	}
	g.active.Add(1)
}

func (g *connectStreamDuplexGate) LeaveDuplex() {
	if g == nil || !g.enabled {
		return
	}
	g.active.Add(-1)
	g.mu.Lock()
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *connectStreamDuplexGate) inflightLocked() int64 {
	v := g.responseAhead - g.uploadReleased
	if v < 0 {
		return 0
	}
	return v
}

// ResponseReadChunk returns how many bytes the feeder may read this round (duplex window).
func (g *connectStreamDuplexGate) ResponseReadChunk(max int) int {
	if g == nil || !g.enabled || !g.Active() || max <= 0 {
		return max
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	rem := int64(g.windowBytes) - g.inflightLocked()
	if rem <= 0 {
		return 0
	}
	if int64(max) > rem {
		return int(rem)
	}
	return max
}

// WaitResponseSlot blocks until n additional response bytes may enter the app (duplex active).
func (g *connectStreamDuplexGate) WaitResponseSlot(n int) {
	if g == nil || !g.enabled || n <= 0 || !g.Active() {
		return
	}
	want := int64(n)
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.inflightLocked()+want > int64(g.windowBytes) {
		g.cond.Wait()
	}
}

// CommitResponse records n bytes stored from the HTTP response (feeder ring), awaiting upload ACK credit.
func (g *connectStreamDuplexGate) CommitResponse(n int) {
	if g == nil || !g.enabled || n <= 0 || !g.Active() {
		return
	}
	g.mu.Lock()
	g.responseAhead += int64(n)
	g.mu.Unlock()
}

// RecordUpload credits request-body bytes released toward the peer (ACK path).
func (g *connectStreamDuplexGate) RecordUpload(n int) {
	if g == nil || !g.enabled || n <= 0 {
		return
	}
	g.mu.Lock()
	g.uploadReleased += int64(n)
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *connectStreamDuplexGate) RingCap() int {
	if g == nil {
		return connectStreamDownloadFeederRingCapLegacy
	}
	return g.ringCap
}

func (g *connectStreamDuplexGate) MaxDownloadChunk() int {
	if g == nil || !g.Active() {
		return connectStreamDownloadSinkMaxBulk
	}
	return g.windowBytes
}

func (g *connectStreamDuplexGate) UploadChunk() int {
	if g == nil {
		return defaultConnectStreamDuplexUploadChunk
	}
	return g.uploadChunk
}

func (g *connectStreamDuplexGate) MaxUploadChunk(fullBufLen int) int {
	if g == nil || !g.Active() {
		return fullBufLen
	}
	if g.uploadChunk < fullBufLen {
		return g.uploadChunk
	}
	return fullBufLen
}

func (g *connectStreamDuplexGate) CoalescePerCallCap() int {
	if g == nil || !g.Active() {
		return masqueConnectStreamReadCoalescePerCall
	}
	return g.windowBytes
}

func (g *connectStreamDuplexGate) DuplexFlushThreshold() int {
	if g == nil {
		return defaultConnectStreamDuplexUploadChunk
	}
	return g.uploadChunk
}
