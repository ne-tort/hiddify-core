package masque

import (
	"context"
	"errors"
	"io"
	"sync"
)

// connectStreamDownloadFeederRingCap is the backlog between the QUIC response body and
// streamConn.WriteTo. Sized for several coalesce rounds so the feeder keeps draining while
// TUN/TCP blocks, without per-chunk heap allocations.
const connectStreamDownloadFeederRingCap = 4 << 20

// connectStreamDownloadFeeder drains the HTTP/2/3 CONNECT-stream response body on a background
// goroutine into a fixed ring buffer so QUIC can keep delivering DATA while the TUN relay blocks
// on Write (unbuffered io.Pipe download pumps deadlocked here; bench tcp_down ~64 KiB/RTT).
type connectStreamDownloadFeeder struct {
	startOnce sync.Once
	ring      []byte
	r, w      int
	used      int

	mu      sync.Mutex
	data    *sync.Cond
	err     error
	errOnce sync.Once
	closed  bool
}

func (f *connectStreamDownloadFeeder) start(ctx context.Context, body io.Reader) {
	if body == nil {
		f.setErr(io.EOF)
		return
	}
	f.startOnce.Do(func() {
		f.ring = make([]byte, connectStreamDownloadFeederRingCap)
		f.data = sync.NewCond(&f.mu)
		go func() {
			bp := masqueStreamDownloadWriteToBufPool.Get().(*[]byte)
			defer masqueStreamDownloadWriteToBufPool.Put(bp)
			scratch := *bp
			for {
				if ctx != nil {
					select {
					case <-ctx.Done():
						f.fail(context.Cause(ctx))
						return
					default:
					}
				}
				if f.ringSpace() == 0 {
					f.waitRingSpace()
					if f.isClosed() {
						return
					}
					continue
				}
				// Background drain: keep blocking on the response body until the ring is full.
				// Stopping after !ConnectStreamReadBuffered capped bench tcp_down at ~64 KiB/RTT.
				for f.ringSpace() > 0 {
					n, err := coalesceConnectStreamReadFeeder(body, scratch)
					if n > 0 {
						if !f.writeRing(scratch[:n]) {
							return
						}
					}
					if err != nil {
						if errors.Is(err, io.EOF) {
							if n == 0 {
								f.finish()
								return
							}
							break
						}
						f.fail(err)
						return
					}
					if n == 0 {
						f.fail(errors.New("masque connect-stream download feeder: coalesce returned (0,nil)"))
						return
					}
				}
			}
		}()
	})
}

func (f *connectStreamDownloadFeeder) writeRing(p []byte) bool {
	for len(p) > 0 {
		f.mu.Lock()
		for f.used == len(f.ring) && !f.closed {
			if f.err != nil {
				f.mu.Unlock()
				return false
			}
			f.data.Wait()
		}
		if f.closed {
			f.mu.Unlock()
			return false
		}
		space := len(f.ring) - f.used
		n := len(p)
		if n > space {
			n = space
		}
		if n == 0 {
			f.mu.Unlock()
			continue
		}
		if f.w+n <= len(f.ring) {
			copy(f.ring[f.w:], p[:n])
		} else {
			first := len(f.ring) - f.w
			copy(f.ring[f.w:], p[:first])
			copy(f.ring[:], p[first:n])
		}
		f.w = (f.w + n) % len(f.ring)
		f.used += n
		f.mu.Unlock()
		f.data.Broadcast()
		p = p[n:]
	}
	return true
}

func (f *connectStreamDownloadFeeder) setErr(err error) {
	if err == nil {
		return
	}
	f.errOnce.Do(func() {
		f.err = err
	})
}

func (f *connectStreamDownloadFeeder) fail(err error) {
	f.setErr(err)
	f.finish()
}

func (f *connectStreamDownloadFeeder) finish() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.data.Broadcast()
}

// ConnectStreamReadBuffered reports bytes already in the ring (no QUIC read required).
func (f *connectStreamDownloadFeeder) ConnectStreamReadBuffered() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.used > 0
}

// tryRead copies from the ring without blocking. ok is false when the ring is empty and open.
func (f *connectStreamDownloadFeeder) tryRead(p []byte) (int, bool) {
	if len(p) == 0 {
		return 0, true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used == 0 {
		if f.closed {
			return 0, true
		}
		return 0, false
	}
	n := len(p)
	if n > f.used {
		n = f.used
	}
	if f.r+n <= len(f.ring) {
		copy(p, f.ring[f.r:f.r+n])
	} else {
		first := len(f.ring) - f.r
		copy(p, f.ring[f.r:])
		copy(p[first:], f.ring[:n-first])
	}
	f.r = (f.r + n) % len(f.ring)
	f.used -= n
	f.data.Broadcast()
	return n, true
}

func (f *connectStreamDownloadFeeder) ringSpaceLocked() int {
	return len(f.ring) - f.used
}

func (f *connectStreamDownloadFeeder) ringSpace() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ringSpaceLocked()
}

// waitRingSpace blocks until the ring has space or the feeder is closed/failed.
func (f *connectStreamDownloadFeeder) waitRingSpace() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.used == len(f.ring) && !f.closed && f.err == nil {
		f.data.Wait()
	}
}

func (f *connectStreamDownloadFeeder) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *connectStreamDownloadFeeder) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.used == 0 {
		if f.closed {
			if f.err == nil {
				return 0, io.EOF
			}
			return 0, f.err
		}
		f.data.Wait()
	}
	n := len(p)
	if n > f.used {
		n = f.used
	}
	if f.r+n <= len(f.ring) {
		copy(p, f.ring[f.r:f.r+n])
	} else {
		first := len(f.ring) - f.r
		copy(p, f.ring[f.r:])
		copy(p[first:], f.ring[:n-first])
	}
	f.r = (f.r + n) % len(f.ring)
	f.used -= n
	f.data.Broadcast()
	return n, nil
}
