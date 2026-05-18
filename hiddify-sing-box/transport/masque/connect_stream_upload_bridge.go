package masque

import (
	"io"
	"sync"
)

// connectStreamUploadBridgeCap decouples CONNECT-stream upload (TUN ACKs) from the unbuffered
// io.Pipe feeding http sendRequestBody. A blocked pipe write stalls TUN ReadFrom and clocks
// download at ~64 KiB/RTT on bench tcp_down.
const connectStreamUploadBridgeCap = 512 << 10

// connectStreamUploadBridge is a fixed-size ring in front of the request-body pipe.
type connectStreamUploadBridge struct {
	inner  io.WriteCloser
	ring   []byte
	r, w   int
	used   int
	mu     sync.Mutex
	data   *sync.Cond
	closed bool
	err    error
	wg     sync.WaitGroup
}

func newConnectStreamUploadBridge(inner io.WriteCloser) *connectStreamUploadBridge {
	b := &connectStreamUploadBridge{
		inner: inner,
		ring:  make([]byte, connectStreamUploadBridgeCap),
	}
	b.data = sync.NewCond(&b.mu)
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.pump()
	}()
	return b
}

func (b *connectStreamUploadBridge) pump() {
	bp := masqueStreamUploadReadFromBufPool.Get().(*[]byte)
	defer masqueStreamUploadReadFromBufPool.Put(bp)
	buf := *bp
	for {
		n, done := b.takeLocked(buf)
		if n > 0 {
			if _, err := writeAllIOWriter(b.inner, buf[:n]); err != nil {
				b.setErr(err)
				return
			}
		}
		if done {
			return
		}
	}
}

func (b *connectStreamUploadBridge) takeLocked(dst []byte) (int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.used == 0 {
		if b.closed {
			return 0, true
		}
		if b.err != nil {
			return 0, true
		}
		b.data.Wait()
	}
	n := len(dst)
	if n > b.used {
		n = b.used
	}
	if b.r+n <= len(b.ring) {
		copy(dst, b.ring[b.r:b.r+n])
	} else {
		first := len(b.ring) - b.r
		copy(dst, b.ring[b.r:])
		copy(dst[first:], b.ring[:n-first])
	}
	b.r = (b.r + n) % len(b.ring)
	b.used -= n
	b.data.Broadcast()
	done := b.closed && b.used == 0
	return n, done
}

func (b *connectStreamUploadBridge) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		b.mu.Lock()
		for b.used == len(b.ring) && !b.closed && b.err == nil {
			b.data.Wait()
		}
		if b.err != nil {
			err := b.err
			b.mu.Unlock()
			if total > 0 {
				return total, err
			}
			return 0, err
		}
		if b.closed {
			b.mu.Unlock()
			if total > 0 {
				return total, io.ErrClosedPipe
			}
			return 0, io.ErrClosedPipe
		}
		space := len(b.ring) - b.used
		n := len(p)
		if n > space {
			n = space
		}
		if b.w+n <= len(b.ring) {
			copy(b.ring[b.w:], p[:n])
		} else {
			first := len(b.ring) - b.w
			copy(b.ring[b.w:], p[:first])
			copy(b.ring[:], p[first:n])
		}
		b.w = (b.w + n) % len(b.ring)
		b.used += n
		b.mu.Unlock()
		b.data.Broadcast()
		p = p[n:]
		total += n
	}
	return total, nil
}

func (b *connectStreamUploadBridge) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.data.Broadcast()
	// Unblock pump if it is waiting on a full io.Pipe.
	_ = b.inner.Close()
	b.wg.Wait()
	return nil
}

func (b *connectStreamUploadBridge) setErr(err error) {
	if err == nil {
		return
	}
	b.mu.Lock()
	if b.err == nil {
		b.err = err
	}
	b.closed = true
	b.mu.Unlock()
	b.data.Broadcast()
}
