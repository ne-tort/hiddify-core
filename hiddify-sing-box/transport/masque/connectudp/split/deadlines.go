package split

import (
	"sync/atomic"
	"time"
)

// ConnDeadlines stores read/write deadlines as Unix-nanosecond atomics (0 = no deadline).
type ConnDeadlines struct {
	Read  atomic.Int64
	Write atomic.Int64
}

func deadlineNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func (d *ConnDeadlines) SetDeadline(t time.Time) {
	v := deadlineNanos(t)
	d.Read.Store(v)
	d.Write.Store(v)
}

func (d *ConnDeadlines) SetReadDeadline(t time.Time) {
	d.Read.Store(deadlineNanos(t))
}

func (d *ConnDeadlines) SetWriteDeadline(t time.Time) {
	d.Write.Store(deadlineNanos(t))
}

func (d *ConnDeadlines) WriteTimeoutExceeded() bool {
	v := d.Write.Load()
	return v != 0 && time.Now().UnixNano() > v
}
