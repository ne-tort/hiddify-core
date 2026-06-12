package connectip

import (
	"sync/atomic"
	"time"
)

// PacketDeadlines stores read/write deadlines as Unix-nanosecond atomics (0 = none).
// Hot ReadFrom/WriteTo paths use a single atomic load per check.
type PacketDeadlines struct {
	read  atomic.Int64
	write atomic.Int64
}

func deadlineNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func (d *PacketDeadlines) SetDeadline(t time.Time) {
	v := deadlineNanos(t)
	d.read.Store(v)
	d.write.Store(v)
}

func (d *PacketDeadlines) SetReadDeadline(t time.Time) {
	d.read.Store(deadlineNanos(t))
}

func (d *PacketDeadlines) SetWriteDeadline(t time.Time) {
	d.write.Store(deadlineNanos(t))
}

func (d *PacketDeadlines) ReadTimeoutExceeded() bool {
	v := d.read.Load()
	return v != 0 && time.Now().UnixNano() > v
}

func (d *PacketDeadlines) WriteTimeoutExceeded() bool {
	v := d.write.Load()
	return v != 0 && time.Now().UnixNano() > v
}

func (d *PacketDeadlines) readDeadline() int64 {
	return d.read.Load()
}
