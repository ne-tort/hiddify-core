//go:build with_gvisor && linux

package tun

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
)

const hostEgressPrefetchMax = 128

type hostEgressPrefetch struct {
	mu sync.Mutex
	q  [][]byte
}

var nativeTunHostEgressPrefetch sync.Map // *NativeTun → *hostEgressPrefetch

func (t *NativeTun) hostEgressPrefetch() *hostEgressPrefetch {
	if t == nil {
		return nil
	}
	if v, ok := nativeTunHostEgressPrefetch.Load(t); ok {
		return v.(*hostEgressPrefetch)
	}
	p := &hostEgressPrefetch{}
	actual, _ := nativeTunHostEgressPrefetch.LoadOrStore(t, p)
	return actual.(*hostEgressPrefetch)
}

func (p *hostEgressPrefetch) pop(dst []byte) (int, bool) {
	if p == nil {
		return 0, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.q) == 0 {
		return 0, false
	}
	pkt := p.q[0]
	p.q = p.q[1:]
	if len(pkt) > len(dst) {
		p.q = append([][]byte{pkt}, p.q...)
		return 0, false
	}
	n := copy(dst, pkt)
	return n, true
}

func (p *hostEgressPrefetch) push(pkt []byte) {
	if p == nil || len(pkt) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.q) >= hostEgressPrefetchMax {
		return
	}
	p.q = append(p.q, pkt)
}

// ReadHostEgress reads one kernel egress datagram from the tun fd (usque Device.ReadPacket parity).
// Prefetch: virtio GRO splits and non-blocking drain keep multiple pkts per syscall (PERF-3).
func (t *NativeTun) ReadHostEgress(ctx context.Context, p []byte) (int, error) {
	if t == nil || len(p) == 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if n, ok := t.hostEgressPrefetch().pop(p); ok {
		return n, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.tunFile.SetReadDeadline(deadline)
	} else {
		_ = t.tunFile.SetReadDeadline(time.Time{})
	}
	defer func() { _ = t.tunFile.SetReadDeadline(time.Time{}) }()

	n, err := t.readHostEgressPrefetch(p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.EAGAIN) {
			if ctx.Err() != nil {
				return 0, context.Cause(ctx)
			}
			return 0, nil
		}
		if errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EBADFD) {
			return 0, netErrClosed(err)
		}
		return n, err
	}
	return n, nil
}

func (t *NativeTun) readHostEgressPrefetch(first []byte) (int, error) {
	if t.vnetHdr {
		return t.readHostEgressVirtioBatch(first)
	}
	n, err := t.readHostEgressLocked(first)
	if n > 0 {
		t.drainHostEgressNonblock()
	}
	return n, err
}

func (t *NativeTun) readHostEgressVirtioBatch(first []byte) (int, error) {
	if t.writeBuffer == nil {
		t.writeBuffer = make([]byte, virtioNetHdrLen+int(gsoMaxSize))
	}
	n, err := t.tunFile.Read(t.writeBuffer)
	if err != nil {
		return 0, err
	}
	batch := t.BatchSize()
	if batch > idealBatchSize {
		batch = idealBatchSize
	}
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	bufs[0] = first
	for i := 1; i < batch; i++ {
		bufs[i] = make([]byte, int(t.options.MTU)+128)
	}
	got, err := handleVirtioRead(t.writeBuffer[:n], bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if got == 0 || sizes[0] == 0 {
		return 0, nil
	}
	pf := t.hostEgressPrefetch()
	for i := 1; i < got; i++ {
		if sizes[i] <= 0 {
			continue
		}
		cp := append([]byte(nil), bufs[i][:sizes[i]]...)
		pf.push(cp)
	}
	return sizes[0], nil
}

func (t *NativeTun) drainHostEgressNonblock() {
	_ = t.tunFile.SetReadDeadline(time.Now())
	defer func() { _ = t.tunFile.SetReadDeadline(time.Time{}) }()
	pf := t.hostEgressPrefetch()
	for {
		raw := buf.Get(int(t.options.MTU) + 128)
		n, err := t.tunFile.Read(raw)
		if err != nil || n <= 0 {
			buf.Put(raw)
			return
		}
		pkt := append([]byte(nil), raw[:n]...)
		buf.Put(raw)
		pf.push(pkt)
	}
}

func (t *NativeTun) readHostEgressLocked(p []byte) (int, error) {
	if t.vnetHdr {
		raw := buf.Get(virtioNetHdrLen + len(p))
		defer buf.Put(raw)
		n, err := t.tunFile.Read(raw)
		if err != nil {
			return 0, err
		}
		var sizes [1]int
		got, err := handleVirtioRead(raw[:n], [][]byte{p}, sizes[:], 0)
		if err != nil {
			return 0, err
		}
		if got == 0 || sizes[0] == 0 {
			return 0, nil
		}
		return sizes[0], nil
	}
	return t.tunFile.Read(p)
}

func netErrClosed(err error) error {
	if errors.Is(err, syscall.EBADFD) {
		return os.ErrClosed
	}
	return err
}

var _ HostEgressReader = (*NativeTun)(nil)
