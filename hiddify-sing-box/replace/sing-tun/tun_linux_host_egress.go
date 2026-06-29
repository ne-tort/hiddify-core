//go:build with_gvisor && linux

package tun

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
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
	if n, ok := t.hostEgressPrefetch().pop(p); ok {
		return n, nil
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.After(time.Now()) {
		return t.readHostEgressNonblocking(p)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
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
		n, err := t.readHostEgressVirtioBatch(first)
		if n > 0 {
			t.drainHostEgressVirtioNonblock()
			return n, err
		}
		if err != nil {
			return 0, err
		}
		n, err = t.readHostEgressLocked(first)
		if n > 0 {
			t.drainHostEgressVirtioNonblock()
		}
		return n, err
	}
	n, err := t.readHostEgressLocked(first)
	if n > 0 && !t.vnetHdr {
		// Fill prefetch for read-ahead pump / ReadBatch drain (not used on canceled LoopIn ctx).
		t.drainHostEgressNonblock()
	}
	return n, err
}

func (t *NativeTun) readHostEgressNonblocking(p []byte) (int, error) {
	_ = t.tunFile.SetReadDeadline(time.Now())
	defer func() { _ = t.tunFile.SetReadDeadline(time.Time{}) }()
	n, err := t.readHostEgressLocked(p)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.EAGAIN) {
			return 0, nil
		}
		if errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EBADFD) {
			return 0, netErrClosed(err)
		}
		return 0, err
	}
	return n, nil
}

func (t *NativeTun) readHostEgressVirtioBatch(first []byte) (int, error) {
	if t.writeBuffer == nil {
		t.writeBuffer = make([]byte, virtioNetHdrLen+int(gsoMaxSize))
	}
	t.readAccess.Lock()
	n, err := t.tunFile.Read(t.writeBuffer)
	t.readAccess.Unlock()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.EAGAIN) {
			return 0, nil
		}
		return 0, err
	}
	if n <= 0 {
		return 0, nil
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
	if got == 0 {
		return 0, nil
	}
	pf := t.hostEgressPrefetch()
	firstLen := 0
	for i := 0; i < got; i++ {
		if sizes[i] <= 0 {
			continue
		}
		pkt := bufs[i][:sizes[i]]
		if len(pkt) < 1 || pkt[0]>>4 != 4 {
			continue
		}
		if firstLen == 0 {
			if sizes[i] > len(first) {
				return 0, nil
			}
			copy(first, pkt)
			firstLen = sizes[i]
			continue
		}
		cp := append([]byte(nil), pkt...)
		pf.push(cp)
	}
	return firstLen, nil
}

func (t *NativeTun) drainHostEgressNonblock() {
	_ = t.tunFile.SetReadDeadline(time.Now())
	defer func() { _ = t.tunFile.SetReadDeadline(time.Time{}) }()
	if t.vnetHdr {
		t.drainHostEgressVirtioNonblock()
		return
	}
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

func (t *NativeTun) drainHostEgressVirtioNonblock() {
	if t.writeBuffer == nil {
		t.writeBuffer = make([]byte, virtioNetHdrLen+int(gsoMaxSize))
	}
	_ = t.tunFile.SetReadDeadline(time.Now())
	defer func() { _ = t.tunFile.SetReadDeadline(time.Time{}) }()
	pf := t.hostEgressPrefetch()
	batch := t.BatchSize()
	if batch > idealBatchSize {
		batch = idealBatchSize
	}
	if batch < 1 {
		batch = 1
	}
	for {
		t.readAccess.Lock()
		n, err := t.tunFile.Read(t.writeBuffer)
		t.readAccess.Unlock()
		if err != nil || n <= 0 {
			return
		}
		bufs := make([][]byte, batch)
		sizes := make([]int, batch)
		for i := range bufs {
			bufs[i] = make([]byte, int(t.options.MTU)+128)
		}
		got, err := handleVirtioRead(t.writeBuffer[:n], bufs, sizes, 0)
		if err != nil || got == 0 {
			return
		}
		for i := 0; i < got; i++ {
			if sizes[i] <= 0 {
				continue
			}
			pkt := bufs[i][:sizes[i]]
			if len(pkt) < 1 || pkt[0]>>4 != 4 {
				continue
			}
			cp := append([]byte(nil), pkt...)
			pf.push(cp)
		}
	}
}

func (t *NativeTun) readHostEgressLocked(p []byte) (int, error) {
	if t.vnetHdr {
		if t.writeBuffer == nil {
			t.writeBuffer = make([]byte, virtioNetHdrLen+int(gsoMaxSize))
		}
		const maxNonIPv4Skips = 64
		for skipped := 0; skipped < maxNonIPv4Skips; skipped++ {
			t.readAccess.Lock()
			n, err := t.tunFile.Read(t.writeBuffer)
			t.readAccess.Unlock()
			b0 := byte(0)
			b10 := byte(0)
			if n > 0 {
				b0 = t.writeBuffer[0]
				if n > virtioNetHdrLen {
					b10 = t.writeBuffer[virtioNetHdrLen]
				}
			}
			logHostEgressRawRead(n, err, b0, b10, true)
			if n > 0 && hostEgressTraceEnabled() && hostEgressRawReadCount.Load() <= 8 {
				limit := n
				if limit > 24 {
					limit = 24
				}
				log.Printf("connect-ip tun raw hdr: % x", t.writeBuffer[:limit])
			}
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.EAGAIN) {
					return 0, nil
				}
				return 0, err
			}
			if n <= 0 {
				return 0, nil
			}
			got, parseErr := parseVirtioEgressFrame(t.writeBuffer[:n], p)
			if got > 0 {
				if p[0]>>4 != 4 {
					if hostEgressDebug() {
						log.Printf("connect-ip tun egress skip non-ipv4 len=%d b0=%#x", got, p[0])
					}
					continue
				}
				return got, nil
			}
			if hostEgressDebug() {
				off10 := byte(0)
				if n > virtioNetHdrLen {
					off10 = t.writeBuffer[virtioNetHdrLen]
				}
				log.Printf("connect-ip tun egress drop n=%d b0=%#x b10=%#x parseErr=%v", n, t.writeBuffer[0], off10, parseErr)
			}
			if parseErr != nil {
				return 0, parseErr
			}
		}
		return 0, nil
	}
	return t.tunFile.Read(p)
}

// parseVirtioEgressFrame strips virtio_net_hdr when present; salvages IPv4 by scanning hdr slack.
func parseVirtioEgressFrame(raw []byte, dst []byte) (int, error) {
	if len(raw) == 0 || len(dst) == 0 {
		return 0, nil
	}
	const ipv4Min = 20
	if len(raw) > virtioNetHdrLen {
		var sizes [1]int
		got, err := handleVirtioRead(raw, [][]byte{dst}, sizes[:], 0)
		if err == nil && got > 0 && sizes[0] > 0 {
			return sizes[0], nil
		}
		if virtioHdrAllZero(raw[:virtioNetHdrLen]) {
			payload := len(raw) - virtioNetHdrLen
			if payload > len(dst) {
				payload = len(dst)
			}
			if payload >= ipv4Min {
				copy(dst, raw[virtioNetHdrLen:virtioNetHdrLen+payload])
				return payload, nil
			}
		}
	}
	scanMax := virtioNetHdrLen + 2
	if scanMax > len(raw)-ipv4Min {
		scanMax = len(raw) - ipv4Min
	}
	if scanMax < 0 {
		scanMax = 0
	}
	for off := 0; off <= scanMax; off++ {
		if raw[off]>>4 != 4 {
			continue
		}
		payload := len(raw) - off
		if payload > len(dst) {
			payload = len(dst)
		}
		if payload < ipv4Min {
			continue
		}
		copy(dst, raw[off:off+payload])
		return payload, nil
	}
	return 0, nil
}

func virtioHdrAllZero(hdr []byte) bool {
	for _, b := range hdr {
		if b != 0 {
			return false
		}
	}
	return len(hdr) > 0
}

func hostEgressDebug() bool {
	return strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1"
}

// ReadHostEgressBatch reads up to maxN datagrams per syscall boundary (prefetch first, then blocking read + drain).
func (t *NativeTun) ReadHostEgressBatch(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	if t == nil || maxN <= 0 || len(bufs) == 0 {
		return 0, nil
	}
	if maxN > len(bufs) {
		maxN = len(bufs)
	}
	pf := t.hostEgressPrefetch()
	got := 0
	for got < maxN && len(bufs[got]) > 0 {
		if _, ok := pf.pop(bufs[got]); ok {
			got++
			continue
		}
		break
	}
	if got >= maxN {
		return got, nil
	}
	if len(bufs[got]) == 0 {
		return got, nil
	}
	n, err := t.ReadHostEgress(ctx, bufs[got])
	if err != nil {
		if got > 0 {
			return got, nil
		}
		return 0, err
	}
	if n <= 0 {
		return got, nil
	}
	got++
	for got < maxN && len(bufs[got]) > 0 {
		if _, ok := pf.pop(bufs[got]); ok {
			got++
			continue
		}
		break
	}
	return got, nil
}

func netErrClosed(err error) error {
	if errors.Is(err, syscall.EBADFD) {
		return os.ErrClosed
	}
	return err
}

var _ HostEgressReader = (*NativeTun)(nil)
var _ HostEgressBatchReader = (*NativeTun)(nil)
var _ HostIngressWriter = (*NativeTun)(nil)
