//go:build with_gvisor && linux

package tun

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// ReadHostEgress reads one kernel egress datagram from the tun fd (usque Device.ReadPacket parity).
// Blocking read when ctx has no deadline; zero-deadline ctx returns after one non-blocking attempt.
func (t *NativeTun) ReadHostEgress(ctx context.Context, p []byte) (int, error) {
	if t == nil || len(p) == 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.tunFile.SetReadDeadline(deadline)
	} else {
		_ = t.tunFile.SetReadDeadline(time.Time{})
	}
	defer func() { _ = t.tunFile.SetReadDeadline(time.Time{}) }()

	n, err := t.readHostEgressLocked(p)
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
