package masque

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type tcpOverIPDialer struct {
	mu      sync.Mutex
	stack   TCPNetstack
	factory TCPNetstackFactory
	session IPPacketSession
	state   tcpOverIPState
}

type tcpOverIPState uint8

var defaultTCPOverIPDialTimeout = 5 * time.Second

const (
	tcpOverIPStateInit tcpOverIPState = iota
	tcpOverIPStateEstablishing
	tcpOverIPStateActive
	tcpOverIPStateClosing
	tcpOverIPStateClosed
)

func newTCPOverIPDialer(factory TCPNetstackFactory, session IPPacketSession) *tcpOverIPDialer {
	return &tcpOverIPDialer{
		factory: factory,
		session: session,
		state:   tcpOverIPStateInit,
	}
}

func (d *tcpOverIPDialer) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		ctx, cancel = context.WithTimeout(ctx, defaultTCPOverIPDialTimeout)
		defer cancel()
	}

	d.mu.Lock()
	if d.state == tcpOverIPStateClosed {
		d.mu.Unlock()
		return nil, ErrLifecycleClosed
	}
	if d.stack == nil {
		d.state = tcpOverIPStateEstablishing
		if d.factory == nil {
			d.factory = unavailableTCPNetstackFactory{}
		}
		stack, err := d.factory.New(ctx, d.session)
		if err != nil {
			d.state = tcpOverIPStateInit
			recordConnectIPStackReady(false)
			d.mu.Unlock()
			return nil, errors.Join(ErrTCPStackInit, err)
		}
		d.stack = stack
		d.state = tcpOverIPStateActive
		recordConnectIPStackReady(true)
	}
	stack := d.stack
	d.mu.Unlock()

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		conn, err := stack.DialContext(ctx, destination)
		if err == nil {
			d.mu.Lock()
			d.state = tcpOverIPStateActive
			d.mu.Unlock()
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
		base := 50 * time.Millisecond * time.Duration(attempt+1)
		// Small jitter helps to avoid synchronized retries in multi-session storms.
		jitter := time.Duration(rand.Intn(25)) * time.Millisecond
		if backoffErr := waitContextBackoff(ctx, base+jitter); backoffErr != nil {
			return nil, backoffErr
		}
	}
	return nil, errors.Join(ErrTCPDial, lastErr)
}

func (d *tcpOverIPDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stack != nil {
		d.state = tcpOverIPStateClosing
		err := d.stack.Close()
		d.stack = nil
		d.state = tcpOverIPStateClosed
		return err
	}
	d.state = tcpOverIPStateClosed
	return nil
}
