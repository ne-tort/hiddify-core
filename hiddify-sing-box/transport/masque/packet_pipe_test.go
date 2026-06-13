package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
)

type packetPipeSession struct {
	recvCh  chan []byte
	sendCh  chan []byte
	closeCh chan struct{}
	once    sync.Once
}

const packetPipeQueueDepth = 4096

func newPacketPipePair() (*packetPipeSession, *packetPipeSession) {
	aToB := make(chan []byte, packetPipeQueueDepth)
	bToA := make(chan []byte, packetPipeQueueDepth)
	return &packetPipeSession{recvCh: bToA, sendCh: aToB, closeCh: make(chan struct{})},
		&packetPipeSession{recvCh: aToB, sendCh: bToA, closeCh: make(chan struct{})}
}

func (s *packetPipeSession) ReadPacket(buffer []byte) (int, error) {
	select {
	case <-s.closeCh:
		return 0, net.ErrClosed
	case packet, ok := <-s.recvCh:
		if !ok {
			return 0, io.EOF
		}
		if len(packet) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, packet), nil
	}
}

func (s *packetPipeSession) WritePacket(buffer []byte) ([]byte, error) {
	packet := append([]byte(nil), buffer...)
	select {
	case <-s.closeCh:
		return nil, net.ErrClosed
	case s.sendCh <- packet:
		return nil, nil
	default:
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.closeCh:
		return nil, net.ErrClosed
	case s.sendCh <- packet:
		return nil, nil
	case <-timer.C:
		return nil, errors.New("packetpipe: i/o timeout")
	}
}

func (s *packetPipeSession) Close() error {
	s.once.Do(func() {
		close(s.closeCh)
	})
	return nil
}

type localizeIngressHost struct {
	sess IPPacketSession
	ns   *connectIPTCPNetstack
}

func (h *localizeIngressHost) IngressTransportModeOK() bool { return h.sess != nil }

func (h *localizeIngressHost) IngressPacketReader() func(context.Context, []byte) (int, error) {
	if h.sess == nil {
		return nil
	}
	return func(_ context.Context, buf []byte) (int, error) {
		return h.sess.ReadPacket(buf)
	}
}

func (h *localizeIngressHost) IngressTCPInstallInflight() bool        { return false }
func (h *localizeIngressHost) IngressTCPNetstack() *connectIPTCPNetstack { return h.ns }
func (h *localizeIngressHost) IngressTCPNetstackForInject() *connectIPTCPNetstack {
	return h.ns
}

func (h *localizeIngressHost) IngressTCPFastPath(pkt []byte) bool {
	return cip.TCPIngressFastPath(pkt, true, h.ns != nil, false)
}

func (h *localizeIngressHost) IngressDeliverTCP(pkt []byte) bool {
	return h.IngressDeliverTCPNoFlush(pkt)
}

func (h *localizeIngressHost) IngressDeliverTCPNoFlush(pkt []byte) bool {
	if h.ns == nil {
		return false
	}
	return cip.DeliverTCPIngress(pkt, cip.TCPIngressDeliverHooks{
		ActiveNetstack: func() *cip.Netstack { return h.ns },
	})
}

func (h *localizeIngressHost) IngressFlushAckWake() {}

type localizeIngressHostWithWake struct {
	localizeIngressHost
	flushes *atomic.Int32
}

func (h *localizeIngressHostWithWake) IngressFlushAckWake() {
	if h.flushes != nil {
		h.flushes.Add(1)
	}
}

func (h *localizeIngressHost) IngressOnReadFatal(err error) {
	if h.ns != nil {
		h.ns.FailWithError(errors.Join(session.ErrTransportInit, err))
	}
}

func (h *localizeIngressHost) IngressDebugLog([]byte, int, bool, bool) {}
func (h *localizeIngressHost) IngressObsEvent(string)                {}
func (h *localizeIngressHost) IngressEngineDrop(string)              {}
func (h *localizeIngressHost) IngressReadDrop(string)                {}
func (h *localizeIngressHost) IngressSessionReset(string)            {}

// startConnectIPIngressRelay runs the production connectip.Ingress demux loop for localize benches.
func startConnectIPIngressRelay(sess IPPacketSession, ns *connectIPTCPNetstack, wakeFlushes ...*atomic.Int32) func() {
	var host cip.IngressHost = &localizeIngressHost{sess: sess, ns: ns}
	if len(wakeFlushes) > 0 && wakeFlushes[0] != nil {
		host = &localizeIngressHostWithWake{
			localizeIngressHost: localizeIngressHost{sess: sess, ns: ns},
			flushes:             wakeFlushes[0],
		}
	}
	ing := cip.NewIngress(host)
	ing.MaybeStart(ns != nil)
	return func() { ing.StopGracefully() }
}
