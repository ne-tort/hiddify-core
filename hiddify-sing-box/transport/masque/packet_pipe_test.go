package masque

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
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

func runIngressRelay(sess IPPacketSession, ns *connectIPTCPNetstack) func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readBuffer := make([]byte, 64*1024)
		consecutiveRetryableFailures := 0
		const retryableReadFailureLimit = 32
		for {
			n, err := sess.ReadPacket(readBuffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
					return
				}
				if isRetryablePacketReadError(err) {
					consecutiveRetryableFailures++
					incConnectIPReadDropReason("retryable_read_error")
					if consecutiveRetryableFailures < retryableReadFailureLimit {
						time.Sleep(2 * time.Millisecond)
						continue
					}
					incConnectIPReadDropReason("retryable_read_exhausted")
					incConnectIPSessionReset("read_retry_exhausted")
				} else {
					incConnectIPReadDropReason("fatal_read_error")
					incConnectIPSessionReset("read_exit")
				}
				ns.FailWithError(errors.Join(ErrTransportInit, err))
				return
			}
			consecutiveRetryableFailures = 0
			if n <= 0 {
				continue
			}
			ns.InjectInboundClone(readBuffer[:n])
		}
	}()
	return wg.Wait
}
