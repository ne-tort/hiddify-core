package relay

import (
	"context"
	"errors"
	"net"
	"time"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	defaultOnwardUDPBatchPoll = 100 * time.Millisecond
	onwardUDPBatchCoalesceSpins = 8
)

type onwardUDPWireLen func(payload []byte) int

func onwardUDPWireLenRaw(payload []byte) int {
	return len(payload)
}

func onwardUDPWireLenH2Capsule(payload []byte) int {
	return h2c.UDPPayloadWireLen(payload)
}

// readOnwardUDPBatch drains available onward UDP datagrams (h2o/h3 parity: poll first read, zero-deadline coalesce).
func readOnwardUDPBatch(ctx context.Context, conn *net.UDPConn, buf []byte, maxWire int, wireLen onwardUDPWireLen) ([][]byte, error) {
	if conn == nil {
		return nil, errors.New("masque: udp batch read: nil conn")
	}
	if wireLen == nil {
		wireLen = onwardUDPWireLenRaw
	}
	if maxWire <= 0 {
		maxWire = 32 * 1024
	}
	var payloads [][]byte
	wire := 0
	first := true
	coalesceSpins := 0
	for {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Time{})
			if len(payloads) > 0 {
				recordRelayS2CBatch(payloads)
				return payloads, nil
			}
			return nil, ctx.Err()
		default:
		}
		if !first {
			// Short future deadline drains already-queued datagrams without blocking for in-flight arrivals.
			_ = conn.SetReadDeadline(time.Now().Add(time.Microsecond))
		} else if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetReadDeadline(dl)
		} else {
			_ = conn.SetReadDeadline(time.Now().Add(defaultOnwardUDPBatchPoll))
		}
		n, err := conn.Read(buf)
		first = false
		if err != nil {
			_ = conn.SetReadDeadline(time.Time{})
			if len(payloads) > 0 && isUDPReadTimeout(err) {
				if len(payloads) == 1 && wire < maxWire && coalesceSpins < onwardUDPBatchCoalesceSpins {
					coalesceSpins++
					continue
				}
				recordRelayS2CBatch(payloads)
				return payloads, nil
			}
			if n > 0 {
				payloads = append(payloads, append([]byte(nil), buf[:n]...))
			}
			recordRelayS2CBatch(payloads)
			return payloads, err
		}
		if n <= 0 {
			continue
		}
		payloads = append(payloads, append([]byte(nil), buf[:n]...))
		wire += wireLen(buf[:n])
		coalesceSpins = 0
		if wire >= maxWire {
			_ = conn.SetReadDeadline(time.Time{})
			recordRelayS2CBatch(payloads)
			return payloads, nil
		}
	}
}

func isUDPReadTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
