package relay

import (
	"context"
	"errors"
	"net"
	"time"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const defaultOnwardUDPBatchPoll = 100 * time.Millisecond

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
	for {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Time{})
			if len(payloads) > 0 {
				return payloads, nil
			}
			return nil, ctx.Err()
		default:
		}
		if !first {
			_ = conn.SetReadDeadline(time.Now())
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
				return payloads, nil
			}
			if n > 0 {
				payloads = append(payloads, append([]byte(nil), buf[:n]...))
			}
			return payloads, err
		}
		if n <= 0 {
			continue
		}
		payloads = append(payloads, append([]byte(nil), buf[:n]...))
		wire += wireLen(buf[:n])
		if wire >= maxWire {
			_ = conn.SetReadDeadline(time.Time{})
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
