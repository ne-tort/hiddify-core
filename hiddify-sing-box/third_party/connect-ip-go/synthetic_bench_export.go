package connectip

import (
	"bytes"
	"io"
	"time"
)

// SyntheticH2ReadPacketBench measures Conn.ReadPacket on an in-memory H2 capsule pipe
// (no TLS/HTTP/2/server). ipPacketLen is the proxied IPv4 packet size returned by ReadPacket.
func SyntheticH2ReadPacketBench(ipPacketLen int, dur time.Duration) (totalBytes int64, mbps float64) {
	if ipPacketLen <= 0 {
		ipPacketLen = 540
	}
	if dur <= 0 {
		dur = 2 * time.Second
	}

	bodyR, bodyW := io.Pipe()
	str := &h2CapsulePipeStream{
		body:  bodyR,
		pipeW: io.Discard,
	}
	conn := newProxiedConn(str, true)
	defer conn.Close()
	defer bodyR.Close()
	defer bodyW.Close()

	ipPacket := make([]byte, ipPacketLen)
	wire := bytes.NewBuffer(make([]byte, 0, ipPacketLen+64))
	out := make([]byte, ipPacketLen+64)

	start := time.Now()
	deadline := start.Add(dur)
	var total int64
	for time.Now().Before(deadline) {
		wire.Reset()
		dgramPayload := composeProxiedIPDatagramPayload(contextIDZero, ipPacket)
		if err := appendHTTPDatagramCapsule(wire, dgramPayload); err != nil {
			break
		}
		if _, err := bodyW.Write(wire.Bytes()); err != nil {
			break
		}
		n, err := conn.ReadPacket(out)
		if err != nil || n <= 0 {
			continue
		}
		total += int64(n)
	}
	wall := time.Since(start)
	if wall > 0 && total > 0 {
		mbps = float64(total*8) / wall.Seconds() / 1e6
	}
	return total, mbps
}
