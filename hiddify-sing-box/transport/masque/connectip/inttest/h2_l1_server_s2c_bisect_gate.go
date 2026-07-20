//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-S2C-SERVER: onward direct vs conn-wire S2C; server H2 capsule counters vs client ReadPacket.

import (
	"testing"
)

const (
	s2cBisectBenchDur            = NativeSynthBenchDur
	s2cBisectMinBytes            = 4 * 1024 * 1024
	s2cBisectOnwardDirectMinMbps = 500.0 // loopback TCP bulk sanity
	s2cBisectConnOnwardMaxRatio  = 0.55    // conn-wire should be well below onward direct
	s2cBisectClientServerMin   = 0.75    // client IP bytes vs server proxied IP bytes (ctx stripped)
	s2cBisectH2DownBandFloor     = 200.0
	s2cBisectH2DownBandCeiling   = 450.0
	s2cContextIDWireBytes        = 1 // quicvarint(0) prefix on proxied payload
)

// RunGATEConnectIPH2L1ServerS2CBisect localizes server onward vs H2 S2C wire vs client receive.
func RunGATEConnectIPH2L1ServerS2CBisect(t *testing.T) {
	t.Helper()
	onward := runOnwardDirectDownloadSample(t, s2cBisectBenchDur)

	connStack := openConnectIPH2ConnWire(t)
	s2c := runConnWireUDPFountainWithS2CStats(t, connStack, "conn-wire", s2cBisectBenchDur, connWireUDPFountainPayloadLen)

	logAndAnalyzeServerS2CBisect(t, onward, s2c)
}

func logAndAnalyzeServerS2CBisect(t *testing.T, onward ThroughputSample, s2c connWireS2CResult) {
	t.Helper()
	client := s2c.Client
	t.Logf("S2C onward %s", onward)
	t.Logf("S2C client %s", client)

	if onward.Bytes < s2cBisectMinBytes {
		t.Fatalf("onward direct bytes=%d want>=%d", onward.Bytes, s2cBisectMinBytes)
	}
	if onward.Mbps < s2cBisectOnwardDirectMinMbps {
		t.Fatalf("onward direct %.1f < %.0f — harness/target broken", onward.Mbps, s2cBisectOnwardDirectMinMbps)
	}
	if client.Bytes < s2cBisectMinBytes {
		t.Fatalf("conn-wire client bytes=%d want>=%d", client.Bytes, s2cBisectMinBytes)
	}

	connOnwardRatio := client.Mbps / onward.Mbps
	t.Logf("S2C conn-wire/onward-direct ratio=%.2f (wire=%.1f onward=%.1f Mbit/s)",
		connOnwardRatio, client.Mbps, onward.Mbps)

	serverIPBytes := int64(s2c.ServerDatagramBytes)
	if s2c.ServerDatagrams > 0 {
		serverIPBytes -= int64(s2c.ServerDatagrams * s2cContextIDWireBytes)
	}
	clientServerRatio := float64(client.Bytes) / float64(serverIPBytes)
	t.Logf("S2C server datagrams=%d payload_bytes=%d flushes=%d skip=%d idle=%d",
		s2c.ServerDatagrams, s2c.ServerDatagramBytes, s2c.ServerFlushes, s2c.ServerFlushSkips, s2c.ServerIdleFlushes)
	if s2c.ServerFlushes > 0 {
		avgFlushUs := float64(s2c.ServerFlushNsTotal) / float64(s2c.ServerFlushes) / 1000.0
		t.Logf("S2C server avg_flush=%.1f us flushes/dgram=%.3f",
			avgFlushUs, float64(s2c.ServerFlushes)/float64(s2c.ServerDatagrams))
	}
	t.Logf("S2C client/server-ip-bytes ratio=%.2f (client=%d server_ip_est=%d)",
		clientServerRatio, client.Bytes, serverIPBytes)

	if client.Mbps < s2cBisectH2DownBandFloor || client.Mbps > s2cBisectH2DownBandCeiling {
		t.Fatalf("conn-wire %.1f outside band [%.0f, %.0f]", client.Mbps, s2cBisectH2DownBandFloor, s2cBisectH2DownBandCeiling)
	}

	if connOnwardRatio > s2cBisectConnOnwardMaxRatio {
		t.Fatalf("conn-wire/onward %.2f > %.2f — expected connect-ip+H2 tax (wire=%.1f onward=%.1f)",
			connOnwardRatio, s2cBisectConnOnwardMaxRatio, client.Mbps, onward.Mbps)
	}

	if clientServerRatio < s2cBisectClientServerMin {
		t.Logf("OPEN: server S2C enqueue > client ReadPacket drain (ratio=%.2f client=%d server_ip=%d) — pipeline buffer or client H2 decode",
			clientServerRatio, client.Bytes, serverIPBytes)
	}

	t.Logf("S2C PASS: onward direct >> conn-wire (ratio=%.2f); conn-wire=%.0f in H2 ceiling band — tax is connect-ip+H2 wire (server/client=%.2f)",
		connOnwardRatio, client.Mbps, clientServerRatio)
}
