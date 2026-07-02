package h2

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

func runH2IntegrationUDPSink(t *testing.T) (*net.UDPConn, *atomic.Int64) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	var rx atomic.Int64
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				rx.Add(int64(n))
			}
		}
	}()
	return c, &rx
}

// TestH2AsymmetricUploadMaxCapsuleSinglePacket verifies upload leg forwards one max capsule (UDP-6MIG-11 repro).
func TestH2AsymmetricUploadMaxCapsuleSinglePacket(t *testing.T) {
	sink, rx := runH2IntegrationUDPSink(t)
	sinkPort := sink.LocalAddr().(*net.UDPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)
	cfg := newH2ProdShapedIntegrationDialConfig(t, proxyPort)
	pc := dialH2IntegrationUDPWithConfig(t, proxyPort, cfg, net.JoinHostPort("127.0.0.1", strconv.Itoa(sinkPort)))

	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	payload := make([]byte, maxPayload)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	baseline := rx.Load()
	nw, err := pc.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, maxPayload, nw)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rx.Load()-baseline >= int64(maxPayload) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("upload leg did not deliver max capsule payload to sink within 3s (rx=%d want>=%d)",
		rx.Load()-baseline, maxPayload)
}

const (
	h2MaxCapsuleWriteStall = 2 * time.Second
	h2MaxCapsuleTestSlack  = 5 * time.Second
)

// TestH2AsymmetricUploadMaxCapsuleBurst hammers max capsules briefly; must not deadlock on upload pipe.
func TestH2AsymmetricUploadMaxCapsuleBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("burst hammer")
	}
	runH2MaxCapsuleBurstDuration(t, 500*time.Millisecond)
}

func TestH2AsymmetricUploadMaxCapsuleSustained(t *testing.T) {
	if testing.Short() {
		t.Skip("sustained hammer")
	}
	runH2MaxCapsuleBurstDuration(t, 2*time.Second)
}

func runH2MaxCapsuleBurstDuration(t *testing.T, dur time.Duration) {
	t.Helper()
	sink, rx := runH2IntegrationUDPSink(t)
	sinkPort := sink.LocalAddr().(*net.UDPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)
	cfg := newH2ProdShapedIntegrationDialConfig(t, proxyPort)
	pc := dialH2IntegrationUDPWithConfig(t, proxyPort, cfg, net.JoinHostPort("127.0.0.1", strconv.Itoa(sinkPort)))

	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	payload := make([]byte, maxPayload)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	baseline := rx.Load()
	deadline := time.Now().Add(dur)
	testDeadline := deadline.Add(h2MaxCapsuleTestSlack)
	var sent int64
	for time.Now().Before(deadline) {
		if time.Now().After(testDeadline) {
			t.Fatalf("max-capsule upload exceeded %v overall (upload pipe/http2 stall)", dur+h2MaxCapsuleTestSlack)
		}
		type writeRes struct {
			n   int
			err error
		}
		ch := make(chan writeRes, 1)
		go func() {
			n, err := pc.WriteTo(payload, nil)
			ch <- writeRes{n, err}
		}()
		var res writeRes
		select {
		case res = <-ch:
		case <-time.After(h2MaxCapsuleWriteStall):
			t.Fatalf("WriteTo stalled >%v — upload pipe/http2 deadlock", h2MaxCapsuleWriteStall)
		}
		require.NoError(t, res.err)
		nw := res.n
		require.Equal(t, maxPayload, nw)
		sent += int64(maxPayload)
	}
	delivered := rx.Load() - baseline
	if delivered == 0 {
		t.Fatal("burst upload delivered 0 bytes — upload relay or client pump dead")
	}
	t.Logf("burst maxCapsule(%s): sent~%d delivered=%d (%.1f%%)",
		dur, sent, delivered, 100*float64(delivered)/float64(sent))
}
