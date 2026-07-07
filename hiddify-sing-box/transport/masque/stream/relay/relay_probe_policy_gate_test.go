package relay

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGATERelayProbePolicyProdOpportunistic(t *testing.T) {
	t.Parallel()
	p := ProdRelayProbePolicy()
	if p.DownloadPrimeWait != 0 || p.UploadProbeWait != 0 {
		t.Fatalf("prod probe must be peek-only: %+v", p)
	}
}

func TestGATERelayProbePolicyNoProdEnv(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(wd, "relay_probe_policy.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "os.Getenv") {
		t.Fatal("relay_probe_policy.go must not read env knobs")
	}
}

func TestGATERelayPrimeDownloadPeekImmediate(t *testing.T) {
	t.Parallel()
	const banner = "iperf3\r\n"
	src := &bannerPrimeConn{
		banner: []byte(banner),
		rest:   []byte("body"),
	}
	prime, err := relayTunnelPrimeDownloadPolicy(src, ProdRelayProbePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if string(prime) != banner {
		t.Fatalf("prime=%q want %q", prime, banner)
	}
}

func TestGATERelayPrimeDownloadProdSkipsSlowBanner(t *testing.T) {
	t.Parallel()
	src := newDeadlineDelayedConn([]byte("banner"), 50*time.Millisecond)
	prime, err := relayTunnelPrimeDownloadPolicy(src, ProdRelayProbePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(prime) != 0 {
		t.Fatalf("prod prime must not wait for slow banner, got %q", prime)
	}
}

func TestGATERelayPrimeDownloadLegacyWaitsSlowBanner(t *testing.T) {
	t.Parallel()
	src := newDeadlineDelayedConn([]byte("banner"), 20*time.Millisecond)
	prime, err := relayTunnelPrimeDownloadPolicy(src, LegacyRelayProbePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if string(prime) != "banner" {
		t.Fatalf("legacy prime=%q want banner", prime)
	}
}

func TestGATERelayH3ProbeProdInstantTimeoutNeutral(t *testing.T) {
	t.Parallel()
	src, mode, uploadStarted := relayH3ProbeUploadLegPolicy(timeoutReader{}, ProdRelayProbePolicy())
	if mode != relayH3UploadLegNeutral {
		t.Fatalf("mode=%v want neutral", mode)
	}
	if uploadStarted {
		t.Fatal("instant timeout must not mark upload started")
	}
	if src == nil {
		t.Fatal("expected reader")
	}
}

// deadlineDelayedConn serves payload after delay and honors SetReadDeadline.
type deadlineDelayedConn struct {
	payload []byte
	delay   time.Duration

	mu       sync.Mutex
	deadline time.Time
	hasDL    bool
}

func newDeadlineDelayedConn(payload []byte, delay time.Duration) *deadlineDelayedConn {
	return &deadlineDelayedConn{
		payload: append([]byte(nil), payload...),
		delay:   delay,
	}
}

func (c *deadlineDelayedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	hasDL := c.hasDL
	c.mu.Unlock()

	timer := time.NewTimer(c.delay)
	defer timer.Stop()
	if hasDL {
		if !deadline.IsZero() {
			if wait := time.Until(deadline); wait <= 0 {
				return 0, &timeoutError{}
			} else if wait < c.delay {
				timer.Reset(wait)
			}
		}
		select {
		case <-timer.C:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return 0, &timeoutError{}
		}
	} else {
		<-timer.C
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.payload) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.payload)
	c.payload = c.payload[n:]
	return n, nil
}

func (c *deadlineDelayedConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *deadlineDelayedConn) Close() error              { return nil }
func (c *deadlineDelayedConn) LocalAddr() net.Addr       { return nil }
func (c *deadlineDelayedConn) RemoteAddr() net.Addr      { return nil }
func (c *deadlineDelayedConn) SetDeadline(time.Time) error      { return nil }
func (c *deadlineDelayedConn) SetWriteDeadline(time.Time) error { return nil }

func (c *deadlineDelayedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	c.hasDL = true
	return nil
}
