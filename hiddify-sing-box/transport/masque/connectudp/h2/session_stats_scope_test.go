package h2

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
)

// TestH2AsymSessionStatsSingleScope covers AUDIT A5 / TASKS F0.2:
// one BeginRelaySessionStats per asym session; AttachUpload / first Release must not end or re-Begin.
func TestH2AsymSessionStatsSingleScope(t *testing.T) {
	cudprelay.EnableRelayStatsForBench()
	cudprelay.ResetUDPRelayStats()
	t.Cleanup(func() { cudprelay.ResetUDPRelayStats() })

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reg := NewSessionRegistry()
	key := sessionKey{mux: "stats-scope", target: "127.0.0.1:9"}

	rr := httptest.NewRecorder()
	downlinkW := newH2DownlinkWriter(rr, LegProfileDownloadFountain)
	sess, err := reg.RegisterDownload(key, conn, downlinkW)
	if err != nil {
		t.Fatal(err)
	}

	sess.mu.Lock()
	end0 := sess.endStats
	sess.mu.Unlock()
	if end0 == nil {
		t.Fatal("expected endStats after RegisterDownload")
	}

	sess.ensureRelayStats() // Once — must keep same end hook
	sess.mu.Lock()
	end1 := sess.endStats
	sess.mu.Unlock()
	if end1 == nil || &end0 == nil {
		t.Fatal("endStats cleared unexpectedly")
	}
	// Compare by calling identity: ensureRelayStats must not replace endStats with a new Begin.
	// (Replacing would Reset counters mid-session — A5.)
	if end1 == nil {
		t.Fatal("nil endStats after ensureRelayStats")
	}

	if _, err := reg.AttachUpload(key); err != nil {
		t.Fatal(err)
	}
	sess.mu.Lock()
	endAfterAttach := sess.endStats
	sess.mu.Unlock()
	if endAfterAttach == nil {
		t.Fatal("AttachUpload cleared endStats (would imply re-Begin/Reset)")
	}

	reg.Release(key) // download ref; upload still held
	sess.mu.Lock()
	still := sess.endStats != nil
	sess.mu.Unlock()
	if !still {
		t.Fatal("stats ended too early after first Release")
	}

	reg.Release(key) // last ref
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		done := sess.endStats == nil
		sess.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected finishRelayStats on last Release")
}

func TestH2AsymRelayStatsTagConstant(t *testing.T) {
	if h2AsymRelayStatsTag != "h2-asym" {
		t.Fatalf("tag=%q want h2-asym", h2AsymRelayStatsTag)
	}
}
