package h2

import (
	"net"
	"net/http/httptest"
	"testing"
)

func udpStillWritable(t *testing.T, conn *net.UDPConn) error {
	t.Helper()
	_, err := conn.WriteToUDP([]byte("probe"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	return err
}

// TestAsymSharedUDPStaysOpenWhileUploadHoldsRef covers AUDIT A3 / TASKS F2.1:
// download Release must not close onward UDP while upload still holds a ref.
func TestAsymSharedUDPStaysOpenWhileUploadHoldsRef(t *testing.T) {
	reg := NewSessionRegistry()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	key := sessionKey{target: "127.0.0.1:9", mux: "a3-test"}
	rr := httptest.NewRecorder()
	downlinkW := newH2DownlinkWriter(rr, LegProfileDownloadFountain)

	if _, err := reg.RegisterDownload(key, conn, downlinkW); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.AttachUpload(key); err != nil {
		t.Fatal(err)
	}
	// Download leg ends first (Release once) — upload still holds ref.
	reg.Release(key)

	if err := udpStillWritable(t, conn); err != nil {
		t.Fatalf("upload path after download Release: %v (A3: UDP closed early)", err)
	}

	reg.Release(key) // last ref — closes
	if err := udpStillWritable(t, conn); err == nil {
		t.Fatal("expected closed UDP after last Release")
	}
}

// TestAsymDownloadReentryRetainsRef covers AUDIT C15 / TASKS F2.6.
func TestAsymDownloadReentryRetainsRef(t *testing.T) {
	reg := NewSessionRegistry()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	key := sessionKey{target: "127.0.0.1:9", mux: "c15-test"}
	rr := httptest.NewRecorder()
	downlinkW := newH2DownlinkWriter(rr, LegProfileDownloadFountain)
	if _, err := reg.RegisterDownload(key, conn, downlinkW); err != nil {
		t.Fatal(err)
	}
	sess, w, ok := reg.lookupDownloadSession(key)
	if !ok || sess == nil || w == nil {
		t.Fatal("lookup miss")
	}
	reg.retainSession(key)
	reg.Release(key) // drop re-entry ref — original Register ref remains
	if err := udpStillWritable(t, conn); err != nil {
		t.Fatalf("UDP closed after re-entry Release without retain pairing: %v", err)
	}
	reg.Release(key)
}
