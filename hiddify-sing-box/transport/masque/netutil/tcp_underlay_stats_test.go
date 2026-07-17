package netutil

import (
	"net"
	"testing"
)

type deadAddr struct{}

func (deadAddr) Network() string { return "tcp" }
func (deadAddr) String() string  { return "127.0.0.1:0" }

type fakeConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (f *fakeConn) RemoteAddr() net.Addr { return f.remote }
func (f *fakeConn) LocalAddr() net.Addr  { return f.local }

func TestTrackTCPUnderlayPrunesNilAndSnapshotsEmptyOK(t *testing.T) {
	ResetTCPUnderlayStatsTrackingForTest()
	TrackTCPUnderlay("test", nil)
	s := SnapshotTCPUnderlayStats()
	if s.TrackedConns != 0 {
		t.Fatalf("nil conn should not stay tracked: %+v", s)
	}
	fc := &fakeConn{remote: deadAddr{}, local: deadAddr{}}
	TrackTCPUnderlay("test-fake", fc)
	s = SnapshotTCPUnderlayStats()
	// Without syscall.Conn, ReadTCPInfo returns !OK → prune (do not keep zombies by addr alone).
	if s.TrackedConns != 0 {
		t.Fatalf("expected fake !OK conn pruned, got %d", s.TrackedConns)
	}
	ResetTCPUnderlayStatsTrackingForTest()
	if SnapshotTCPUnderlayStats().TrackedConns != 0 {
		t.Fatal("reset failed")
	}
}

func TestReadTCPInfoNilSafe(t *testing.T) {
	if got := ReadTCPInfo(nil); got.OK {
		t.Fatalf("nil conn must not be OK: %+v", got)
	}
}
