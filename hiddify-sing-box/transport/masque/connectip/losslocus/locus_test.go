package losslocus

import "testing"

func TestSnapshotNowHasLocusKeys(t *testing.T) {
	Reset()
	RecordTunWriteFail()
	RecordTunInjectInvalid()
	RecordServerS2DiscardTeardown()
	s := SnapshotNow("client")
	if s.Role != "client" {
		t.Fatalf("role=%q", s.Role)
	}
	if s.Drops["tun_write_fail"] != 1 {
		t.Fatalf("tun_write_fail=%d", s.Drops["tun_write_fail"])
	}
	if s.Drops["tun_inject_invalid"] != 1 {
		t.Fatalf("tun_inject_invalid=%d", s.Drops["tun_inject_invalid"])
	}
	if s.Drops["server_s2_discard_teardown"] != 1 {
		t.Fatalf("discard=%d", s.Drops["server_s2_discard_teardown"])
	}
	// RTO excluded from total
	want := s.Drops["tun_write_fail"] + s.Drops["tun_inject_invalid"] + s.Drops["server_s2_discard_teardown"]
	// plus any process-global wire/quic baselines
	if s.Total < want {
		t.Fatalf("total_drops=%d want >= %d", s.Total, want)
	}
	for _, k := range []string{
		"client_ingress_capsule_full",
		"client_egress_write_fail",
		"underlay_h3_quic_rcv_queue",
		"server_s2_write_fail",
	} {
		if _, ok := s.Drops[k]; !ok {
			t.Fatalf("missing key %s", k)
		}
	}
}
