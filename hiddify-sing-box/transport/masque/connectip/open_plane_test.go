package connectip

import (
	"errors"
	"testing"

	libconnectip "github.com/quic-go/connect-ip-go"
)

func TestBeginOpenSessionSetsScope(t *testing.T) {
	t.Parallel()
	BeginOpenSession(" 10.200.0.2/32 ", 17)
	snapshot := ObservabilitySnapshot()
	if got := snapshot["connect_ip_scope_target"]; got != "10.200.0.2/32" {
		t.Fatalf("scope target: got %q", got)
	}
	if got := snapshot["connect_ip_scope_ipproto"]; got != uint8(17) {
		t.Fatalf("scope ipproto: got %v", got)
	}
}

func TestOpenSessionNotSupportedError(t *testing.T) {
	t.Parallel()
	err := OpenSessionNotSupportedError()
	if !errors.Is(err, Errs.Capability) {
		t.Fatalf("expected Errs.Capability, got %v", err)
	}
	snapshot := ObservabilitySnapshot()
	reasons, ok := snapshot["connect_ip_packet_write_fail_reason_total"].(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected reason map type: %T", snapshot["connect_ip_packet_write_fail_reason_total"])
	}
	if reasons["open_not_supported"] == 0 {
		t.Fatal("expected open_not_supported write-fail reason")
	}
}

func TestRecordOpenSessionSuccessNewIncrementsCounter(t *testing.T) {
	t.Parallel()
	before := ObservabilitySnapshot()["connect_ip_open_session_total"].(uint64)
	RecordOpenSessionSuccessNew()
	after := ObservabilitySnapshot()["connect_ip_open_session_total"].(uint64)
	if after != before+1 {
		t.Fatalf("open session total: before=%d after=%d", before, after)
	}
	if id := ObservabilitySnapshot()["connect_ip_session_id"].(string); id == "" {
		t.Fatal("expected non-empty session id after new open")
	}
}

func TestNewClientPacketSessionFromParamsTrimsProfileLocals(t *testing.T) {
	t.Parallel()
	session := NewClientPacketSessionFromParams(SessionPacketParams{
		Conn:             &libconnectip.Conn{},
		ProfileLocalIPv4: " 198.18.0.2 ",
		ProfileLocalIPv6: " fd00::1 ",
	})
	boot := SessionBootstrapFrom(session)
	if boot.ProfileLocalIPv4 != "198.18.0.2" {
		t.Fatalf("profile v4: got %q", boot.ProfileLocalIPv4)
	}
}
