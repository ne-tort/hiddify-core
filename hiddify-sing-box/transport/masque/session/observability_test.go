package session

import (
	"errors"
	"testing"
)

func TestSnapshotMetricsIncludesErrorClassCounters(t *testing.T) {
	before := SnapshotMetrics()
	RecordTCPDialFailure()
	RecordTCPDialErrorClass(ErrTCPDial)
	RecordTCPDialErrorClass(ErrPolicyFallbackDenied)
	RecordTCPDialErrorClass(ErrTCPOverConnectIP)
	RecordTCPDialErrorClass(errors.New("unknown"))
	after := SnapshotMetrics()

	if after.TCPDialFailTotal < before.TCPDialFailTotal+1 {
		t.Fatalf("expected dial fail counter increment, before=%d after=%d", before.TCPDialFailTotal, after.TCPDialFailTotal)
	}
	if after.TCPErrorClassDialTotal < before.TCPErrorClassDialTotal+1 {
		t.Fatalf("expected dial class counter increment, before=%d after=%d", before.TCPErrorClassDialTotal, after.TCPErrorClassDialTotal)
	}
	if after.TCPErrorClassPolicyTotal < before.TCPErrorClassPolicyTotal+1 {
		t.Fatalf("expected policy class counter increment, before=%d after=%d", before.TCPErrorClassPolicyTotal, after.TCPErrorClassPolicyTotal)
	}
	if after.TCPErrorClassCapTotal < before.TCPErrorClassCapTotal+1 {
		t.Fatalf("expected capability class counter increment, before=%d after=%d", before.TCPErrorClassCapTotal, after.TCPErrorClassCapTotal)
	}
	if after.TCPErrorClassOtherTotal < before.TCPErrorClassOtherTotal+1 {
		t.Fatalf("expected other class counter increment, before=%d after=%d", before.TCPErrorClassOtherTotal, after.TCPErrorClassOtherTotal)
	}
}

func TestSnapshotMetricsTracksDialSuccessFallbackStackReady(t *testing.T) {
	before := SnapshotMetrics()
	RecordTCPDialSuccess()
	RecordTCPDialSuccess()
	RecordTCPFallback()
	RecordConnectIPStackReady(true)
	RecordConnectIPStackReady(false)
	after := SnapshotMetrics()
	if after.TCPDialTotal < before.TCPDialTotal+2 {
		t.Fatalf("tcp_dial_total: before=%d after=%d", before.TCPDialTotal, after.TCPDialTotal)
	}
	if after.TCPFallbackTotal < before.TCPFallbackTotal+1 {
		t.Fatalf("tcp_fallback_total: before=%d after=%d", before.TCPFallbackTotal, after.TCPFallbackTotal)
	}
	if after.ConnectIPStackReady < before.ConnectIPStackReady+1 {
		t.Fatalf("connect_ip_stack_ready_total: before=%d after=%d", before.ConnectIPStackReady, after.ConnectIPStackReady)
	}
	if after.ConnectIPStackNotReady < before.ConnectIPStackNotReady+1 {
		t.Fatalf("connect_ip_stack_not_ready_total: before=%d after=%d", before.ConnectIPStackNotReady, after.ConnectIPStackNotReady)
	}
}
