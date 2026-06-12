package connectip

import "testing"

func TestObservabilitySnapshotPolicyReasonContract(t *testing.T) {
	t.Parallel()
	snapshot := ObservabilitySnapshot()
	reasonMapRaw, ok := snapshot["connect_ip_policy_drop_icmp_reason_total"]
	if !ok {
		t.Fatal("expected connect_ip_policy_drop_icmp_reason_total key in observability snapshot")
	}
	reasonMap, ok := reasonMapRaw.(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected policy-drop reason map type: %T", reasonMapRaw)
	}
	for _, reason := range []string{"src_not_allowed", "dst_not_allowed", "proto_not_allowed"} {
		if _, exists := reasonMap[reason]; !exists {
			t.Fatalf("expected mandatory policy-drop reason key %q", reason)
		}
	}
}

func TestObservabilitySnapshotIncludesNetstackNotifyMetrics(t *testing.T) {
	t.Parallel()
	snapshot := ObservabilitySnapshot()
	for _, key := range []string{
		"connect_ip_netstack_write_notify_retry_continue_drop_total",
		"connect_ip_netstack_write_notify_slow_iteration_total",
	} {
		raw, ok := snapshot[key]
		if !ok {
			t.Fatalf("expected %q in ObservabilitySnapshot", key)
		}
		if _, ok := raw.(uint64); !ok {
			t.Fatalf("unexpected type for %s: %T", key, raw)
		}
	}
}
