package h2

import "testing"

func TestUploadLegCoalesceThreshold(t *testing.T) {
	up := NewPacketConn(PacketConnConfig{UploadOnly: true, LegProfile: LegProfileUpload})
	if up.uploadCoalesceThreshold() != h2UploadCoalesceBulkBytesConfigured() {
		t.Fatalf("upload leg pre-bulk threshold=%d want %d", up.uploadCoalesceThreshold(), h2UploadCoalesceBulkBytesConfigured())
	}
	up.bulkUpload = true
	if up.uploadCoalesceThreshold() != h2UploadCoalesceThreshold {
		t.Fatalf("upload leg bulk threshold=%d want %d", up.uploadCoalesceThreshold(), h2UploadCoalesceThreshold)
	}
	bidi := NewPacketConn(PacketConnConfig{LegProfile: LegProfileEchoBidi})
	if bidi.uploadCoalesceThreshold() != h2UploadCoalesceBulkBytesConfigured() {
		t.Fatalf("bidi threshold=%d want bulk %d", bidi.uploadCoalesceThreshold(), h2UploadCoalesceBulkBytesConfigured())
	}
}
