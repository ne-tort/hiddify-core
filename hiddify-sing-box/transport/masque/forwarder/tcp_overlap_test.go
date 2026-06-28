package forwarder

import "testing"

func TestTrimPayloadAtRcvNxt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		seq     uint32
		rcvNxt  uint32
		payload []byte
		wantLen int
		wantOK  bool
	}{
		{"exact", 1000, 1000, []byte{1, 2, 3}, 3, true},
		{"duplicate", 1000, 1003, []byte{1, 2, 3}, 0, true},
		{"overlap_tail", 1000, 1002, []byte{1, 2, 3, 4, 5}, 3, true},
		{"gap", 1010, 1000, []byte{1}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := trimPayloadAtRcvNxt(tt.seq, tt.rcvNxt, tt.payload)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want %v", ok, tt.wantOK)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("len=%d want %d", len(got), tt.wantLen)
			}
		})
	}
}
