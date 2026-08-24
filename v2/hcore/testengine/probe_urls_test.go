package testengine

import "testing"

func TestSplitProbeURLs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"https://a.example/x", []string{"https://a.example/x"}},
		{"https://a.example/x\nhttps://b.example/y", []string{"https://a.example/x", "https://b.example/y"}},
		{"  https://a\n\nhttps://b  \r\nhttps://c ", []string{"https://a", "https://b", "https://c"}},
	}
	for _, tc := range cases {
		got := splitProbeURLs(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitProbeURLs(%q) len=%d want %d (%v)", tc.in, len(got), len(tc.want), got)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("splitProbeURLs(%q)[%d]=%q want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
