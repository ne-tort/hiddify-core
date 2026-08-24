package config

import "testing"

func TestConnectionTestURLsForDNS(t *testing.T) {
	t.Parallel()
	if got := connectionTestURLsForDNS(nil); got != nil {
		t.Fatalf("nil opt: %v", got)
	}
	opt := &ClientOptions{}
	opt.ConnectionTestUrl = "http://singular.example/"
	got := connectionTestURLsForDNS(opt)
	if len(got) != 1 || got[0] != "http://singular.example/" {
		t.Fatalf("fallback singular: %v", got)
	}
	opt.ConnectionTestUrls = []string{"http://a/", "http://b/"}
	got = connectionTestURLsForDNS(opt)
	if len(got) != 2 {
		t.Fatalf("prefer list: %v", got)
	}
	// Must not mutate list when empty after clearing
	opt.ConnectionTestUrls = nil
	_ = connectionTestURLsForDNS(opt)
	if len(opt.ConnectionTestUrls) != 0 {
		t.Fatalf("mutated options: %v", opt.ConnectionTestUrls)
	}
}
