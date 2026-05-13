package masque

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type stubConnectIPPrefixSource struct {
	current []netip.Prefix
	seq     [][]netip.Prefix
	idx     int
}

func (s *stubConnectIPPrefixSource) CurrentAssignedPrefixes() []netip.Prefix {
	cp := make([]netip.Prefix, len(s.current))
	copy(cp, s.current)
	return cp
}

func (s *stubConnectIPPrefixSource) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	if s.idx < len(s.seq) {
		p := s.seq[s.idx]
		s.idx++
		s.current = append([]netip.Prefix(nil), p...)
		return append([]netip.Prefix(nil), p...), nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWaitForNonEmptyAssignedPrefixesImmediate(t *testing.T) {
	src := &stubConnectIPPrefixSource{
		current: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
	}
	got, err := waitForNonEmptyAssignedPrefixes(src, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].String() != "10.0.0.2/32" {
		t.Fatalf("unexpected prefixes: %v", got)
	}
}

func TestWaitForNonEmptyAssignedPrefixesSkipsEmptyNotifications(t *testing.T) {
	src := &stubConnectIPPrefixSource{
		seq: [][]netip.Prefix{
			nil,
			{netip.MustParsePrefix("172.19.100.2/31")},
		},
	}
	got, err := waitForNonEmptyAssignedPrefixes(src, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].String() != "172.19.100.2/31" {
		t.Fatalf("unexpected prefixes: %v", got)
	}
}

func TestWaitForNonEmptyAssignedPrefixesTimeout(t *testing.T) {
	src := &stubConnectIPPrefixSource{}
	_, err := waitForNonEmptyAssignedPrefixes(src, 30*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}
