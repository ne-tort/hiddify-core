package masque

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestConnectIPBootstrapWaitPolicy(t *testing.T) {
	t.Run("relaxed_profile_local_fast_path", func(t *testing.T) {
		policy := newConnectIPBootstrapWaitPolicy(false, "172.16.0.2", "", 20*time.Second)
		if !policy.ProfileLocal {
			t.Fatal("expected profile local to be detected")
		}
		if policy.RequirePrefix {
			t.Fatal("expected relaxed policy")
		}
		if policy.FirstWait != connectIPBootstrapFastProfileWait {
			t.Fatalf("expected fast first wait, got %v", policy.FirstWait)
		}
		if !policy.SendRequestAddresses {
			t.Fatal("expected best-effort RequestAddresses")
		}
		if policy.RequestAddressesTimeout != connectIPBootstrapFastRequestTimeout {
			t.Fatalf("expected fast request timeout, got %v", policy.RequestAddressesTimeout)
		}
		if policy.SecondWait != connectIPBootstrapFastProfileWait {
			t.Fatalf("expected fast second wait, got %v", policy.SecondWait)
		}
		if !policy.AdvertiseProfileLocal {
			t.Fatal("expected profile-local advertise fallback")
		}
	})

	t.Run("relaxed_without_profile_local_preserves_cautious_waits", func(t *testing.T) {
		policy := newConnectIPBootstrapWaitPolicy(false, "", "", 6*time.Second)
		if policy.ProfileLocal {
			t.Fatal("did not expect profile local")
		}
		if policy.FirstWait != 10*time.Second {
			t.Fatalf("expected 10s first wait, got %v", policy.FirstWait)
		}
		if policy.SecondWait != 6*time.Second {
			t.Fatalf("expected relaxed 6s second wait, got %v", policy.SecondWait)
		}
		if policy.AdvertiseProfileLocal {
			t.Fatal("did not expect profile-local advertise fallback")
		}
	})

	t.Run("strict_preserves_full_prefix_requirement", func(t *testing.T) {
		policy := newConnectIPBootstrapWaitPolicy(true, "172.16.0.2", "", 6*time.Second)
		if !policy.RequirePrefix {
			t.Fatal("expected strict policy")
		}
		if !policy.ProfileLocal {
			t.Fatal("expected profile local to be detected")
		}
		if policy.FirstWait != 10*time.Second {
			t.Fatalf("expected 10s first wait, got %v", policy.FirstWait)
		}
		if policy.SecondWait != 20*time.Second {
			t.Fatalf("expected full strict second wait, got %v", policy.SecondWait)
		}
		if policy.AdvertiseProfileLocal {
			t.Fatal("strict mode must not advertise profile-local fallback")
		}
	})
}

func TestWaitForNonEmptyAssignedPrefixes(t *testing.T) {
	t.Run("returns_existing_snapshot_without_waiting", func(t *testing.T) {
		prefix := netip.MustParsePrefix("172.16.0.2/32")
		src := &fakeConnectIPPrefixSource{current: []netip.Prefix{prefix}}
		start := time.Now()
		prefixes, err := waitForNonEmptyAssignedPrefixes(src, time.Second)
		if err != nil {
			t.Fatalf("wait prefixes: %v", err)
		}
		if time.Since(start) > 50*time.Millisecond {
			t.Fatal("expected immediate return for existing snapshot")
		}
		if len(prefixes) != 1 || prefixes[0] != prefix {
			t.Fatalf("unexpected prefixes: %v", prefixes)
		}
	})

	t.Run("returns_when_notify_arrives_before_deadline", func(t *testing.T) {
		prefix := netip.MustParsePrefix("172.16.0.2/32")
		src := &fakeConnectIPPrefixSource{notify: make(chan []netip.Prefix, 1)}
		go func() {
			time.Sleep(20 * time.Millisecond)
			src.notify <- []netip.Prefix{prefix}
		}()
		start := time.Now()
		prefixes, err := waitForNonEmptyAssignedPrefixes(src, time.Second)
		if err != nil {
			t.Fatalf("wait prefixes: %v", err)
		}
		if elapsed := time.Since(start); elapsed >= time.Second {
			t.Fatalf("expected early return, took %v", elapsed)
		}
		if len(prefixes) != 1 || prefixes[0] != prefix {
			t.Fatalf("unexpected prefixes: %v", prefixes)
		}
	})

	t.Run("times_out_when_no_prefix_arrives", func(t *testing.T) {
		src := &fakeConnectIPPrefixSource{notify: make(chan []netip.Prefix)}
		start := time.Now()
		prefixes, err := waitForNonEmptyAssignedPrefixes(src, 25*time.Millisecond)
		if err == nil {
			t.Fatal("expected timeout")
		}
		if len(prefixes) != 0 {
			t.Fatalf("unexpected prefixes: %v", prefixes)
		}
		if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
			t.Fatalf("timeout returned too early: %v", elapsed)
		}
	})
}

type fakeConnectIPPrefixSource struct {
	current []netip.Prefix
	notify  chan []netip.Prefix
}

func (f *fakeConnectIPPrefixSource) CurrentAssignedPrefixes() []netip.Prefix {
	return slices.Clone(f.current)
}

func (f *fakeConnectIPPrefixSource) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case prefixes := <-f.notify:
		f.current = slices.Clone(prefixes)
		return slices.Clone(prefixes), nil
	}
}
