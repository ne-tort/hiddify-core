package masque

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

type connectIPPrefixSource interface {
	CurrentAssignedPrefixes() []netip.Prefix
	LocalPrefixes(ctx context.Context) ([]netip.Prefix, error)
}

// waitForNonEmptyAssignedPrefixes waits for a non-empty ADDRESS_ASSIGN snapshot.
// Some edges can emit interim empty assignments before the final prefix set.
func waitForNonEmptyAssignedPrefixes(src connectIPPrefixSource, wait time.Duration) ([]netip.Prefix, error) {
	if src == nil {
		return nil, errors.New("connect-ip prefix source is nil")
	}
	if prefixes := src.CurrentAssignedPrefixes(); len(prefixes) > 0 {
		return prefixes, nil
	}
	if wait <= 0 {
		return nil, context.DeadlineExceeded
	}

	deadline := time.Now().Add(wait)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		prefixes, err := src.LocalPrefixes(ctx)
		cancel()
		if len(prefixes) > 0 {
			return prefixes, nil
		}
		if err == nil {
			continue
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			if prefixes := src.CurrentAssignedPrefixes(); len(prefixes) > 0 {
				return prefixes, nil
			}
			if time.Now().Before(deadline) {
				continue
			}
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
}
