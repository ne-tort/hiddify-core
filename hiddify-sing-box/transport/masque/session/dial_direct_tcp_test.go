package session

import (
	"context"
	"errors"
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDialDirectTCPRejectsInvalidDestination(t *testing.T) {
	_, err := DialDirectTCP(context.Background(), nil, "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected direct tcp dial to reject invalid destination")
	}
	if !errors.Is(err, strm.Errs.Capability) {
		t.Fatalf("expected capability error for invalid destination, got: %v", err)
	}
}
