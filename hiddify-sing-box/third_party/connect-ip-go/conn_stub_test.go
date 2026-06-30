package connectip

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestErrTransportUnsetOnBareConn(t *testing.T) {
	var c Conn
	_, err := c.ReadPacketWithContext(context.Background(), make([]byte, 4))
	if !errors.Is(err, ErrTransportUnset) {
		t.Fatalf("got %v want ErrTransportUnset", err)
	}
}

func TestStubIngressConnProbeBlocksUntilDeadline(t *testing.T) {
	c := NewStubIngressConn()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.ReadPacketWithContext(ctx, make([]byte, 4))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v want deadline exceeded", err)
	}
}
