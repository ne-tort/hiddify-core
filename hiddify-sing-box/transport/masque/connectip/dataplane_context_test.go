package connectip

import (
	"context"
	"testing"
)

func TestDataplaneContextDoesNotInheritOpenCancel(t *testing.T) {
	t.Parallel()
	type ctxKey struct{}
	parent := context.WithValue(context.Background(), ctxKey{}, "marker")
	parent, cancel := context.WithCancel(parent)
	cancel()
	if parent.Err() == nil {
		t.Fatal("parent context should be canceled")
	}
	dc := DataplaneContext(parent)
	if dc.Err() != nil {
		t.Fatalf("dataplane context must not inherit open cancellation: %v", dc.Err())
	}
	if got, _ := dc.Value(ctxKey{}).(string); got != "marker" {
		t.Fatalf("expected context values preserved from parent, got %q", got)
	}
}
