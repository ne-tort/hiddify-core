package server

import (
	"errors"
	"testing"
)

func TestStartErrorStoreClearLoadNil(t *testing.T) {
	t.Parallel()
	var store StartErrorStore
	store.Clear()
	if err := store.Load(); err != nil {
		t.Fatalf("expected nil after clear, got %v", err)
	}
}

func TestStartErrorStoreStoreLoad(t *testing.T) {
	t.Parallel()
	var store StartErrorStore
	want := errors.New("serve stopped")
	store.Store(want)
	if got := store.Load(); got != want {
		t.Fatalf("Load()=%v want %v", got, want)
	}
}

func TestStartErrorStoreNilReceiverSafe(t *testing.T) {
	t.Parallel()
	var store *StartErrorStore
	store.Clear()
	if err := store.Load(); err != nil {
		t.Fatalf("nil store Load: %v", err)
	}
	store.Store(errors.New("ignored"))
}
