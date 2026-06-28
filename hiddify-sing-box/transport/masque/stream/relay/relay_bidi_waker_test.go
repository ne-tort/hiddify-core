package relay

import (
	"bytes"
	"io"
	"testing"
)

func TestRelayBidiWakerNilForNonH3Leg(t *testing.T) {
	if relayBidiWakerFromRW(nil) != nil {
		t.Fatal("nil leg")
	}
	if relayBidiWakerFromRW(nopRelayRW{}) != nil {
		t.Fatal("non-stream leg")
	}
	if relayBidiWakerFromWriter(bytes.NewBuffer(nil)) != nil {
		t.Fatal("non-stream writer")
	}
}

type nopRelayRW struct{}

func (nopRelayRW) Read([]byte) (int, error)  { return 0, io.EOF }
func (nopRelayRW) Write([]byte) (int, error) { return 0, nil }
func (nopRelayRW) Close() error              { return nil }
