package http2

import "testing"

type masqueWakeStubBody struct {
	wakeCalls int
}

func (b *masqueWakeStubBody) Read(p []byte) (int, error) { return 0, nil }

func (b *masqueWakeStubBody) Close() error { return nil }

func (b *masqueWakeStubBody) MasqueWakeRequestBodyWrite() { b.wakeCalls++ }

func TestMasqueWakeRequestBodyWriteDispatches(t *testing.T) {
	body := &masqueWakeStubBody{}
	masqueWakeRequestBodyWrite(body)
	if body.wakeCalls != 1 {
		t.Fatalf("masqueWakeRequestBodyWrite calls: got %d want 1", body.wakeCalls)
	}
}

func TestMasqueWakeRequestBodyWriteNilSafe(t *testing.T) {
	masqueWakeRequestBodyWrite(nil)
}
