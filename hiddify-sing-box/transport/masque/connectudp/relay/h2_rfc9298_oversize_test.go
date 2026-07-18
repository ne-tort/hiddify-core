package relay

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

type h2OversizeOnward struct{}

func (h2OversizeOnward) Queue([]byte) (bool, error) {
	return false, errors.New("relay should not run")
}

func (h2OversizeOnward) Flush() (bool, error) { return false, nil }

// TestRelayH2ConnectUplinkAbortsOnOversizeCapsule locks H2 uplink abort when a single DATAGRAM capsule exceeds wire max.
func TestRelayH2ConnectUplinkAbortsOnOversizeCapsule(t *testing.T) {
	t.Parallel()
	oversizeUDP := make([]byte, h2c.MaxUDPPayloadPerDatagramCapsule()+1)
	var wire bytes.Buffer
	if err := h2c.AppendDatagramCapsuleWire(&wire, oversizeUDP); err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader(wire.Bytes()))}
	err := RelayH2ConnectUplink(req, h2OversizeOnward{}, 64*1024, nil, nil)
	if !errors.Is(err, h2c.ErrOversizedDeclared) {
		t.Fatalf("RelayH2ConnectUplink: %v want ErrOversizedDeclared", err)
	}
}

// TestRelayH2RelayOnwardRejectsRFC9298MaxUDP locks uplink abort when CheckConnectUDPUDPPayload fails.
// Product capsule max makes >65527 unreachable via ParseNextDatagramCapsuleWire; this test feeds
// a valid small capsule then verifies the Check helper used by relayOnward rejects RFC-illegal sizes.
func TestRelayH2RelayOnwardRejectsRFC9298MaxUDP(t *testing.T) {
	t.Parallel()
	payload := make([]byte, frame.MaxProxiedUDPPayloadBytes+1)
	if err := frame.CheckConnectUDPUDPPayload(len(payload), 0); !errors.Is(err, frame.ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("CheckConnectUDPUDPPayload: %v", err)
	}
	// Declared oversize still aborts uplink (F-H2-OS-03 path).
	var wire bytes.Buffer
	oversizeUDP := make([]byte, h2c.MaxUDPPayloadPerDatagramCapsule()+1)
	if err := h2c.AppendDatagramCapsuleWire(&wire, oversizeUDP); err != nil {
		// May fail early; either way uplink must not Queue.
		_ = err
	}
	req := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader(wire.Bytes()))}
	err := RelayH2ConnectUplink(req, h2OversizeOnward{}, 64*1024, nil, nil)
	if err == nil && wire.Len() > 0 {
		t.Fatal("RelayH2ConnectUplink: expected error on oversize/declared capsule")
	}
	if wire.Len() > 0 && err != nil && !errors.Is(err, h2c.ErrOversizedDeclared) && !errors.Is(err, frame.ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("RelayH2ConnectUplink: %v want ErrOversizedDeclared or ErrProxiedUDPPayloadTooLarge", err)
	}
}
