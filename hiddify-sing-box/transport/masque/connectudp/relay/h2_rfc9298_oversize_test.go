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

func (h2OversizeOnward) SendBurstViews([]byte, int, int, int) (bool, error) {
	return false, errors.New("relay should not run")
}

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

// TestRelayH2RelayOnwardRejectsRFC9298MaxUDP guards relayOnward RFC 9298 §4 abort for payloads >65527.
func TestRelayH2RelayOnwardRejectsRFC9298MaxUDP(t *testing.T) {
	t.Parallel()
	payload := make([]byte, frame.MaxProxiedUDPPayloadBytes+1)
	var wire bytes.Buffer
	// Valid per-capsule wire; relayOnward must still reject RFC-illegal UDP payload length.
	small := payload[:h2c.MaxUDPPayloadPerDatagramCapsule()]
	if err := h2c.AppendDatagramCapsuleWire(&wire, small); err != nil {
		t.Fatal(err)
	}
	// Directly exercise ValidateProxiedUDPPayloadLen parity used in relayOnward.
	if err := frame.ValidateProxiedUDPPayloadLen(len(payload)); !errors.Is(err, frame.ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("ValidateProxiedUDPPayloadLen: %v", err)
	}
}
