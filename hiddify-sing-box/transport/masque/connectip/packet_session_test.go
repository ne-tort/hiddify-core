package connectip

import (
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
)

func TestClientPacketSessionDatagramCeiling(t *testing.T) {
	session := &ClientPacketSession{datagramCeiling: 1280}
	_, err := session.WritePacket(make([]byte, 1400))
	if err == nil {
		t.Fatal("expected datagram ceiling error")
	}
}

func TestClientPacketSessionCloseKeepsSharedConn(t *testing.T) {
	sharedConn := &connectip.Conn{}
	session := NewClientPacketSession(ClientPacketSessionConfig{Conn: sharedConn})
	if err := session.Close(); err != nil {
		t.Fatalf("close wrapped connect-ip session: %v", err)
	}
	if session.Conn() != sharedConn {
		t.Fatal("expected close to keep shared connect-ip conn alive")
	}
}

func TestSessionBootstrapFromClientPacketSession(t *testing.T) {
	sharedConn := &connectip.Conn{}
	session := NewClientPacketSession(ClientPacketSessionConfig{
		Conn:            sharedConn,
		DatagramCeiling: 1400,
		OverlayH2:       true,
		ProfileLocalIPv4: "198.18.0.2",
	})
	boot := SessionBootstrapFrom(session)
	if boot.PrefixSource != sharedConn {
		t.Fatal("expected prefix source from underlying conn")
	}
	if boot.DatagramCeiling != 1400 || !boot.OverlayH2 {
		t.Fatalf("unexpected bootstrap: ceiling=%d overlayH2=%v", boot.DatagramCeiling, boot.OverlayH2)
	}
	if boot.ProfileLocalIPv4 != "198.18.0.2" {
		t.Fatalf("unexpected profile local v4: %q", boot.ProfileLocalIPv4)
	}
}

func TestUDPBridgeConfigFromClientPacketSession(t *testing.T) {
	sharedConn := &connectip.Conn{}
	pmtu := NewUDPPMTUState(1200, 512, 1400)
	session := NewClientPacketSession(ClientPacketSessionConfig{
		Conn:              sharedConn,
		DatagramCeiling:   1500,
		UDPPayloadHardCap: 1180,
		PMTUState:         pmtu,
		ProfileLocalIPv4:  "198.18.0.3",
	})
	cfg := UDPBridgeConfigFrom(session)
	if !cfg.OK {
		t.Fatal("expected ok bridge config")
	}
	if cfg.PrefixSource != sharedConn || cfg.PMTUState != pmtu {
		t.Fatal("unexpected prefix source or pmtu state")
	}
	if cfg.UDPPayloadHardCap != 1180 {
		t.Fatalf("unexpected udp hard cap: %d", cfg.UDPPayloadHardCap)
	}
	if cfg.DatagramCeiling != DatagramCeilingMax() {
		t.Fatalf("expected datagram ceiling clamped to max %d, got %d", DatagramCeilingMax(), cfg.DatagramCeiling)
	}
}
