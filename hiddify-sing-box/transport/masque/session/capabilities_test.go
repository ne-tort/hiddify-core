package session_test

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestOverlayCapabilitySetDatagramsTracksHTTPLayer(t *testing.T) {
	base := session.CapabilitySet{
		ExtendedConnect: true,
		Datagrams:       false,
		CapsuleProtocol: true,
		ConnectUDP:      true,
		ConnectIP:       true,
	}

	if got := session.OverlayCapabilitySet(base, option.MasqueHTTPLayerH2); got.Datagrams {
		t.Fatal("expected Datagrams=false on h2 overlay")
	}
	if got := session.OverlayCapabilitySet(base, option.MasqueHTTPLayerH3); !got.Datagrams {
		t.Fatal("expected Datagrams=true on h3 overlay after rotation from h2-effective ctor")
	}

	h3Base := base
	h3Base.Datagrams = true
	if got := session.OverlayCapabilitySet(h3Base, option.MasqueHTTPLayerH3); !got.Datagrams {
		t.Fatal("expected Datagrams=true on h3 overlay with h3-effective ctor")
	}
	if got := session.OverlayCapabilitySet(h3Base, option.MasqueHTTPLayerH2); got.Datagrams {
		t.Fatal("expected Datagrams=false on h2 overlay with h3-effective ctor")
	}
}
