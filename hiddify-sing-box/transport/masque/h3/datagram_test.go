package h3

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func TestH3DatagramMTUClamp(t *testing.T) {
	t.Run("UDPWriteMax_default_ceiling", func(t *testing.T) {
		ceiling := cip.DefaultDatagramCeilingMax
		hardCap := 65535
		got := UDPWriteMax(ceiling, hardCap)
		want := ceiling - UDPDatagramWriteSlack
		if got != want {
			t.Fatalf("UDPWriteMax(%d, %d) = %d, want %d", ceiling, hardCap, got, want)
		}
	})

	t.Run("UDPWriteMax_floor_512", func(t *testing.T) {
		got := UDPWriteMax(600, 65535)
		if got != UDPWriteMin {
			t.Fatalf("UDPWriteMax(600) = %d, want floor %d", got, UDPWriteMin)
		}
	})

	t.Run("UDPWriteMax_hard_cap", func(t *testing.T) {
		got := UDPWriteMax(1500, 900)
		if got != 900 {
			t.Fatalf("UDPWriteMax(1500, 900) = %d, want hard cap 900", got)
		}
	})

	t.Run("SplitPayloadSizes", func(t *testing.T) {
		max := UDPWriteMax(cip.DefaultDatagramCeilingMax, 65535)
		payloadLen := max + max + 100
		sizes := SplitPayloadSizes(payloadLen, max)
		sum := 0
		for _, n := range sizes {
			if n <= 0 || n > max {
				t.Fatalf("invalid chunk size %d with max %d", n, max)
			}
			sum += n
		}
		if sum != payloadLen {
			t.Fatalf("chunk sum %d != payload %d", sum, payloadLen)
		}
		if len(sizes) != 3 {
			t.Fatalf("expected 3 datagrams, got %v", sizes)
		}
	})
}

func TestApplyWarpTransportFieldsCfConnectIP(t *testing.T) {
	tr := &http3.Transport{}
	ApplyWarpTransportFields(tr, WarpTransportOptions{CfConnectIP: true})
	if tr.AdditionalSettings == nil || tr.AdditionalSettings[CloudflareLegacyH3DatagramSettingID] != 1 {
		t.Fatalf("expected legacy H3 datagram setting, got %#v", tr.AdditionalSettings)
	}
	if !tr.DisableCompression {
		t.Fatal("expected DisableCompression")
	}
}

func TestApplyWarpTransportFieldsNoop(t *testing.T) {
	tr := &http3.Transport{}
	ApplyWarpTransportFields(tr, WarpTransportOptions{})
	if len(tr.AdditionalSettings) > 0 {
		t.Fatalf("unexpected AdditionalSettings: %#v", tr.AdditionalSettings)
	}
}
