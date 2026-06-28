package h2

import "testing"

func TestConnectUDPDialPolicyFromEnv(t *testing.T) {
	t.Setenv(envH2ConnectUDPAsymmetricDuplex, "0")
	t.Setenv(envH2ConnectUDPUploadStreams, "4")
	p := ConnectUDPDialPolicyFromEnv()
	if p.AsymmetricDuplex {
		t.Fatal("expected asymmetric duplex off")
	}
	if p.UploadStreams != 4 {
		t.Fatalf("upload streams: got %d want 4", p.UploadStreams)
	}
}

func TestConnectUDPDialPolicyFromEnvDefaults(t *testing.T) {
	t.Setenv(envH2ConnectUDPAsymmetricDuplex, "")
	t.Setenv(envH2ConnectUDPUploadStreams, "")
	p := ConnectUDPDialPolicyFromEnv()
	if !p.AsymmetricDuplex {
		t.Fatal("expected asymmetric duplex default on")
	}
	if p.UploadStreams != 1 {
		t.Fatalf("upload streams default: got %d want 1", p.UploadStreams)
	}
}
