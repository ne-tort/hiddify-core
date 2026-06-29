package h2

import "testing"

func TestConnectUDPDialPolicyProdDefaults(t *testing.T) {
	p := ConnectUDPDialPolicyFromEnv()
	if !p.AsymmetricDuplex {
		t.Fatal("expected asymmetric duplex on")
	}
	if p.UploadStreams != 1 {
		t.Fatalf("upload streams: got %d want 1", p.UploadStreams)
	}
}
