package option

import (
	"encoding/json"
	"testing"
)

func TestAwgPeerOptionsPreSharedKeyJSON(t *testing.T) {
	const raw = `{"address":"x.example","port":51820,"public_key":"abc","pre_shared_key":"psk1","allowed_ips":["0.0.0.0/0"]}`
	var p AwgPeerOptions
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.PreSharedKey != "psk1" {
		t.Fatalf("got %q", p.PreSharedKey)
	}
}
