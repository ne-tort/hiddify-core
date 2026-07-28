package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mockCFAccountResponse() cfAccountData {
	var account cfAccountData
	account.ID = "acc-test"
	account.Token = "tok-test"
	account.Account.Type = "free"
	account.Config.ClientID = "AQID"
	account.Config.Interface.Addresses.V4 = "172.16.0.2/32"
	account.Config.Interface.Addresses.V6 = "2606:4700:110::1/128"
	account.Config.Peers = []struct {
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			V4   string `json:"v4"`
			V6   string `json:"v6"`
			Host string `json:"host"`
		} `json:"endpoint"`
	}{{
		PublicKey: "peer-pub-key",
	}}
	account.Config.Peers[0].Endpoint.V4 = "162.159.198.2:443"
	return account
}

func withMockCFAPI(t *testing.T, handler http.HandlerFunc, fn func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	oldRoot := cfAPIRoot
	cfAPIRoot = srv.URL
	t.Cleanup(func() { cfAPIRoot = oldRoot })
	fn()
}

func TestRegisterWarpWireGuardMockHTTP(t *testing.T) {
	withMockCFAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/reg") {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var reg cfRegistration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			t.Fatal(err)
		}
		if reg.KeyType != cfKeyTypeWG || reg.TunnelType != cfTunTypeWG || reg.Key == "" {
			t.Fatalf("bad registration body: %+v", reg)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockCFAccountResponse())
	}, func() {
		acc, cfg, _, err := RegisterWarpWireGuard("")
		if err != nil {
			t.Fatal(err)
		}
		if acc.AccountID != "acc-test" || acc.AccessToken != "tok-test" {
			t.Fatalf("account=%+v", acc)
		}
		if cfg.PeerPublicKey != "peer-pub-key" || cfg.LocalAddressIPv4 == "" {
			t.Fatalf("cfg=%+v", cfg)
		}
		if cfg.PrivateKey == "" {
			t.Fatal("expected generated private key")
		}
	})
}

func TestRegisterWarpMasqueMockHTTP(t *testing.T) {
	calls := 0
	withMockCFAPI(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reg"):
			_ = json.NewEncoder(w).Encode(mockCFAccountResponse())
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/reg/acc-test"):
			var upd cfDeviceUpdate
			if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
				t.Fatal(err)
			}
			if upd.KeyType != cfKeyTypeMQ || upd.TunnelType != cfTunTypeMQ || upd.Key == "" {
				t.Fatalf("bad masque enroll body: %+v", upd)
			}
			resp := mockCFAccountResponse()
			resp.Config.Peers[0].PublicKey = "masque-endpoint-pub"
			_ = json.NewEncoder(w).Encode(resp)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}, func() {
		acc, cfg, _, err := RegisterWarpMasque()
		if err != nil {
			t.Fatal(err)
		}
		if calls != 2 {
			t.Fatalf("expected 2 API calls, got %d", calls)
		}
		if acc.AccountID != "acc-test" {
			t.Fatalf("account=%+v", acc)
		}
		if cfg.PublicKey != "masque-endpoint-pub" || cfg.Server != "162.159.198.2" {
			t.Fatalf("cfg=%+v", cfg)
		}
		if cfg.ServerPort != 443 || cfg.PrivateKey == "" {
			t.Fatalf("cfg=%+v", cfg)
		}
	})
}

func TestRegisterWarpWireGuardAPIError(t *testing.T) {
	withMockCFAPI(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}, func() {
		_, _, _, err := RegisterWarpWireGuard("")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "403") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
