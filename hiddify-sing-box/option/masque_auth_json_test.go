package option

import (
	"encoding/json"
	"testing"
)

func TestMasqueServerAuthJSONShortKeys(t *testing.T) {
	raw := `{
		"policy": "first_match",
		"bearer": ["alpha", "beta"],
		"sha256": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
		"basics": [{"user": "alice", "pass": "x"}, {"username": "bob", "password": "y"}],
		"mtls": {
			"ca": ["-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHfhwIDAQABMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjYwNTEyMDAwMDAwWhcNMzYwNTEyMDAwMDAwWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALxx\n-----END CERTIFICATE-----\n"],
			"trust": []
		}
	}`
	var a MasqueServerAuthOptions
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatal(err)
	}
	if len(a.BearerTokens) != 2 || a.BearerTokens[0] != "alpha" {
		t.Fatalf("bearer: %+v", a.BearerTokens)
	}
	if len(a.BearerTokenSHA256) != 1 {
		t.Fatalf("sha256: %+v", a.BearerTokenSHA256)
	}
	if len(a.BasicCredentials) != 2 || a.BasicCredentials[0].Username != "alice" || a.BasicCredentials[1].Username != "bob" {
		t.Fatalf("basics: %+v", a.BasicCredentials)
	}
	if a.MTLS == nil || len(a.MTLS.ClientCAPEM) != 1 {
		t.Fatalf("mtls ca: %+v", a.MTLS)
	}
}
