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
		"basics": [{"user": "alice", "pass": "x"}, {"username": "bob", "password": "y"}]
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
}
