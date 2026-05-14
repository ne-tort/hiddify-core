package masque

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestCompileMasqueServerAuth_legacyServerTokenOnly(t *testing.T) {
	a, err := compileMasqueServerAuth(option.MasqueEndpointOptions{ServerToken: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || !a.httpConfigured || !a.policyFirstMatch {
		t.Fatalf("unexpected compiled auth: %#v", a)
	}
	req := mustReqWithAuth(t, "Authorization", "Bearer secret")
	if !a.AuthorizeRequest(req) {
		t.Fatal("expected bearer match")
	}
	req2 := mustReqWithAuth(t, "Authorization", "Bearer wrong")
	if a.AuthorizeRequest(req2) {
		t.Fatal("expected bearer reject")
	}
}

func TestCompileMasqueServerAuth_firstMatchBearerOnly(t *testing.T) {
	a, err := compileMasqueServerAuth(option.MasqueEndpointOptions{
		ServerAuth: &option.MasqueServerAuthOptions{
			Policy:       option.MasqueServerAuthPolicyFirstMatch,
			BearerTokens: []string{"a"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !a.AuthorizeRequest(mustReqWithAuth(t, "Authorization", "Bearer a")) {
		t.Fatal("bearer should pass")
	}
	req := &http.Request{Header: make(http.Header)}
	if a.AuthorizeRequest(req) {
		t.Fatal("expected deny without creds when bearer ACL configured")
	}
}

func TestCompileMasqueServerAuth_allRequiredBearerOnly(t *testing.T) {
	a, err := compileMasqueServerAuth(option.MasqueEndpointOptions{
		ServerAuth: &option.MasqueServerAuthOptions{
			Policy:       option.MasqueServerAuthPolicyAllRequired,
			BearerTokens: []string{"x"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := mustReqWithAuth(t, "Authorization", "Bearer x")
	if !a.AuthorizeRequest(req) {
		t.Fatal("all_required with only http layer: bearer should suffice")
	}
}

func TestCompileMasqueServerAuth_basic(t *testing.T) {
	a, err := compileMasqueServerAuth(option.MasqueEndpointOptions{
		ServerAuth: &option.MasqueServerAuthOptions{
			BasicCredentials: []option.MasqueBasicCredential{{Username: "u", Password: "p"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	if !a.AuthorizeRequest(mustReqWithAuth(t, "Authorization", raw)) {
		t.Fatal("basic match")
	}
}

func TestCompileMasqueServerAuth_proxyAuthorization(t *testing.T) {
	a, err := compileMasqueServerAuth(option.MasqueEndpointOptions{ServerToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Header: make(http.Header)}
	req.Header.Set("Proxy-Authorization", "Bearer tok")
	if !a.AuthorizeRequest(req) {
		t.Fatal("proxy-auth bearer")
	}
}

func TestAuthorizeRequest_firstMatchTLSOrHTTP(t *testing.T) {
	a := &compiledMasqueServerAuth{
		policyFirstMatch: true,
		tlsConfigured:    true,
		httpConfigured:   true,
		bearerHashes:     map[[32]byte]struct{}{sha256SumBytes([]byte("tok")): {}},
	}
	reqNo := &http.Request{Header: make(http.Header)}
	if a.AuthorizeRequest(reqNo) {
		t.Fatal("expected deny without tls or http")
	}
	leaf := &x509.Certificate{Raw: []byte{9}}
	reqTLS := &http.Request{Header: make(http.Header), TLS: &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}}
	if !a.AuthorizeRequest(reqTLS) {
		t.Fatal("tls alone should pass first_match")
	}
	reqHTTP := mustReqWithAuth(t, "Authorization", "Bearer tok")
	if !a.AuthorizeRequest(reqHTTP) {
		t.Fatal("bearer alone should pass first_match")
	}
}

func TestAuthorizeRequest_allRequiredTLSAndHTTP(t *testing.T) {
	a := &compiledMasqueServerAuth{
		policyFirstMatch: false,
		tlsConfigured:    true,
		httpConfigured:   true,
		bearerHashes:     map[[32]byte]struct{}{sha256SumBytes([]byte("x")): {}},
	}
	leaf := &x509.Certificate{Raw: []byte{7}}
	reqTLSOnly := &http.Request{Header: make(http.Header), TLS: &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}}
	if a.AuthorizeRequest(reqTLSOnly) {
		t.Fatal("all_required needs http too")
	}
	reqBoth := mustReqWithAuth(t, "Authorization", "Bearer x")
	reqBoth.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if !a.AuthorizeRequest(reqBoth) {
		t.Fatal("both layers should pass")
	}
}

func TestAuthorizeRequest_mTLSVerifiedChain(t *testing.T) {
	a := &compiledMasqueServerAuth{
		policyFirstMatch: true,
		tlsConfigured:    true,
		httpConfigured:   false,
	}
	leaf := &x509.Certificate{Raw: []byte{1, 2, 3}}
	req := &http.Request{Header: make(http.Header), TLS: &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}}
	if !a.AuthorizeRequest(req) {
		t.Fatal("tls verified chain should satisfy first_match")
	}
}

func TestApplyTLSClientAuth_verifyIfGiven(t *testing.T) {
	a := &compiledMasqueServerAuth{tlsConfigured: true, clientCAs: x509.NewCertPool()}
	cfg := &tls.Config{}
	a.applyTLSClientAuth(cfg)
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("expected VerifyClientCertIfGiven, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs != a.clientCAs {
		t.Fatal("ClientCAs not set")
	}
}

func mustReqWithAuth(t *testing.T, key, val string) *http.Request {
	t.Helper()
	r := &http.Request{Header: make(http.Header)}
	r.Header.Set(key, val)
	return r
}
