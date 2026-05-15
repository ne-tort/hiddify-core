package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"math/big"
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
		tlsPeerRequired:  true,
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
		tlsPeerRequired:  true,
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
		tlsPeerRequired:  true,
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

func mustReqWithAuth(t *testing.T, key, val string) *http.Request {
	t.Helper()
	r := &http.Request{Header: make(http.Header)}
	r.Header.Set(key, val)
	return r
}

func TestCompileMasqueServerAuth_leafSPKIRequiresInboundTLS(t *testing.T) {
	hex64 := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err := compileMasqueServerAuth(option.MasqueEndpointOptions{
		ServerAuth: &option.MasqueServerAuthOptions{
			ClientLeafSPKI_SHA256: []string{hex64},
		},
	})
	if err == nil {
		t.Fatal("expected error: leaf SPKI pins require mTLS (InboundTLS client authentication)")
	}
}

func TestAuthorizeRequest_leafSPKIPinMatchAndReject(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	var wrong [32]byte
	wrong[0] = 0xff

	a := &compiledMasqueServerAuth{
		policyFirstMatch: true,
		tlsPeerRequired:  true,
		httpConfigured:   false,
		leafSPKIHashes:   map[[32]byte]struct{}{want: {}},
	}
	reqOK := &http.Request{Header: make(http.Header), TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}}
	if !a.AuthorizeRequest(reqOK) {
		t.Fatal("expected SPKI pin match")
	}
	a2 := &compiledMasqueServerAuth{
		policyFirstMatch: true,
		tlsPeerRequired:  true,
		httpConfigured:   false,
		leafSPKIHashes:   map[[32]byte]struct{}{wrong: {}},
	}
	if a2.AuthorizeRequest(reqOK) {
		t.Fatal("expected SPKI pin reject")
	}
}
