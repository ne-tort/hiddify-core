package masque

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// compiledMasqueServerAuth holds precomputed ACL state for MASQUE server HTTP authorization.
type compiledMasqueServerAuth struct {
	policyFirstMatch bool

	tlsPeerRequired bool

	httpConfigured bool
	bearerHashes     map[[sha256.Size]byte]struct{}
	basicHashes      map[[sha256.Size]byte]struct{}
	leafSPKIHashes   map[[sha256.Size]byte]struct{}
}

func sha256SumBytes(b []byte) [sha256.Size]byte {
	return sha256.Sum256(b)
}

func mergeBearerTokenHashes(dst map[[sha256.Size]byte]struct{}, tokens []string) {
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		h := sha256SumBytes([]byte(t))
		dst[h] = struct{}{}
	}
}

func parseBearerSHA256HexEntries(entries []string, dst map[[sha256.Size]byte]struct{}) error {
	for _, s := range entries {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if len(s) != sha256.Size*2 {
			return E.New("masque server_auth: bearer_token_sha256 must be 64 hex chars, got length ", len(s))
		}
		var h [sha256.Size]byte
		_, err := hex.Decode(h[:], []byte(s))
		if err != nil {
			return E.Cause(err, "masque server_auth: invalid bearer_token_sha256 hex")
		}
		dst[h] = struct{}{}
	}
	return nil
}

func parseLeafSPKIHexEntries(entries []string, dst map[[sha256.Size]byte]struct{}) error {
	for _, s := range entries {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if len(s) != sha256.Size*2 {
			return E.New("masque server_auth: client_leaf_spki_sha256 must be 64 hex chars, got length ", len(s))
		}
		var h [sha256.Size]byte
		_, err := hex.Decode(h[:], []byte(s))
		if err != nil {
			return E.Cause(err, "masque server_auth: invalid client_leaf_spki_sha256 hex")
		}
		dst[h] = struct{}{}
	}
	return nil
}

func basicCredentialHash(user, pass string) [sha256.Size]byte {
	u := strings.TrimSpace(user)
	return sha256SumBytes([]byte(u + "\x00" + pass))
}

func inboundTLSRequiresVerifiedClientPeer(t *option.InboundTLSOptions) bool {
	if t == nil {
		return false
	}
	switch tls.ClientAuthType(t.ClientAuthentication) {
	case tls.NoClientCert:
		return false
	default:
		return true
	}
}

func compileMasqueServerAuth(o option.MasqueEndpointOptions) (*compiledMasqueServerAuth, error) {
	auth := o.ServerAuth
	legacy := strings.TrimSpace(o.ServerToken)

	var policy string
	if auth != nil {
		policy = strings.TrimSpace(strings.ToLower(auth.Policy))
	}
	if policy == "" {
		policy = option.MasqueServerAuthPolicyFirstMatch
	}
	if policy != option.MasqueServerAuthPolicyFirstMatch && policy != option.MasqueServerAuthPolicyAllRequired {
		return nil, E.New("masque server_auth: invalid policy (use first_match or all_required)")
	}

	bearerHashes := make(map[[sha256.Size]byte]struct{})
	basicMap := make(map[[sha256.Size]byte]struct{})
	leafSPKIHashes := make(map[[sha256.Size]byte]struct{})
	if auth != nil {
		mergeBearerTokenHashes(bearerHashes, auth.BearerTokens)
		if err := parseBearerSHA256HexEntries(auth.BearerTokenSHA256, bearerHashes); err != nil {
			return nil, err
		}
		for _, c := range auth.BasicCredentials {
			u := strings.TrimSpace(c.Username)
			if u == "" {
				continue
			}
			h := basicCredentialHash(u, c.Password)
			basicMap[h] = struct{}{}
		}
		if err := parseLeafSPKIHexEntries(auth.ClientLeafSPKI_SHA256, leafSPKIHashes); err != nil {
			return nil, err
		}
	}
	if legacy != "" {
		mergeBearerTokenHashes(bearerHashes, []string{legacy})
	}

	httpConfigured := len(bearerHashes) > 0 || len(basicMap) > 0
	tlsPeerRequired := inboundTLSRequiresVerifiedClientPeer(o.InboundTLS)
	if len(leafSPKIHashes) > 0 && !tlsPeerRequired {
		return nil, E.New("masque server_auth: client_leaf_spki_sha256 requires InboundTLS client authentication (mTLS)")
	}

	if !httpConfigured && !tlsPeerRequired {
		return nil, nil
	}

	return &compiledMasqueServerAuth{
		policyFirstMatch: policy == option.MasqueServerAuthPolicyFirstMatch,
		tlsPeerRequired:  tlsPeerRequired,
		httpConfigured:   httpConfigured,
		bearerHashes:     bearerHashes,
		basicHashes:      basicMap,
		leafSPKIHashes:   leafSPKIHashes,
	}, nil
}

func (a *compiledMasqueServerAuth) tlsPeerOK(r *http.Request) bool {
	if !a.tlsPeerRequired {
		return true
	}
	if r == nil || r.TLS == nil {
		return false
	}
	var leaf *x509.Certificate
	if len(r.TLS.PeerCertificates) > 0 {
		leaf = r.TLS.PeerCertificates[0]
	} else if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		leaf = r.TLS.VerifiedChains[0][0]
	}
	if leaf == nil {
		return false
	}
	if len(a.leafSPKIHashes) > 0 {
		h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		_, ok := a.leafSPKIHashes[h]
		return ok
	}
	return len(r.TLS.VerifiedChains) > 0
}

func bearerFromAuthHeader(raw string) (token string, ok bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 7+1 {
		return "", false
	}
	if !strings.EqualFold(raw[:7], "bearer ") {
		return "", false
	}
	return strings.TrimSpace(raw[7:]), true
}

func basicFromAuthHeader(raw string) (user, pass string, ok bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 6+1 {
		return "", "", false
	}
	if !strings.EqualFold(raw[:6], "basic ") {
		return "", "", false
	}
	payload := strings.TrimSpace(raw[6:])
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", "", false
	}
	s := string(b)
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

func checkHTTPAuthHeader(header string, a *compiledMasqueServerAuth) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if tok, ok := bearerFromAuthHeader(header); ok && tok != "" {
		h := sha256SumBytes([]byte(tok))
		_, hit := a.bearerHashes[h]
		return hit
	}
	if u, p, ok := basicFromAuthHeader(header); ok {
		h := basicCredentialHash(u, p)
		_, hit := a.basicHashes[h]
		return hit
	}
	return false
}

func (a *compiledMasqueServerAuth) httpCredentialsOK(r *http.Request) bool {
	if !a.httpConfigured {
		return true
	}
	if checkHTTPAuthHeader(r.Header.Get("Authorization"), a) {
		return true
	}
	return checkHTTPAuthHeader(r.Header.Get("Proxy-Authorization"), a)
}

// AuthorizeRequest returns whether the request may access MASQUE handlers.
func (a *compiledMasqueServerAuth) AuthorizeRequest(r *http.Request) bool {
	if a == nil {
		return true
	}
	if a.policyFirstMatch {
		switch {
		case a.tlsPeerRequired && a.httpConfigured:
			return a.tlsPeerOK(r) || a.httpCredentialsOK(r)
		case a.tlsPeerRequired:
			return a.tlsPeerOK(r)
		default:
			return a.httpCredentialsOK(r)
		}
	}
	switch {
	case a.tlsPeerRequired && a.httpConfigured:
		return a.tlsPeerOK(r) && a.httpCredentialsOK(r)
	case a.tlsPeerRequired:
		return a.tlsPeerOK(r)
	default:
		return a.httpCredentialsOK(r)
	}
}
