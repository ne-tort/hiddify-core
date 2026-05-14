package masque

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// compiledMasqueServerAuth holds precomputed ACL state for MASQUE server HTTP+TLS authorization.
type compiledMasqueServerAuth struct {
	policyFirstMatch bool

	tlsConfigured bool
	clientCAs     *x509.CertPool

	httpConfigured bool
	bearerHashes     map[[sha256.Size]byte]struct{}
	basicHashes      map[[sha256.Size]byte]struct{}
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

func basicCredentialHash(user, pass string) [sha256.Size]byte {
	u := strings.TrimSpace(user)
	return sha256SumBytes([]byte(u + "\x00" + pass))
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
	}
	if legacy != "" {
		mergeBearerTokenHashes(bearerHashes, []string{legacy})
	}

	var pool *x509.CertPool
	if auth != nil && auth.MTLS != nil {
		m := auth.MTLS
		pemCount := 0
		for _, pemStr := range m.ClientCAPEM {
			if strings.TrimSpace(pemStr) == "" {
				continue
			}
			pemCount++
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM([]byte(pemStr)) {
				return nil, E.New("masque server_auth: failed to parse client_ca_pem")
			}
		}
		for _, pemStr := range m.TrustedClientCertPEM {
			pemStr = strings.TrimSpace(pemStr)
			if pemStr == "" {
				continue
			}
			pemCount++
			if pool == nil {
				pool = x509.NewCertPool()
			}
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				return nil, E.New("masque server_auth: trusted_client_cert_pem: no PEM block")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, E.Cause(err, "masque server_auth: trusted_client_cert_pem")
			}
			pool.AddCert(cert)
		}
		if pemCount == 0 {
			pool = nil
		}
	}

	httpConfigured := len(bearerHashes) > 0 || len(basicMap) > 0
	tlsConfigured := pool != nil

	if !httpConfigured && !tlsConfigured {
		return nil, nil
	}

	return &compiledMasqueServerAuth{
		policyFirstMatch: policy == option.MasqueServerAuthPolicyFirstMatch,
		tlsConfigured:    tlsConfigured,
		clientCAs:        pool,
		httpConfigured:   httpConfigured,
		bearerHashes:     bearerHashes,
		basicHashes:      basicMap,
	}, nil
}

func (a *compiledMasqueServerAuth) applyTLSClientAuth(cfg *tls.Config) {
	if a == nil || !a.tlsConfigured || a.clientCAs == nil || cfg == nil {
		return
	}
	// VerifyClientCertIfGiven: optional client cert at TLS, verified against ClientCAs when present.
	// Final access control stays in AuthorizeRequest (tlsPeerOK vs HTTP Basic/Bearer, first_match / all_required).
	// RequireAndVerifyClientCert would block HTTP-only clients when server_auth combines mTLS CA + Bearer/Basic.
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	cfg.ClientCAs = a.clientCAs
}

func (a *compiledMasqueServerAuth) tlsPeerOK(r *http.Request) bool {
	if !a.tlsConfigured {
		return true
	}
	if r == nil || r.TLS == nil {
		return false
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
	// Only evaluate layers that were configured; an absent layer must not make
	// first_match succeed when the other layer is the sole real requirement.
	if a.policyFirstMatch {
		switch {
		case a.tlsConfigured && a.httpConfigured:
			return a.tlsPeerOK(r) || a.httpCredentialsOK(r)
		case a.tlsConfigured:
			return a.tlsPeerOK(r)
		default:
			return a.httpCredentialsOK(r)
		}
	}
	// all_required
	switch {
	case a.tlsConfigured && a.httpConfigured:
		return a.tlsPeerOK(r) && a.httpCredentialsOK(r)
	case a.tlsConfigured:
		return a.tlsPeerOK(r)
	default:
		return a.httpCredentialsOK(r)
	}
}
