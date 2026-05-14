package option

import (
	stdjson "encoding/json"
)

// UnmarshalJSON accepts short keys alongside the long-form fields:
//   bearer  -> merged into bearer_tokens
//   sha256  -> merged into bearer_token_sha256
//   basics  -> merged into basic_credentials
// mtls (MasqueServerMTLSOptions): ca / trust -> client_ca_pem / trusted_client_cert_pem
func (a *MasqueServerAuthOptions) UnmarshalJSON(data []byte) error {
	type aux struct {
		Policy             string                   `json:"policy"`
		BearerTokens       []string                 `json:"bearer_tokens"`
		Bearer             []string                 `json:"bearer"`
		BearerTokenSHA256  []string                 `json:"bearer_token_sha256"`
		Sha256             []string                 `json:"sha256"`
		BasicCredentials   []MasqueBasicCredential  `json:"basic_credentials"`
		Basics             []MasqueBasicCredential  `json:"basics"`
		MTLS               *MasqueServerMTLSOptions `json:"mtls"`
	}
	var j aux
	if err := stdjson.Unmarshal(data, &j); err != nil {
		return err
	}
	a.Policy = j.Policy
	a.BearerTokens = append(append([]string{}, j.BearerTokens...), j.Bearer...)
	a.BearerTokenSHA256 = append(append([]string{}, j.BearerTokenSHA256...), j.Sha256...)
	a.BasicCredentials = append(append([]MasqueBasicCredential{}, j.BasicCredentials...), j.Basics...)
	a.MTLS = j.MTLS
	return nil
}

func (m *MasqueServerMTLSOptions) UnmarshalJSON(data []byte) error {
	type aux struct {
		ClientCAPEM          []string `json:"client_ca_pem"`
		CA                   []string `json:"ca"`
		TrustedClientCertPEM []string `json:"trusted_client_cert_pem"`
		Trust                []string `json:"trust"`
	}
	var j aux
	if err := stdjson.Unmarshal(data, &j); err != nil {
		return err
	}
	m.ClientCAPEM = append(append([]string{}, j.ClientCAPEM...), j.CA...)
	m.TrustedClientCertPEM = append(append([]string{}, j.TrustedClientCertPEM...), j.Trust...)
	return nil
}

// UnmarshalJSON accepts user/pass short keys.
func (b *MasqueBasicCredential) UnmarshalJSON(data []byte) error {
	type aux struct {
		Username string `json:"username"`
		Password string `json:"password"`
		User     string `json:"user"`
		Pass     string `json:"pass"`
	}
	var j aux
	if err := stdjson.Unmarshal(data, &j); err != nil {
		return err
	}
	b.Username = j.Username
	if b.Username == "" {
		b.Username = j.User
	}
	b.Password = j.Password
	if b.Password == "" {
		b.Password = j.Pass
	}
	return nil
}
