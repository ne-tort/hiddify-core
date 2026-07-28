package config

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	cfAPIURL     = "https://api.cloudflareclient.com"
	cfAPIVersion = "v0a4471"
	cfKeyTypeWG  = "curve25519"
	cfTunTypeWG  = "wireguard"
	cfKeyTypeMQ  = "secp256r1"
	cfTunTypeMQ  = "masque"
)

// cfAPIRoot is the Cloudflare API origin (overridable in tests).
var cfAPIRoot = cfAPIURL

func cfAPIPath(path string) string {
	return cfAPIRoot + "/" + cfAPIVersion + path
}

var cfHeaders = map[string]string{
	"User-Agent":         "WARP for Android",
	"CF-Client-Version":  "a-6.35-4471",
	"Content-Type":       "application/json; charset=UTF-8",
	"Connection":         "Keep-Alive",
}

type cfRegistration struct {
	Key          string `json:"key"`
	InstallID    string `json:"install_id"`
	FcmToken     string `json:"fcm_token"`
	Tos          string `json:"tos"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	OsVersion    string `json:"os_version"`
	KeyType      string `json:"key_type"`
	TunnelType   string `json:"tunnel_type"`
	Locale       string `json:"locale"`
}

type cfDeviceUpdate struct {
	Key        string `json:"key"`
	KeyType    string `json:"key_type"`
	TunnelType string `json:"tunnel_type"`
	Name       string `json:"name,omitempty"`
}

type cfAccountData struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	Account struct {
		License  string `json:"license"`
		WarpPlus bool   `json:"warp_plus"`
		Type     string `json:"account_type"`
	} `json:"account"`
	Config struct {
		ClientID  string `json:"client_id"`
		Peers     []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func cfTOSNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func cfDoJSON(method, url string, headers map[string]string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return err
	}
	for k, v := range cfHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare api %s: %s: %s", method, resp.Status, string(raw))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func generateX25519Base64() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func generateECDSAP256() (privDERB64, pubDERB64 string, pubDER []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", nil, err
	}
	pubDER, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", nil, err
	}
	return base64.StdEncoding.EncodeToString(privDER),
		base64.StdEncoding.EncodeToString(pubDER),
		pubDER, nil
}

func stripEndpointPort(hostPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if strings.HasPrefix(hostPort, "[") {
		if i := strings.LastIndex(hostPort, "]"); i >= 0 {
			return hostPort[1:i]
		}
	}
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		return hostPort[:i]
	}
	return hostPort
}

// RegisterWarpWireGuard creates a free Cloudflare WARP WireGuard identity.
// Optional licenseKey binds WARP+ when non-empty and not a transport sentinel.
func RegisterWarpWireGuard(licenseKey string) (WarpAccount, WarpWireguardConfig, string, error) {
	privB64, pubB64, err := generateX25519Base64()
	if err != nil {
		return WarpAccount{}, WarpWireguardConfig{}, "", err
	}
	reg := cfRegistration{
		Key:          pubB64,
		Tos:          cfTOSNow(),
		Model:        "PC",
		SerialNumber: "",
		KeyType:      cfKeyTypeWG,
		TunnelType:   cfTunTypeWG,
		Locale:       "en_US",
	}
	var account cfAccountData
	if err := cfDoJSON("POST", cfAPIPath("/reg"), nil, reg, &account); err != nil {
		return WarpAccount{}, WarpWireguardConfig{}, "", err
	}
	if licenseKey != "" && licenseKey != WarpTransportMasque {
		_ = cfDoJSON("POST", cfAPIPath("/reg/"+account.ID+"/account"),
			map[string]string{"Authorization": "Bearer " + account.Token},
			map[string]string{"license": licenseKey}, &account)
	}
	if len(account.Config.Peers) == 0 {
		return WarpAccount{}, WarpWireguardConfig{}, "", fmt.Errorf("warp: empty peers in registration response")
	}
	cfg := WarpWireguardConfig{
		PrivateKey:       privB64,
		LocalAddressIPv4: account.Config.Interface.Addresses.V4,
		LocalAddressIPv6: account.Config.Interface.Addresses.V6,
		PeerPublicKey:    account.Config.Peers[0].PublicKey,
		ClientID:         account.Config.ClientID,
	}
	acc := WarpAccount{AccountID: account.ID, AccessToken: account.Token}
	log := fmt.Sprintf("Warp+ enabled: %t\nAccount type: %s\n", account.Account.WarpPlus, account.Account.Type)
	return acc, cfg, log, nil
}

// RegisterWarpMasque creates a Cloudflare account then enrolls an ECDSA MASQUE device key.
func RegisterWarpMasque() (WarpAccount, WarpMasqueConfig, string, error) {
	// Step 1: create account with a throwaway WG key (usque pattern).
	_, throwawayPub, err := generateX25519Base64()
	if err != nil {
		return WarpAccount{}, WarpMasqueConfig{}, "", err
	}
	reg := cfRegistration{
		Key:        throwawayPub,
		Tos:        cfTOSNow(),
		Model:      "PC",
		KeyType:    cfKeyTypeWG,
		TunnelType: cfTunTypeWG,
		Locale:     "en_US",
	}
	var account cfAccountData
	if err := cfDoJSON("POST", cfAPIPath("/reg"), nil, reg, &account); err != nil {
		return WarpAccount{}, WarpMasqueConfig{}, "", err
	}
	if account.ID == "" || account.Token == "" {
		return WarpAccount{}, WarpMasqueConfig{}, "", fmt.Errorf("warp masque: missing account id/token")
	}

	privB64, _, pubDER, err := generateECDSAP256()
	if err != nil {
		return WarpAccount{}, WarpMasqueConfig{}, "", err
	}
	update := cfDeviceUpdate{
		Key:        base64.StdEncoding.EncodeToString(pubDER),
		KeyType:    cfKeyTypeMQ,
		TunnelType: cfTunTypeMQ,
		Name:       "Hiddify",
	}
	if err := cfDoJSON("PATCH", cfAPIPath("/reg/"+account.ID),
		map[string]string{"Authorization": "Bearer " + account.Token},
		update, &account); err != nil {
		return WarpAccount{}, WarpMasqueConfig{}, "", err
	}
	if len(account.Config.Peers) == 0 {
		return WarpAccount{}, WarpMasqueConfig{}, "", fmt.Errorf("warp masque: empty peers after enroll")
	}
	peer := account.Config.Peers[0]
	server := stripEndpointPort(peer.Endpoint.V4)
	if server == "" {
		server = stripEndpointPort(peer.Endpoint.Host)
	}
	if server == "" {
		server = "162.159.198.1"
	}
	cfg := WarpMasqueConfig{
		PrivateKey:  privB64,
		PublicKey:   peer.PublicKey,
		IPv4:        account.Config.Interface.Addresses.V4,
		IPv6:        account.Config.Interface.Addresses.V6,
		Server:      server,
		ServerPort:  443,
		ClientID:    account.Config.ClientID,
		AccountID:   account.ID,
		AccessToken: account.Token,
	}
	acc := WarpAccount{AccountID: account.ID, AccessToken: account.Token}
	log := fmt.Sprintf("MASQUE enrolled\nAccount type: %s\nServer: %s\n", account.Account.Type, server)
	return acc, cfg, log, nil
}
