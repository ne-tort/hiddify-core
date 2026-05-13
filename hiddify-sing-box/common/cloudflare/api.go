package cloudflare

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/tidwall/gjson"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type CloudflareApi struct {
	client http.Client
}

var (
	ErrCloudflareUnauthorized   = errors.New("cloudflare api unauthorized")
	ErrCloudflareRateLimited    = errors.New("cloudflare api rate limited")
	ErrCloudflareServerError    = errors.New("cloudflare api server error")
	ErrCloudflareUnexpectedCode = errors.New("cloudflare api unexpected status code")
)

const baseUrl = "https://api.cloudflareclient.com/v0i1909051800/"

// warpMasqueEnrollAPIPrefix is the Cloudflare WARP client API version usque uses for MASQUE ECDSA enroll (PATCH /reg/{id}).
// Other control-plane calls stay on baseUrl (sing-box historical iOS-style CreateProfile).
const warpMasqueEnrollAPIPrefix = "https://api.cloudflareclient.com/v0a4471"

// applyCloudflareAndroidClientHeaders mimics Diniboy1123/usque internal.Headers for WARP Android API compatibility.
func applyCloudflareAndroidClientHeaders(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "WARP for Android")
	}
	req.Header.Set("CF-Client-Version", "a-6.35-4471")
	req.Header.Set("Connection", "Keep-Alive")
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}
}

// masqueDeviceUpdate mirrors Diniboy1123/usque models.DeviceUpdate JSON tags (key, key_type, tunnel_type, name).
type masqueDeviceUpdate struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

// EnrollMasqueDeviceKey registers a MASQUE device public key (PKIX DER, base64 in JSON) via PATCH /reg/{id}.
// Field semantics match usque EnrollKey: key_type secp256r1, tunnel_type masque, Android client headers, API v0a4471.
func (api *CloudflareApi) EnrollMasqueDeviceKey(ctx context.Context, authToken, deviceID string, publicKeyPKIX []byte, deviceName string) error {
	if authToken == "" || deviceID == "" {
		return errors.New("cloudflare: enroll MASQUE: missing auth token or device id")
	}
	body := masqueDeviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(publicKeyPKIX),
		KeyType: "secp256r1",
		TunType: "masque",
	}
	if deviceName != "" {
		body.Name = deviceName
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	patchURL := warpMasqueEnrollAPIPrefix + "/reg/" + deviceID
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, patchURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+authToken)
	applyCloudflareAndroidClientHeaders(request)
	response, err := api.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return classifyCloudflareStatus(response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return nil
}

func NewCloudflareApiDetour(detour N.Dialer) *CloudflareApi {
	opts := make([]CloudflareApiOption, 0, 1)
	if detour != nil {
		opts = append(opts, WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}))
	}
	return NewCloudflareApi(opts...)
}
func NewCloudflareApi(opts ...CloudflareApiOption) *CloudflareApi {
	api := &CloudflareApi{http.Client{Timeout: 30 * time.Second}}
	for _, opt := range opts {
		opt(api)
	}
	return api
}

func (api *CloudflareApi) CreateProfile(ctx context.Context, publicKey string) (*CloudflareProfile, error) {
	request, err := http.NewRequest("POST", baseUrl+"reg", strings.NewReader(
		fmt.Sprintf(
			"{\"install_id\":\"\",\"tos\":\"%s\",\"key\":\"%s\",\"fcm_token\":\"\",\"type\":\"ios\",\"locale\":\"en_US\"}",
			time.Now().Format("2006-01-02T15:04:05.000Z"),
			publicKey,
		),
	))
	if err != nil {
		return nil, err
	}
	applyCloudflareAndroidClientHeaders(request)
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, classifyCloudflareStatus(response.StatusCode)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	profile := new(CloudflareProfile)
	return profile, json.NewDecoder(strings.NewReader(gjson.Get(string(content), "result").Raw)).Decode(profile)
}

func (api *CloudflareApi) GetProfile(ctx context.Context, authToken string, id string) (*CloudflareProfile, error) {
	request, err := http.NewRequest("GET", baseUrl+"reg/"+id, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+authToken)
	applyCloudflareAndroidClientHeaders(request)
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, classifyCloudflareStatus(response.StatusCode)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	profile := new(CloudflareProfile)
	return profile, json.NewDecoder(strings.NewReader(gjson.Get(string(content), "result").Raw)).Decode(profile)
}

func (api *CloudflareApi) UpdateAccount(ctx context.Context, profile *CloudflareProfile, license string) (*CloudflareProfile, error) {
	deviceId := profile.ID
	authToken := profile.Token
	// Consumer WARP+ license attach: PUT /reg/{id}/account with Bearer (POST returns 405 on current API edge).
	request, err := http.NewRequest("PUT", fmt.Sprint(baseUrl, "reg/", deviceId, "/account"), strings.NewReader(
		fmt.Sprintf(`{"license":%s}`, strconv.Quote(license)),
	))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+authToken)
	request.Header.Set("Content-Type", "application/json")
	applyCloudflareAndroidClientHeaders(request)
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, classifyCloudflareStatus(response.StatusCode)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	ia := new(IdentityAccount)
	if err := json.Unmarshal([]byte(content), ia); err != nil {
		return nil, err
	}

	profile.Account = *ia
	return profile, nil
}

func (api *CloudflareApi) CreateProfileLicense(ctx context.Context, privateKey string, license string) (*CloudflareProfile, error) {
	var wgKey wgtypes.Key
	var err error
	if privateKey != "" {
		wgKey, err = wgtypes.ParseKey(privateKey)
		if err != nil {

			return nil, err
		}
	} else {
		wgKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {

			return nil, err
		}
	}
	profile, err := api.CreateProfile(ctx, wgKey.PublicKey().String())
	if err != nil {
		return nil, err
	}
	profile.Config.PrivateKey = wgKey.String()
	if license == "" {
		return profile, nil
	}
	return api.UpdateAccount(ctx, profile, license)
}

func (api *CloudflareApi) DeleteProfile(ctx context.Context, profile *CloudflareProfile) error {
	request, err := http.NewRequest("DELETE", fmt.Sprint(baseUrl, "reg/", profile.ID), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+profile.Token)
	applyCloudflareAndroidClientHeaders(request)
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return classifyCloudflareStatus(response.StatusCode)
	}
	return nil
}

func classifyCloudflareStatus(code int) error {
	switch {
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return fmt.Errorf("%w: %d", ErrCloudflareUnauthorized, code)
	case code == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %d", ErrCloudflareRateLimited, code)
	case code >= 500:
		return fmt.Errorf("%w: %d", ErrCloudflareServerError, code)
	default:
		return fmt.Errorf("%w: %d", ErrCloudflareUnexpectedCode, code)
	}
}
