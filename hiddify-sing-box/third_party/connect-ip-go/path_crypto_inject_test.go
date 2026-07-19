package connectip

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestBuildConnectIPRequestURLOpaqueRequiresSeal(t *testing.T) {
	template := uritemplate.MustNew("https://localhost:1234/masque/ip/{opaque}/")
	_, err := buildConnectIPRequestURL(template, DialOptions{})
	require.EqualError(t, err, "connect-ip: opaque path requires SealIPScope")
}

func TestBuildConnectIPRequestURLOpaqueWithSeal(t *testing.T) {
	template := uritemplate.MustNew("https://localhost:1234/masque/ip/{opaque}/")
	got, err := buildConnectIPRequestURL(template, DialOptions{
		PathObfuscationKey: []byte("unused-by-fake"),
		SealIPScope: func(key []byte, target string, ipproto uint8) (string, error) {
			require.Equal(t, "0.0.0.0/0", target)
			require.Equal(t, uint8(0), ipproto)
			return "sealed-opaque", nil
		},
	})
	require.NoError(t, err)
	require.Equal(t, "https://localhost:1234/masque/ip/sealed-opaque/", got)
}

func TestParseRequestOpaqueRequiresOpener(t *testing.T) {
	prev := ipScopeOpener
	t.Cleanup(func() { SetIPScopeOpener(prev) })
	SetIPScopeOpener(nil)

	template := uritemplate.MustNew("https://localhost:1234/masque/ip/{opaque}/")
	req := newRequest("https://localhost:1234/masque/ip/abc/")
	_, err := ParseRequest(req, template)
	require.Error(t, err)
	var pe *RequestParseError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, http.StatusBadRequest, pe.HTTPStatus)
	require.EqualError(t, pe.Err, "connect-ip: opaque path requires IPScopeOpener")
}

func TestParseRequestOpaqueWithOpener(t *testing.T) {
	prev := ipScopeOpener
	t.Cleanup(func() { SetIPScopeOpener(prev) })
	SetIPScopeOpener(func(opaque string) (string, uint8, error) {
		if opaque != "abc" {
			return "", 0, errors.New("unexpected opaque")
		}
		return "198.18.0.0/15", 17, nil
	})

	template := uritemplate.MustNew("https://localhost:1234/masque/ip/{opaque}/")
	req := newRequest("https://localhost:1234/masque/ip/abc/")
	r, err := ParseRequest(req, template)
	require.NoError(t, err)
	require.True(t, r.HasTarget)
	require.Equal(t, netip.MustParsePrefix("198.18.0.0/15"), r.Target)
	require.True(t, r.HasIPProto)
	require.Equal(t, uint8(17), r.IPProto)
}

func TestParseRequestOpaqueOpenerError(t *testing.T) {
	prev := ipScopeOpener
	t.Cleanup(func() { SetIPScopeOpener(prev) })
	SetIPScopeOpener(func(opaque string) (string, uint8, error) {
		return "", 0, errors.New("bad opaque")
	})

	template := uritemplate.MustNew("https://localhost:1234/masque/ip/{opaque}/")
	req := newRequest("https://localhost:1234/masque/ip/" + strings.Repeat("x", 8) + "/")
	_, err := ParseRequest(req, template)
	require.Error(t, err)
	var pe *RequestParseError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, http.StatusBadRequest, pe.HTTPStatus)
	require.Contains(t, pe.Err.Error(), "opaque path")
}
