package connectip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func newRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Method = http.MethodConnect
	req.Proto = requestProtocol
	req.Header.Add("Capsule-Protocol", capsuleProtocolHeaderValue)
	return req
}

func TestConnectIPRequestParsing(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/masque/ip")
		req := newRequest("https://localhost:1234/masque/ip")
		r, err := ParseRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, &Request{}, r)
	})

	t.Run("parse scoped flow forwarding variables", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/masque/ip?t={target}&i={ipproto}")
		req := newRequest("https://localhost:1234/masque/ip?t=foobar&i=42")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "connect-ip: invalid flow forwarding target: foobar")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("parse scoped flow forwarding variables (path form)", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/masque/ip/{target}/{ipproto}")
		req := newRequest("https://localhost:1234/masque/ip/198.18.0.0%2F15/17")
		r, err := ParseRequest(req, template)
		require.NoError(t, err)
		require.True(t, r.HasTarget)
		require.Equal(t, netip.MustParsePrefix("198.18.0.0/15"), r.Target)
		require.True(t, r.HasIPProto)
		require.Equal(t, uint8(17), r.IPProto)
	})

	t.Run("reject unknown flow forwarding variable", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/masque/ip/{foo}")
		req := newRequest("https://localhost:1234/masque/ip/bar")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, ErrFlowForwardingUnsupported.Error())
		require.Equal(t, http.StatusNotImplemented, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("reject invalid flow forwarding target", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/masque/ip/{target}/{ipproto}")
		req := newRequest("https://localhost:1234/masque/ip/not-a-prefix/17")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "connect-ip: invalid flow forwarding target: not-a-prefix")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("reject invalid flow forwarding ipproto", func(t *testing.T) {
		template := uritemplate.MustNew("https://localhost:1234/masque/ip/{target}/{ipproto}")
		req := newRequest("https://localhost:1234/masque/ip/198.18.0.0%2F15/999")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "connect-ip: invalid flow forwarding ipproto: 999")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	template := uritemplate.MustNew("https://localhost:1234/masque/")

	t.Run("wrong protocol", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Proto = "not-connect-ip"
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "unexpected protocol: not-connect-ip")
		require.Equal(t, http.StatusNotImplemented, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong request method", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Method = http.MethodHead
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "expected CONNECT request, got HEAD")
		require.Equal(t, http.StatusMethodNotAllowed, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong :authority", func(t *testing.T) {
		req := newRequest("https://quic-go.net:1234/masque")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "host in :authority (quic-go.net:1234) does not match template host (localhost:1234)")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("missing Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Del("Capsule-Protocol")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "missing Capsule-Protocol header")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "🤡")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "invalid capsule header value: [🤡]")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header value type", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "1")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "incorrect capsule header value type: int64")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header value", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		v, err := httpsfv.Marshal(httpsfv.NewItem(false))
		require.NoError(t, err)
		req.Header.Set("Capsule-Protocol", v)
		_, err = ParseRequest(req, template)
		require.EqualError(t, err, "incorrect capsule header value: false")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})
}
