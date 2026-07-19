package frame

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	"github.com/yosida95/uritemplate/v3"
)

const testUDPTemplate = "https://masque.example:443/masque/udp/{target_host}/{target_port}"

func connectUDPRequest(t *testing.T, withCapsule bool, capsuleVal bool) *http.Request {
	t.Helper()
	u, err := url.Parse("https://masque.example:443/masque/udp/198.51.100.1/443")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		Host:   "masque.example:443",
		URL:    u,
		Header: http.Header{
			":protocol": []string{RequestProtocol},
		},
		Proto: RequestProtocol,
	}
	if withCapsule {
		if capsuleVal {
			req.Header.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
		} else {
			req.Header.Set(http3.CapsuleProtocolHeader, "?0")
		}
	}
	return req
}

func TestParseRequestRequiresCapsuleProtocol(t *testing.T) {
	t.Parallel()
	tmpl, err := uritemplate.New(testUDPTemplate)
	if err != nil {
		t.Fatal(err)
	}
	req := connectUDPRequest(t, false, false)
	req.Proto = "" // H2-style: :protocol set, Proto empty — capsule header required
	_, err = ParseRequest(req, tmpl)
	var perr *RequestParseError
	if !errors.As(err, &perr) {
		t.Fatalf("ParseRequest: %v want *RequestParseError", err)
	}
	if perr.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", perr.HTTPStatus, http.StatusBadRequest)
	}
}

func TestParseRequestRejectsMissingCapsuleProtocolEvenWithConnectUDPProto(t *testing.T) {
	t.Parallel()
	tmpl, err := uritemplate.New(testUDPTemplate)
	if err != nil {
		t.Fatal(err)
	}
	// Former D-R4 H3 waiver: Proto=connect-udp without Capsule-Protocol must now reject.
	req := connectUDPRequest(t, false, false)
	if req.Proto != RequestProtocol {
		t.Fatalf("Proto=%q want %q", req.Proto, RequestProtocol)
	}
	_, err = ParseRequest(req, tmpl)
	var perr *RequestParseError
	if !errors.As(err, &perr) {
		t.Fatalf("ParseRequest: %v want *RequestParseError", err)
	}
	if perr.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", perr.HTTPStatus, http.StatusBadRequest)
	}
}

func TestParseRequestRejectsFalseCapsuleProtocol(t *testing.T) {
	t.Parallel()
	tmpl, err := uritemplate.New(testUDPTemplate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseRequest(connectUDPRequest(t, true, false), tmpl)
	var perr *RequestParseError
	if !errors.As(err, &perr) {
		t.Fatalf("ParseRequest: %v want *RequestParseError", err)
	}
	if perr.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", perr.HTTPStatus, http.StatusBadRequest)
	}
}

func TestParseRequestAcceptsValidConnectUDP(t *testing.T) {
	t.Parallel()
	tmpl, err := uritemplate.New(testUDPTemplate)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(connectUDPRequest(t, true, true), tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Target != "198.51.100.1:443" {
		t.Fatalf("target: got %q", parsed.Target)
	}
	if parsed.Host != "masque.example:443" {
		t.Fatalf("host: got %q", parsed.Host)
	}
}

func TestParseRequestAcceptsTrailingSlashMismatch(t *testing.T) {
	t.Parallel()
	// pathbuild FullURITemplate ends with `/`; masque-go DialAddr templates often do not.
	tmpl, err := uritemplate.New(testUDPTemplate + "/")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(connectUDPRequest(t, true, true), tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Target != "198.51.100.1:443" {
		t.Fatalf("target: got %q", parsed.Target)
	}
}

func TestParseRequestTargetPortRange(t *testing.T) {
	t.Parallel()
	tmpl, err := uritemplate.New(testUDPTemplate)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(port string) *http.Request {
		t.Helper()
		u, err := url.Parse("https://masque.example:443/masque/udp/198.51.100.1/" + port)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{
			Method: http.MethodConnect,
			Host:   "masque.example:443",
			URL:    u,
			Header: http.Header{
				":protocol":                 []string{RequestProtocol},
				http3.CapsuleProtocolHeader: []string{CapsuleProtocolHeaderValue},
			},
			Proto: RequestProtocol,
		}
	}
	for _, port := range []string{"0", "65536", "99999"} {
		_, err := ParseRequest(mk(port), tmpl)
		var perr *RequestParseError
		if !errors.As(err, &perr) || perr.HTTPStatus != http.StatusBadRequest {
			t.Fatalf("port %s: got %v want RequestParseError 400", port, err)
		}
	}
	for _, tc := range []struct {
		port   string
		target string
	}{
		{"1", "198.51.100.1:1"},
		{"443", "198.51.100.1:443"},
		{"65535", "198.51.100.1:65535"},
	} {
		parsed, err := ParseRequest(mk(tc.port), tmpl)
		if err != nil {
			t.Fatalf("port %s: %v", tc.port, err)
		}
		if parsed.Target != tc.target {
			t.Fatalf("port %s: target got %q want %q", tc.port, parsed.Target, tc.target)
		}
	}
}

func TestParseRequestOpaquePath(t *testing.T) {
	t.Parallel()
	key := pathbuild.ActiveKey(true)
	opaque, err := pathbuild.SealHostPort(key, "198.51.100.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	raw := "https://masque.example:443/.well-known/masque/udp/{opaque}/"
	tmpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := pathbuild.ExpandHostPort(tmpl, key, "198.51.100.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(expanded)
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		Host:   "masque.example:443",
		URL:    u,
		Header: http.Header{
			":protocol":                   []string{RequestProtocol},
			http3.CapsuleProtocolHeader: []string{CapsuleProtocolHeaderValue},
		},
		Proto: RequestProtocol,
	}
	parsed, err := ParseRequest(req, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Target != "198.51.100.1:443" {
		t.Fatalf("target: got %q want 198.51.100.1:443 (opaque=%s)", parsed.Target, opaque)
	}
}
