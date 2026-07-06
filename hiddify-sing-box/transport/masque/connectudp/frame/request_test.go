package frame

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/quic-go/quic-go/http3"
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

func TestParseRequestAcceptsH3ConnectUDPWithoutCapsuleHeader(t *testing.T) {
	t.Parallel()
	tmpl, err := uritemplate.New(testUDPTemplate)
	if err != nil {
		t.Fatal(err)
	}
	req := connectUDPRequest(t, false, false)
	parsed, err := ParseRequest(req, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Target != "198.51.100.1:443" {
		t.Fatalf("target: got %q", parsed.Target)
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
