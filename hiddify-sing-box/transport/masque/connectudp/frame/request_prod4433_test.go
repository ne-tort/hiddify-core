package frame

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func TestParseRequestProd4433ExplicitTemplate(t *testing.T) {
	tmpl, err := uritemplate.New("https://163.5.180.181:4433/masque/udp/{+target_host}/{target_port}")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("https://163.5.180.181:4433/masque/udp/8.8.8.8/53")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		Host:   "163.5.180.181:4433",
		URL:    u,
		Proto:  RequestProtocol,
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{CapsuleProtocolHeaderValue},
		},
	}
	parsed, err := ParseRequest(req, tmpl)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed.Target != "8.8.8.8:53" {
		t.Fatalf("target=%q", parsed.Target)
	}
}
