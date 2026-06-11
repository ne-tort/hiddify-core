package masque

import (
	"net/http"
	"net/url"
	"testing"

	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/option"
)

func TestParseAuthorityConnectTargetFromURL(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest(http.MethodConnect, "https://163.5.180.181:5201/", nil)
	r.Host = "masque.local:4438"
	host, port, err := TM.ParseCONNECTAuthorityTarget(r)
	if err != nil {
		t.Fatal(err)
	}
	if host != "163.5.180.181" || port != "5201" {
		t.Fatalf("got host=%q port=%q", host, port)
	}
}

func TestParseAuthorityConnectTargetFromHost(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest(http.MethodConnect, "/", nil)
	r.Host = "example.com:8443"
	r.URL = &url.URL{Scheme: "https", Host: "example.com:8443", Path: "/"}
	host, port, err := TM.ParseCONNECTAuthorityTarget(r)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || port != "8443" {
		t.Fatalf("got host=%q port=%q", host, port)
	}
}

func TestValidateMasqueConnectAuthorityClientContract(t *testing.T) {
	t.Parallel()
	bad := applyMasqueClientMasqueDefaults(optionMasqueClient(option.MasqueTCPTransportConnectAuthority, "https://x/tcp/{target_host}/{target_port}", ""))
	if err := validateMasqueOptions(bad); err == nil {
		t.Fatal("expected template_tcp + connect_authority error")
	}
	bad2 := applyMasqueClientMasqueDefaults(optionMasqueClient(option.MasqueTCPTransportConnectStream, "", "https://x/"))
	if err := validateMasqueOptions(bad2); err == nil {
		t.Fatal("expected template_connect + connect_stream error")
	}
	ok := applyMasqueClientMasqueDefaults(optionMasqueClient(option.MasqueTCPTransportConnectAuthority, "", ""))
	if err := validateMasqueOptions(ok); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
}

func optionMasqueClient(tcpTransport, templateTCP, templateConnect string) option.MasqueEndpointOptions {
	return option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "masque.example", ServerPort: 443},
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  tcpTransport,
		TemplateTCP:   templateTCP,
		TemplateConnect: templateConnect,
	}
}
