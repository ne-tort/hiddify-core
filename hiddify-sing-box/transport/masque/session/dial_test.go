package session_test

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/session"
)

func testTemplateHooks() session.TemplateURIHooks {
	return session.TemplateURIHooks{}
}

func TestResolveHopOrderLinearChain(t *testing.T) {
	ordered := session.ResolveHopOrder([]session.HopOptions{
		{Tag: "h2", Via: "h1", Server: "h2.example", Port: 443},
		{Tag: "h1", Server: "h1.example", Port: 443},
		{Tag: "h3", Via: "h2", Server: "h3.example", Port: 443},
	})
	if len(ordered) != 3 {
		t.Fatalf("unexpected hop order length: %d", len(ordered))
	}
	if ordered[0].Tag != "h1" || ordered[1].Tag != "h2" || ordered[2].Tag != "h3" {
		t.Fatalf("unexpected hop order: %+v", ordered)
	}
}

func TestResolveHopOrderDisconnectedGraphFallsBackToInputOrder(t *testing.T) {
	input := []session.HopOptions{
		{Tag: "orphan", Via: "missing", Server: "orphan.example", Port: 443},
		{Tag: "entry", Server: "entry.example", Port: 8443},
	}
	ordered := session.ResolveHopOrder(input)
	if len(ordered) != len(input) {
		t.Fatalf("unexpected hop order length: %d", len(ordered))
	}
	for i := range input {
		if ordered[i].Tag != input[i].Tag {
			t.Fatalf("expected fallback to input order for disconnected chain, got: %+v", ordered)
		}
	}
}

func TestResolveEntryHopRejectsMultipleEntries(t *testing.T) {
	_, _, err := session.ResolveEntryHop([]session.HopOptions{
		{Tag: "a", Server: "a.example", Port: 443},
		{Tag: "b", Server: "b.example", Port: 443},
	})
	if err == nil {
		t.Fatal("expected multiple entry hops error")
	}
}

func TestMasqueDialTargetPreservesHostname(t *testing.T) {
	target := session.MasqueDialTarget("engage.cloudflareclient.com", 443)
	if target != "engage.cloudflareclient.com:443" {
		t.Fatalf("unexpected target: %s", target)
	}
}

func TestBuildTemplatesIncludesTCPTemplate(t *testing.T) {
	udp, ip, tcp, err := session.BuildTemplates(session.ClientOptions{
		Server:     "example.com",
		ServerPort: 443,
	}, testTemplateHooks())
	if err != nil {
		t.Fatalf("BuildTemplates failed: %v", err)
	}
	if udp == nil || ip == nil || tcp == nil {
		t.Fatal("expected udp/ip/tcp templates to be initialized")
	}
}

func TestBuildTemplatesWarpMasqueUsqueConnectIPURL(t *testing.T) {
	_, ip, _, err := session.BuildTemplates(session.ClientOptions{
		Server:                "engage.cloudflareclient.com",
		ServerPort:            443,
		WarpConnectIPProtocol: "cf-connect-ip",
	}, testTemplateHooks())
	if err != nil {
		t.Fatalf("BuildTemplates: %v", err)
	}
	if ip == nil {
		t.Fatal("expected ip template")
	}
	if got := ip.Raw(); got != "https://cloudflareaccess.com" {
		t.Fatalf("CONNECT-IP template must match usque internal.ConnectURI, got %q", got)
	}
}

func TestApplyConnectIPFlowScopeRejectsUnsupportedFlowVariable(t *testing.T) {
	_, err := session.ApplyConnectIPFlowScope("https://example.com/masque/ip/{target}/{scope_id}", "10.0.0.0/8", 17)
	if err == nil {
		t.Fatal("expected unsupported flow forwarding variable to fail fast")
	}
	if !errors.Is(err, session.ErrTemplateCapability) {
		t.Fatalf("expected ErrTemplateCapability, got: %v", err)
	}
}

func TestBuildTemplatesApplyConnectIPFlowScope(t *testing.T) {
	_, ip, _, err := session.BuildTemplates(session.ClientOptions{
		Server:                "example.com",
		ServerPort:            443,
		PathIP: "/.well-known/masque/ip",
		ConnectIPScopeTarget:  "10.0.0.0/8",
		ConnectIPScopeIPProto: 6,
	}, testTemplateHooks())
	if err != nil {
		t.Fatalf("BuildTemplates with scope failed: %v", err)
	}
	if got := ip.Raw(); got != "https://example.com:443/.well-known/masque/ip/10.0.0.0%2F8/6/" {
		t.Fatalf("unexpected expanded IP template: %s", got)
	}
}

func TestResolveTLSServerNamePrefersQUICConfig(t *testing.T) {
	if got := session.ResolveTLSServerName(session.ClientOptions{Server: "edge.example"}); got != "edge.example" {
		t.Fatalf("got %q", got)
	}
}

func TestQuicDialCandidateHostPrefersDialPeer(t *testing.T) {
	got := session.QuicDialCandidateHost(session.ClientOptions{Server: "host.example", DialPeer: "1.2.3.4"})
	if got != "1.2.3.4" {
		t.Fatalf("got %q", got)
	}
}

func TestQuicDialCandidateHostAvoidsLoopbackHairpinViaTLS(t *testing.T) {
	tlsCfg := &tls.Config{ServerName: "193.233.216.26"}
	got := session.QuicDialCandidateHost(session.ClientOptions{
		Server:              "127.0.0.1",
		MasqueQUICCryptoTLS: tlsCfg,
	})
	if got != "193.233.216.26" {
		t.Fatalf("loopback server + public SNI: got %q want 193.233.216.26", got)
	}
	got = session.QuicDialCandidateHost(session.ClientOptions{
		Server:              "127.0.0.1",
		MasqueQUICCryptoTLS: &tls.Config{ServerName: "127.0.0.1"},
	})
	if got != "127.0.0.1" {
		t.Fatalf("loopback server + loopback SNI: got %q want 127.0.0.1", got)
	}
	got = session.QuicDialCandidateHost(session.ClientOptions{Server: "edge.example.com"})
	if got != "edge.example.com" {
		t.Fatalf("non-loopback server unchanged: got %q", got)
	}
}

func TestBuildTemplatesDefaultsServerPortTo443WhenZero(t *testing.T) {
	udp, _, _, err := session.BuildTemplates(session.ClientOptions{Server: "example.com"}, testTemplateHooks())
	if err != nil {
		t.Fatalf("BuildTemplates failed: %v", err)
	}
	if got := udp.Raw(); !strings.Contains(got, "https://example.com:443/.well-known/masque/udp/") {
		t.Fatalf("unexpected udp template: %s", got)
	}
}
