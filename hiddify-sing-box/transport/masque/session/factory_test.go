package session_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestCoreClientFactoryWiredFromMasque(t *testing.T) {
	if session.BuildCoreSession == nil {
		t.Fatal("BuildCoreSession not wired")
	}
	sess, err := (session.CoreClientFactory{}).NewSession(context.Background(), session.ClientOptions{
		Server:        "edge.example",
		ServerPort:    443,
		TemplateUDP:   "https://edge.example/masque?h={target_host}&p={target_port}",
		TemplateIP:    "https://edge.example/cf-connect-ip",
		TemplateTCP:   "https://edge.example/masque/tcp?h={target_host}&p={target_port}",
		TransportMode: option.MasqueTransportModeConnectIP,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if sess == nil {
		t.Fatal("nil session")
	}
	_ = sess.Close()
}

func TestMasqueAliasesMatchSessionTypes(t *testing.T) {
	_, _ = (masque.CoreClientFactory{}).NewSession(context.Background(), masque.ClientOptions{
		Server:      "edge.example",
		ServerPort:  443,
		TemplateUDP: "https://edge.example/masque?h={target_host}&p={target_port}",
		TemplateIP:  "https://edge.example/cf-connect-ip",
		TemplateTCP: "https://edge.example/masque/tcp?h={target_host}&p={target_port}",
	})
}
