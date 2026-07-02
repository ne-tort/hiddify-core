package masque

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestCoreClientFactoryExplicitNewSession(t *testing.T) {
	sess, err := (CoreClientFactory{}).NewSession(context.Background(), ClientOptions{
		Server:        "edge.example",
		ServerPort:    443,
		TemplateUDP:   "https://edge.example/masque?h={target_host}&p={target_port}",
		TemplateIP:    "https://edge.example/cf-connect-ip",
		TemplateTCP:   "https://edge.example/masque/tcp?h={target_host}&p={target_port}",
		DataplaneMode: option.MasqueDataplaneConnectIP,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if sess == nil {
		t.Fatal("nil session")
	}
	_ = sess.Close()
}

func TestDirectClientFactoryNewSession(t *testing.T) {
	sess, err := (DirectClientFactory{}).NewSession(context.Background(), ClientOptions{
		Server:     "edge.example",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if sess == nil {
		t.Fatal("nil session")
	}
	_ = sess.Close()
}
