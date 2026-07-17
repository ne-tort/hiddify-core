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
		PathUDP: "/.well-known/masque/udp",
		PathIP: "/.well-known/masque/ip",
		PathTCP: "/.well-known/masque/tcp",
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
