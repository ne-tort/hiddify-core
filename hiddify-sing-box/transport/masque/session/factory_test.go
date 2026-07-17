package session_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestCoreClientFactoryExplicitCtor(t *testing.T) {
	sess, err := (masque.CoreClientFactory{}).NewSession(context.Background(), session.ClientOptions{
		Server:        "edge.example",
		ServerPort:    443,
		PathUDP:       "/.well-known/masque/udp",
		PathIP:        "/.well-known/masque/ip",
		PathTCP:       "/.well-known/masque/tcp",
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

func TestMasqueAliasesMatchSessionTypes(t *testing.T) {
	_, _ = (masque.CoreClientFactory{}).NewSession(context.Background(), masque.ClientOptions{
		Server:     "edge.example",
		ServerPort: 443,
		PathUDP:    "/.well-known/masque/udp",
		PathIP:     "/.well-known/masque/ip",
		PathTCP:    "/.well-known/masque/tcp",
	})
}
