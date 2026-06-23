package client

import (
	"context"
	"errors"
	"net"
	"testing"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/yosida95/uritemplate/v3"
)

type fakeDialHost struct {
	layer       string
	templateErr error
	h2Hook      func(context.Context, *uritemplate.Template, string) (net.PacketConn, error)
	h3Hook      func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error)
}

func (f fakeDialHost) Tag() string { return "t" }
func (f fakeDialHost) CurrentHTTPLayer() string {
	return f.layer
}
func (f fakeDialHost) DialOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if f.h2Hook != nil {
		return f.h2Hook(ctx, template, target)
	}
	return nil, errors.New("h2 unreachable")
}
func (f fakeDialHost) DialH3(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if f.h3Hook != nil {
		return f.h3Hook(ctx, client, template, target)
	}
	return nil, errors.New("h3 unreachable")
}
func (f fakeDialHost) RecordHTTPLayerSuccess(string)      {}
func (f fakeDialHost) ResetHTTPFallbackBudgetAfterSuccess() {}

func (f fakeDialHost) ErrTemplateNotConfigured() error { return f.templateErr }

func TestDialAddrReturnsTemplateErrorWhenNilH3(t *testing.T) {
	t.Parallel()
	errSentinel := errors.New("template missing")
	_, err := DialAddr(
		context.Background(),
		fakeDialHost{layer: option.MasqueHTTPLayerH3, templateErr: errSentinel},
		ObservabilityInput{ResolveDialAddr: func() string { return "dial" }},
		&qmasque.Client{},
		nil,
		"8.8.8.8:53",
	)
	if !errors.Is(err, errSentinel) {
		t.Fatalf("expected template error, got %v", err)
	}
}

func TestDialAddrReturnsTemplateErrorWhenNilH2(t *testing.T) {
	t.Parallel()
	errSentinel := errors.New("template missing")
	_, err := DialAddr(
		context.Background(),
		fakeDialHost{layer: option.MasqueHTTPLayerH2, templateErr: errSentinel},
		ObservabilityInput{ResolveDialAddr: func() string { return "dial" }},
		nil,
		nil,
		"8.8.8.8:53",
	)
	if !errors.Is(err, errSentinel) {
		t.Fatalf("expected template error, got %v", err)
	}
}

func TestDialH3ProductionRequiresClient(t *testing.T) {
	t.Parallel()
	_, err := DialH3Production(context.Background(), nil, nil, &uritemplate.Template{}, "8.8.8.8:53")
	if !errors.Is(err, ErrQUICClientNotInitialized) {
		t.Fatalf("expected ErrQUICClientNotInitialized, got %v", err)
	}
}
