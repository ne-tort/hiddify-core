package h2

import (
	"context"
	"errors"
	"net/http"
	"testing"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/yosida95/uritemplate/v3"
)

type dialH2SessionFakeHost struct {
	tag                   string
	warpProto             string
	templateIP            *uritemplate.Template
	errNoTemplateIP       error
	overlayDialAddr       string
	primaryDialHost       string
	onCtxCanceled         int
	ensureH2              func(ctx context.Context) (http.RoundTripper, error)
	tcpRoundTripper       func(http.RoundTripper) http.RoundTripper
	h2DialParams          mcip.H2DialParams
	bootstrap             mcip.SessionBootstrapParams
	warpAlternateHost     func(string) string
	isExtendedUnsupported func(error) bool
}

func (h *dialH2SessionFakeHost) Tag() string { return h.tag }

func (h *dialH2SessionFakeHost) WarpConnectIPProtocol() string { return h.warpProto }

func (h *dialH2SessionFakeHost) TemplateIP() *uritemplate.Template { return h.templateIP }

func (h *dialH2SessionFakeHost) ErrNoTemplateIP() error {
	if h.errNoTemplateIP != nil {
		return h.errNoTemplateIP
	}
	return errors.New("no template")
}

func (h *dialH2SessionFakeHost) OverlayDialAddr() string { return h.overlayDialAddr }

func (h *dialH2SessionFakeHost) PrimaryDialHost() string { return h.primaryDialHost }

func (h *dialH2SessionFakeHost) WarpAlternateHost(primary string) string {
	if h.warpAlternateHost != nil {
		return h.warpAlternateHost(primary)
	}
	return ""
}

func (h *dialH2SessionFakeHost) IsExtendedConnectUnsupported(err error) bool {
	if h.isExtendedUnsupported != nil {
		return h.isExtendedUnsupported(err)
	}
	return false
}

func (h *dialH2SessionFakeHost) EnsureH2Transport(ctx context.Context) (http.RoundTripper, error) {
	if h.ensureH2 != nil {
		return h.ensureH2(ctx)
	}
	return http.DefaultTransport, nil
}

func (h *dialH2SessionFakeHost) TCPRoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.tcpRoundTripper != nil {
		return h.tcpRoundTripper(defaultTransport)
	}
	return defaultTransport
}

func (h *dialH2SessionFakeHost) H2DialParams() mcip.H2DialParams { return h.h2DialParams }

func (h *dialH2SessionFakeHost) BootstrapParams() mcip.SessionBootstrapParams { return h.bootstrap }

func (h *dialH2SessionFakeHost) OnCtxCanceled() { h.onCtxCanceled++ }

func TestDialH2SessionCanceledBeforeTransport(t *testing.T) {
	tpl, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	host := &dialH2SessionFakeHost{
		tag:             "t",
		templateIP:      tpl,
		overlayDialAddr: "127.0.0.1:443",
		ensureH2: func(context.Context) (http.RoundTripper, error) {
			t.Fatal("ensureH2 must not run when ctx is canceled")
			return nil, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := DialH2Session(ctx, host)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if host.onCtxCanceled != 1 {
		t.Fatalf("expected OnCtxCanceled once, got %d", host.onCtxCanceled)
	}
}

func TestDialH2SessionMissingTemplate(t *testing.T) {
	want := errors.New("template missing")
	host := &dialH2SessionFakeHost{
		errNoTemplateIP: want,
		ensureH2: func(context.Context) (http.RoundTripper, error) {
			t.Fatal("ensureH2 must not run without template")
			return nil, nil
		},
	}
	_, dialErr := DialH2Session(context.Background(), host)
	if !errors.Is(dialErr, want) {
		t.Fatalf("expected %v, got %v", want, dialErr)
	}
}

func TestDialH2SessionEnsureH2ErrorWrapped(t *testing.T) {
	tpl, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	host := &dialH2SessionFakeHost{
		templateIP: tpl,
		ensureH2: func(context.Context) (http.RoundTripper, error) {
			return nil, errors.New("no tcp dialer")
		},
	}
	_, dialErr := DialH2Session(context.Background(), host)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if got := dialErr.Error(); got != "masque connect-ip h2: no tcp dialer" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestDialH2SessionCfConnectIPLogsAlternateOnExtendedConnectUnsupported(t *testing.T) {
	tpl, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	host := &dialH2SessionFakeHost{
		tag:             "warp",
		warpProto:       "cf-connect-ip",
		templateIP:      tpl,
		primaryDialHost: "162.159.198.1",
		warpAlternateHost: func(primary string) string {
			if primary == "162.159.198.1" {
				return "162.159.198.2"
			}
			return ""
		},
		isExtendedUnsupported: func(err error) bool {
			return err != nil && errors.Is(err, errExtendedConnectUnsupported)
		},
		ensureH2: func(context.Context) (http.RoundTripper, error) {
			return roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errExtendedConnectUnsupported
			}), nil
		},
	}
	_, dialErr := DialH2Session(context.Background(), host)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, errExtendedConnectUnsupported) {
		t.Fatalf("expected wrapped extended-connect error, got %v", dialErr)
	}
}

var errExtendedConnectUnsupported = errors.New("extended connect not supported by peer")

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
