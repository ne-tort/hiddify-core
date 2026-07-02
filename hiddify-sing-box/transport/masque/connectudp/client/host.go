package client

import (
	"context"
	"net"

	qmasque "github.com/quic-go/masque-go"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// DialHost wires production CONNECT-UDP overlay dial from package masque.
type DialHost interface {
	Tag() string
	CurrentHTTPLayer() string
	DialOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error)
	DialH3(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)
	RecordHTTPLayerSuccess(layer string)
	ResetHTTPFallbackBudgetAfterSuccess()
	ErrTemplateNotConfigured() error
}

// ListenHost wires production CONNECT-UDP ListenPacket from package masque.
type ListenHost interface {
	ClearHTTPFallbackAfterGiveUp()
	PreResolveDestinationHook()
	PreChainEndReturnHook()
	CtxErr(ctx context.Context) error
	JoinCtxCancel(err error, ctx context.Context) error
	ResolveDestination(destination M.Socksaddr) (string, error)
	PrepareUDP() (client *qmasque.Client, template *uritemplate.Template, writeMax int, httpLayer string, err error)
	DialUDP(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)
	TryHTTPFallbackSwitch(err error) bool
	RewireUDPAfterFallback() (client *qmasque.Client, template *uritemplate.Template)
	RefreshUDPAfterDialFailure(prevClient *qmasque.Client) (client *qmasque.Client, template *uritemplate.Template)
	AdvanceHopAndPrepare() (client *qmasque.Client, template *uritemplate.Template, advanced bool, resetErr error)
	CurrentHTTPLayer() string
	WrapDatagramSplit(pc net.PacketConn, writeMax int, httpLayer string) net.PacketConn
}

// SessionUDP combines dial and listen host callbacks for connectudp/client.Plane.
type SessionUDP interface {
	DialHost
	ListenHost
	ObservabilityInput(template *uritemplate.Template, target string) ObservabilityInput
	NewQUICClient() *qmasque.Client
}
