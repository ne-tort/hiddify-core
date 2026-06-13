package masque

import (
	"errors"
	"sync"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
)

// TestOverlayFallbackConcurrentLifecycleCloseRace stress-tests overlay pivot vs session Close
// without data races (run with -race in CI or locally).
func TestOverlayFallbackConcurrentLifecycleCloseRace(t *testing.T) {
	switchErr := errors.New("extended connect refused")
	for range 64 {
		s := &coreSession{
			CoreSession: session.CoreSession{
				HTTPLayerFallback: true,
				IPConn:            &connectip.Conn{},
			},
		}
		s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			session.TryHTTPFallbackSwitch(&s.CoreSession, s.lifecycleHost(), switchErr)
		}()
		go func() {
			defer wg.Done()
			_ = s.Close()
		}()
		wg.Wait()
	}
}
