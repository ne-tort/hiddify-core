package tcp

import "github.com/sagernet/gvisor/pkg/tcpip"

// TunRelayInitialCwnd is the sender congestion window (segments) for sing-box TUN legs that
// relay MASQUE CONNECT-stream download (iperf -R). Default slow-start often plateaus near
// ~44×MSS (~64 KiB/RTT, ~15 Mbit/s bench); per-forwarder tune avoids stack-wide InitialCwnd bumps.
const TunRelayInitialCwnd = 40

// TuneEndpointBulkRelay raises SndCwnd on a freshly accepted TUN TCP endpoint before bulk relay.
func TuneEndpointBulkRelay(ep tcpip.Endpoint) tcpip.Error {
	e, ok := ep.(*Endpoint)
	if !ok {
		return nil
	}
	e.LockUser()
	defer e.UnlockUser()
	if e.snd == nil {
		return nil
	}
	if e.snd.SndCwnd < TunRelayInitialCwnd {
		e.snd.SndCwnd = TunRelayInitialCwnd
	}
	if e.snd.Ssthresh < TunRelayInitialCwnd {
		e.snd.Ssthresh = TunRelayInitialCwnd
	}
	return nil
}
