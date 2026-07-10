package h3

// TunnelConnParamsHook is invoked before NewTunnelConn on every CONNECT tunnel (tests only; nil in prod).
var TunnelConnParamsHook func(*TunnelConnParams)

var testBidiDownloadActiveHook func(active bool)

// TestDuplexDownloadArmedHook fires when beginDownload runs (synth duplex barrier).
var TestDuplexDownloadArmedHook chan struct{}

func applyTunnelConnParamsHook(p *TunnelConnParams) {
	if TunnelConnParamsHook != nil && p != nil {
		TunnelConnParamsHook(p)
	}
}

// SetTestBidiDownloadActiveHook installs a test-only observer for WriteTo downloadActive
// transitions (S104 negative control). Pass nil to clear.
func SetTestBidiDownloadActiveHook(fn func(active bool)) {
	testBidiDownloadActiveHook = fn
}
